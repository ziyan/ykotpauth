package cli

import (
	"encoding/base64"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/conformal/yubikey"
	"github.com/op/go-logging"
	"github.com/urfave/cli"

	"github.com/ziyan/ykotpauth/settings"
)

var log = logging.MustGetLogger("cli")

func Run(args []string) {

	app := cli.NewApp()
	app.EnableBashCompletion = true
	app.Name = "ykotpauth"
	app.Version = "0.1.0"
	app.Usage = "Yubikey OTP authentication HTTP server."

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "log-level",
			Value: "DEBUG",
			Usage: "log level",
		},
		&cli.StringFlag{
			Name:  "listen-http",
			Value: ":8000",
			Usage: "http listen endpoint",
		},
		&cli.StringFlag{
			Name:  "settings",
			Value: "ykotpauth.yaml",
			Usage: "path to settings file",
		},
		&cli.StringFlag{
			Name:  "real-ip-header",
			Value: "X-Real-IP",
			Usage: "header for getting real ip address",
		},
		&cli.StringFlag{
			Name:  "real-path-header",
			Value: "X-Real-Path",
			Usage: "header for getting real requested path",
		},
		&cli.StringFlag{
			Name:  "reuse-timeout",
			Value: "120s",
			Usage: "same token reuse timeout",
		},
		&cli.BoolFlag{
			Name:  "debug-pprof",
			Usage: "enable pprof debugging",
		},
	}

	app.Before = func(c *cli.Context) error {
		formatter := logging.MustStringFormatter("%{color}%{time:2006-01-02T15:04:05.000Z07:00} [%{level}] <%{pid}> [%{shortfile} %{shortfunc}] %{message}%{color:reset}")
		logging.SetBackend(logging.NewBackendFormatter(logging.NewLogBackend(os.Stderr, "", 0), formatter))
		if level, err := logging.LogLevel(c.String("log-level")); err == nil {
			logging.SetLevel(level, "")
		}
		log.Debugf("log level set to %s", logging.GetLevel(""))
		return nil
	}

	app.After = func(c *cli.Context) error {
		log.Noticef("exiting ...")
		return nil
	}

	app.Action = func(c *cli.Context) error {
		settings := settings.New(c.String("settings"))

		timeout, err := time.ParseDuration(c.String("reuse-timeout"))
		if err != nil {
			log.Errorf("failed to parse reuse timeout \"%s\": %s", c.String("reuse-timeout"), err)
			return err
		}

		// signal to quit
		quit := false

		// serve http
		httping := make(chan struct{})
		go func() {
			defer close(httping)

			mux := http.NewServeMux()
			if c.Bool("debug-pprof") {
				mux.HandleFunc("/debug/pprof/", pprof.Index)
				mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
				mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
				mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
				mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			}

			mux.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
				if ok := func() bool {
					ip := request.Header.Get(c.String("real-ip-header"))
					path := request.Header.Get(c.String("real-path-header"))
					authorization := request.Header.Get("Authorization")
					if !strings.HasPrefix(authorization, "Basic ") {
						log.Debugf("request does not have basic authorization header")
						return false
					}
					decoded, err := base64.StdEncoding.DecodeString(authorization[len("Basic "):])
					if err != nil {
						log.Debugf("failed to decode basic authorization header: %s: %s", authorization, err)
						return false
					}
					userpass := string(decoded)
					if !strings.HasPrefix(userpass, ":") {
						log.Debugf("username is not empty: %s", userpass)
						return false
					}
					id, otp, err := yubikey.ParseOTPString(userpass[1:])
					if err != nil {
						log.Debugf("failed to parse otp: %s", err)
						return false
					}
					log.Infof("access: id = %s, token = %s, ip = %s, path = %s", string(id), userpass[1:], ip, path)
					entry, err := settings.Lookup(string(id))
					if err != nil {
						log.Debugf("failed to look up otp: %s", err)
						return false
					}
					token, err := otp.Parse(entry.Key)
					if err != nil {
						log.Debugf("failed to parse otp: %s", err)
						return false
					}
					counter := uint32(token.Ctr)<<16 | uint32(token.Use)
					if counter < entry.Counter {
						log.Warningf("token reused, possibly replay attack")
						return false
					}
					if counter == entry.Counter {
						if ip != entry.IP {
							log.Warningf("token reused, from different ip, possibly replay attack")
							return false
						}
						if time.Since(entry.Timestamp) > timeout {
							log.Warningf("token reused, from too long ago, possibly replay attack")
							return false
						}
					}
					entry.Counter = counter
					entry.IP = ip
					if err := settings.Update(entry); err != nil {
						log.Debugf("failed to update and save otp: %s", err)
						return false
					}
					if entry.Disabled {
						log.Warningf("token disbabled")
						return false
					}
					log.Noticef("access allowed: id = %s, token = %s, counter = %d, ip = %s, path = %s", string(id), userpass[1:], counter, ip, path)
					return true
				}(); !ok {
					response.Header().Add("WWW-Authenticate", "Basic realm=\"ykotpauth\"")
					http.Error(response, "", 401)
				}
			})

			log.Noticef("listening for http connection on %s", c.String("listen-http"))
			err := http.ListenAndServe(c.String("listen-http"), mux)
			if quit {
				return
			}
			if err != nil {
				log.Errorf("http server exited with error: %s", err)
			}
		}()

		// wait till exit
		signaling := make(chan os.Signal, 1)
		signal.Notify(signaling, syscall.SIGINT, syscall.SIGTERM)
		for !quit {
			select {
			case <-signaling:
				quit = true
			case <-httping:
				quit = true
			}
		}

		return nil
	}

	app.Run(args)
}
