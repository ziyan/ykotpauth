package settings

import (
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"github.com/conformal/yubikey"
	"github.com/op/go-logging"
	"gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("settings")

var (
	ErrInvalid            = errors.New("settings: invalid configuration")
	ErrTokenNotRegistered = errors.New("settings: token not registered")
)

type Token struct {
	ID        string
	Key       yubikey.Key
	Counter   uint32
	IP        string
	Timestamp time.Time
	Disabled  bool
}

type Settings interface {
	Lookup(id string) (*Token, error)
	Update(*Token) error
}

type token struct {
	id        string
	comment   string
	key       yubikey.Key
	counter   uint32
	timestamp time.Time
	ip        string
	disabled  bool
}

type settings struct {
	mutex    sync.Mutex
	filename string
	modified time.Time

	tokens []*token

	dirty bool
}

type rawToken struct {
	ID        string    `yaml:"id,omitempty"`
	Comment   string    `yaml:"comment,omitempty"`
	Key       string    `yaml:"key,omitempty"`
	Counter   uint32    `yaml:"counter,omitempty"`
	Timestamp time.Time `yaml:"timestamp,omitempty"`
	IP        string    `yaml:"ip,omitempty"`
	Disabled  bool      `yaml:"disabled,omitempty"`
}

type rawSettings struct {
	Tokens []*rawToken `yaml:"tokens,omitempty"`
}

func New(filename string) Settings {
	return &settings{
		filename: filename,
	}
}

func (s *settings) load() error {
	start := time.Now()

	fi, err := os.Stat(s.filename)
	if err != nil {
		if os.IsNotExist(err) {
			s.dirty = true
			return nil
		}
		log.Errorf("failed to read settings file %s: %s", s.filename, err)
		return err
	}

	modified := fi.ModTime()
	if modified == s.modified {
		// nothing changed
		return nil
	}

	// read content
	content, err := ioutil.ReadFile(s.filename)
	if err != nil {
		log.Errorf("failed to read settings file %s: %s", s.filename, err)
		return err
	}

	// load settings from disk
	var raw *rawSettings
	if err := yaml.Unmarshal(content, &raw); err != nil {
		log.Errorf("failed to parse settings file %s: %s", s.filename, err)
		return err
	}
	if raw == nil {
		return ErrInvalid
	}

	var tokens []*token
	for _, rawToken := range raw.Tokens {
		data, err := hex.DecodeString(rawToken.Key)
		if err != nil {
			log.Errorf("failed to decode hex key: %s: %s", rawToken.Key, err)
			return err
		}
		tokens = append(tokens, &token{
			id:        rawToken.ID,
			comment:   rawToken.Comment,
			key:       yubikey.NewKey(data),
			counter:   rawToken.Counter,
			timestamp: rawToken.Timestamp,
			ip:        rawToken.IP,
			disabled:  rawToken.Disabled,
		})
	}

	// set the members
	s.modified = modified

	s.tokens = tokens

	log.Debugf("loaded settings from %s, took %s", s.filename, time.Since(start))
	return nil
}

func (s *settings) save() error {
	start := time.Now()

	if !s.dirty {
		return nil
	}

	raw := &rawSettings{}

	raw.Tokens = make([]*rawToken, 0, len(s.tokens))
	for _, token := range s.tokens {
		raw.Tokens = append(raw.Tokens, &rawToken{
			ID:        token.id,
			Comment:   token.comment,
			Key:       hex.EncodeToString(token.key[:]),
			Counter:   token.counter,
			Timestamp: token.timestamp,
			IP:        token.ip,
			Disabled:  token.disabled,
		})
	}

	// write to file
	content, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(s.filename, content, 0600); err != nil {
		return err
	}

	// get modified date
	fi, err := os.Stat(s.filename)
	if err != nil {
		return err
	}
	s.modified = fi.ModTime()
	s.dirty = false

	log.Debugf("saved settings to %s, took %s", s.filename, time.Since(start))
	return nil
}

func (s *settings) Lookup(id string) (*Token, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if err := s.load(); err != nil {
		return nil, err
	}
	for _, token := range s.tokens {
		if token.id == id {
			return &Token{
				ID:        token.id,
				Key:       token.key,
				Counter:   token.counter,
				IP:        token.ip,
				Timestamp: token.timestamp,
				Disabled:  token.disabled,
			}, nil
		}
	}
	return nil, ErrTokenNotRegistered
}

func (s *settings) Update(token *Token) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if err := s.load(); err != nil {
		return err
	}
	for _, t := range s.tokens {
		if t.id == token.ID {
			t.counter = token.Counter
			t.ip = token.IP
			t.timestamp = time.Now().Local()
			s.dirty = true
			return s.save()
		}
	}
	return ErrTokenNotRegistered
}
