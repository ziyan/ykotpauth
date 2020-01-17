ykotpauth
=========

Yubikey OTP authentication HTTP server.


Build
-----

```
# format code
gofmt -l -w .

# build and strip
CGO_ENABLED=0 go build github.com/ziyan/ykotpauth
objcopy --strip-all ykotpauth

# build docker
docker build -t ziyan/ykotpauth .
````

Configuration
-------------

In `nginx` configuration, use the following as an example:

```
location /resource/
{
    auth_request /ykotpauth;
}

location = /ykotpauth
{
    proxy_pass http://ykotpauth:8000;
    proxy_read_timeout 10s;
    proxy_buffering off;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Real-Path $request_uri;
}
```

