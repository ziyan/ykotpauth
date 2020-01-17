FROM busybox

ADD ykotpauth /bin/ykotpauth
USER nobody
ENTRYPOINT ["/bin/ykotpauth"]

