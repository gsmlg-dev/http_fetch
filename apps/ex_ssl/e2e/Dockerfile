FROM caddy:2.8.4-builder AS xcaddy

FROM golang:1.24.7-alpine AS builder

RUN apk add --no-cache ca-certificates git

COPY --from=xcaddy /usr/bin/xcaddy /usr/bin/xcaddy

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

RUN xcaddy build v2.8.4 \
    --with github.com/rushiiMachine/caddy-ja3@bd46d4a35cb63fb9dda5e694fc426ae031147ecf \
    --with github.com/inkress/caddy-ja4@a0fecfabcde03dc76b1bd86b9f8f3811a1d11324

FROM caddy:2.8.4

COPY --from=builder /go/caddy /usr/bin/caddy
COPY Caddyfile.json /etc/caddy/e2e/Caddyfile.json
COPY certs/server.pem certs/server-key.pem /etc/caddy/e2e/

CMD ["caddy", "run", "--config", "/etc/caddy/e2e/Caddyfile.json"]
