# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN case "$TARGETVARIANT" in v7) export GOARM=7 ;; esac && \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -buildvcs=false -trimpath \
    -ldflags "-s -w -X github.com/lijiext/ssh-login-notify/internal/app.version=$VERSION" \
    -o /out/ssh-login-notify ./cmd/ssh-login-notify

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/ssh-login-notify /usr/local/sbin/ssh-login-notify
ENTRYPOINT ["/usr/local/sbin/ssh-login-notify"]
