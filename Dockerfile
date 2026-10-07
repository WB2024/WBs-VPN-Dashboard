# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY internal ./internal
COPY cmd ./cmd
ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go test ./... \
 && go build -trimpath -ldflags "-s -w" -o /out/panel ./cmd/panel \
 && for a in amd64 arm64; do \
      GOOS=linux GOARCH=$a go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/agents/wbs-vpn-agent-linux-$a ./cmd/agent; \
    done

FROM alpine:3.20
RUN adduser -D -u 10001 vpn && mkdir /data && chown vpn /data
COPY --from=build /out/panel /app/panel
COPY --from=build /out/agents /app/agents
USER vpn
ENV DATA_DIR=/data AGENT_DIR=/app/agents LISTEN=:8080
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/panel"]
