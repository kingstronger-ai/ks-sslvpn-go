# syntax=docker/dockerfile:1
# SSLVPN-Go 多阶段构建
FROM golang:1.22-alpine AS builder
# 国内构建加速（证书自动续签引入了阿里云/腾讯云 SDK，依赖体积较大）
ENV GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct
ENV GOFLAGS=-mod=mod
WORKDIR /src
COPY backend/go.mod backend/go.sum* ./
RUN go mod download
COPY backend/ .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/sslvpn ./cmd/sslvpn

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        openvpn easy-rsa iptables iproute2 ldap-utils ca-certificates openssl \
        kmod procps tzdata && \
    rm -rf /var/lib/apt/lists/* && \
    ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin/easyrsa
ENV TZ=Asia/Shanghai
COPY --from=builder /out/sslvpn /usr/local/bin/sslvpn
COPY deploy/entrypoint.sh /entrypoint.sh
# 内置客户端安装包（/downloads 页提供下载；运维可用卷内 /var/lib/sslvpn/downloads 覆盖）
COPY deploy/downloads/ /opt/sslvpn-client/
RUN chmod +x /entrypoint.sh && mkdir -p /etc/openvpn /var/lib/sslvpn
VOLUME ["/var/lib/sslvpn", "/etc/openvpn"]
EXPOSE 8443 8080
ENTRYPOINT ["/entrypoint.sh"]
