# 第一阶段：编译 Go 认证服务
FROM golang:1.20-alpine AS builder
WORKDIR /app
# 初始化 go mod 并下载依赖
COPY auth-server/ ./
# 如果本地没有生成 go.sum，这里运行 tidy
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o auth-server main.go

# 第二阶段：构建最终镜像
FROM nginx:alpine

# 安装必要的工具 (可选，用于调试)
RUN apk add --no-cache curl

# 复制 Go 二进制文件
COPY --from=builder /app/auth-server /usr/local/bin/auth-server

# 复制 Nginx 配置
COPY nginx.conf /etc/nginx/nginx.conf

# 复制静态文件
COPY static /usr/share/nginx/html/static

# 创建数据目录
RUN mkdir -p /data && chmod 777 /data

# 启动脚本：同时启动 Nginx 和 Auth Server
RUN echo '#!/bin/sh' > /start.sh && \
    echo 'nohup /usr/local/bin/auth-server > /var/log/auth.log 2>&1 &' >> /start.sh && \
    echo 'nginx -g "daemon off;"' >> /start.sh && \
    chmod +x /start.sh

CMD ["/start.sh"]