# ---- 构建阶段:alpine 即 musl 环境,产物为静态链接的二进制 ----
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY . .
RUN cargo build --release

# ---- 运行阶段:空白镜像,只装一个静态二进制(无 libc 依赖) ----
FROM scratch
COPY --from=builder /build/target/release/iomon /iomon
ENTRYPOINT ["/iomon"]
