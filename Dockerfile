FROM docker.io/library/rust:1-alpine3.18
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY . .
RUN cargo build --release --locked

FROM docker.io/library/alpine:3.18
RUN apk add android-tools
COPY --from=0 /app/target/release/spytrap-adb /
ENTRYPOINT ["/spytrap-adb"]
