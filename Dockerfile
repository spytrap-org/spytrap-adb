FROM docker.io/rust@sha256:b0b3eb57c3f385499dca593a021e848167f7130a22b41818b7bbf4bdf8bba670
# TODO: this is prone to mirror drift and not reproducible
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY . .
RUN cargo build --release --locked --target=x86_64-unknown-linux-musl

FROM docker.io/alpine@sha256:635f0aa53d99017b38d1a0aa5b2082f7812b03e3cdb299103fe77b5c8a07f1d2
COPY --from=0 /app/target/x86_64-unknown-linux-musl/release/spytrap-adb /
# note: this binary links to /lib/ld-musl-x86_64.so.1
ENTRYPOINT ["/spytrap-adb"]
