#!/bin/sh
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
unshare -Umr sh -xe <<EOF
mount -t tmpfs tmpfs /mnt
mkdir /mnt/src /mnt/cargo
mount --bind "$PWD" /mnt/src
mount --bind "$CARGO_HOME" /mnt/cargo
cd /mnt/src/
CARGO_HOME=/mnt/cargo cargo build --release --verbose --target=x86_64-unknown-linux-musl
EOF
