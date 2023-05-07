all:
	RUSTFLAGS='--remap-path-prefix=$(HOME)=/remap-home --remap-path-prefix=$(PWD)=/remap-pwd' \
	cargo build --release --verbose --target=x86_64-unknown-linux-musl
