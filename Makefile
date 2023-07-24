build:
	repro-env build -- sh -c ' \
	CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
	RUSTFLAGS="-C strip=symbols" \
	cargo build --target x86_64-unknown-linux-musl --release'

.PHONY: build
