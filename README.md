# spytrap.b

Uses adb and usb debugging to scan for suspicious apps and configuration.

## Usage

    # start the adb server for usb debugging
    sudo adb start-server
    # enable usb debugging on the device and connect the android device to the computer
    # list available devices
    ./spytrap-b list
    # fetch rules for scanning
    git clone https://github.com/Te-k/stalkerware-indicators.git
    # scan the first connected device
    ./spytrap-b scan --rules stalkerware-indicators/appid.yaml

## Building from source

    # install rustup
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    # clone the repository
    https://github.com/kpcyrd/spytrap-b
    # enter the directory
    cd spytrap-b/
    # compile the project
    cargo build --release --locked
    # this is the release binary
    ./target/debug/spytrap-b

## FAQ

### `Error: Failed to list devices: Connection refused (os error 111)`

The adb server is not running correctly

### Installing adb on MacOS

    brew install android-platform-tools

### Installing adb on Arch Linux

    pacman -S android-tools

### Installing adb on Debian/Ubuntu

    apt install adb

## License

GPLv3+
