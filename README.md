# spytrap.b

Uses adb and usb debugging to scan for suspicious apps and configuration.

## Usage

```sh
# start the adb server for usb debugging
sudo adb start-server
# enable usb debugging on the device and connect the android device to the computer
# list available devices
./spytrap-b list
# fetch rules for scanning
git clone https://github.com/Te-k/stalkerware-indicators.git
# scan the first connected device
./spytrap-b scan --rules stalkerware-indicators/appid.yaml
```

## Building from source

```sh
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
```

## Example output

```
% target/release/spytrap-b scan --rules stalkerware-indicators/appid.yaml
[2021-12-19T21:26:41Z INFO  spytrap_b] Loaded 130 rules from "stalkerware-indicators/appid.yaml"
[2021-12-19T21:26:41Z INFO  spytrap_b] Device is not rooted
[2021-12-19T21:26:41Z INFO  spytrap_b] Fetching remote clock
[2021-12-19T21:26:41Z INFO  spytrap_b] Local time is 2021-12-19 21:26:41.847457823 UTC, remote time is 2021-12-19 21:26:42.318497288 UTC, drift=PT0.471039465S
[2021-12-19T21:26:41Z INFO  spytrap_b] Comparing list of installed apps with known stalkerware ids
[2021-12-19T21:26:41Z INFO  spytrap_b] Scanning installed apps (0/192)
[2021-12-19T21:26:41Z WARN  spytrap_b] Suspicious Medium: Package "org.jitsi.meet" was manually installed
[2021-12-19T21:26:42Z WARN  spytrap_b] Suspicious Medium: Package "com.android.gpstest.osmdroid" was manually installed
[2021-12-19T21:26:46Z WARN  spytrap_b] Suspicious Medium: Package "org.fdroid.fdroid" was manually installed
[2021-12-19T21:26:46Z INFO  spytrap_b] Scanning installed apps (100/192)
[2021-12-19T21:26:48Z WARN  spytrap_b] Suspicious Medium: Package "com.wifi0" was manually installed
[2021-12-19T21:26:50Z INFO  spytrap_b] Enumerating service list
[2021-12-19T21:26:50Z INFO  spytrap_b] Reading accessibility settings
[2021-12-19T21:26:50Z INFO  spytrap_b::accessibility] Reading accessibility settings
[2021-12-19T21:26:50Z WARN  spytrap_b::accessibility] Found bound accessibility services: "Service[label=WiFi, feedbackType[FEEDBACK_SPOKEN, FEEDBACK_HAPTIC, FEEDBACK_AUDIBLE, FEEDBACK_VISUAL, FEEDBACK_GENERIC, FEEDBACK_BRAILLE], capabilities=1, eventTypes=TYPES_ALL_MASK, notificationTimeout=1000, requestA11yBtn=false]"
[2021-12-19T21:26:50Z WARN  spytrap_b::accessibility] Found enabled accessibility services: "{com.wifi0/com.wifi0.AccessibilityReceiver4}"
[2021-12-19T21:26:50Z WARN  spytrap_b] Suspicious High: An accessibility service is bound
[2021-12-19T21:26:50Z WARN  spytrap_b] Suspicious High: An accessibility service is enabled: "{com.wifi0/com.wifi0.AccessibilityReceiver4}"
[2021-12-19T21:26:50Z INFO  spytrap_b] Scan finished
```

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
