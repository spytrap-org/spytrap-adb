use crate::errors::*;
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, PartialEq, Default)]
pub struct Settings {
    pub values: HashMap<String, String>,
}

impl FromStr for Settings {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut out = Self::default();
        let mut failed_lines = Vec::new();
        for (number, line) in s.lines().enumerate() {
            // It does happen in real world that some variable values
            // are multi line, so this make the parsing fail
            // ignoring the lines and reporting it in the log
            if let Some((key, value)) = line.split_once('=') {
                out.values.insert(key.to_string(), value.to_string());
            } else {
                failed_lines.push(number);
            }
        }
        if !failed_lines.is_empty() {
            //Maybe should be reported as a warning in the report somehow ?
            warn!(
                "Error parsing settings at lines:{:?} content:{}",
                failed_lines, s
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maplit::hashmap;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_parse_lineage_system_namespace() -> Result<()> {
        init();
        let data = "accelerometer_rotation=0
alarm_alert=content://media/internal/audio/media/31?title=Hassium&canonical=1
alarm_alert_set=1
dim_screen=1
dtmf_tone=1
dtmf_tone_type=0
end_button_behavior=2
font_scale=1.0
haptic_feedback_enabled=0
hearing_aid=0
lockscreen_sounds_enabled=1
mode_ringer_streams_affected=422
mute_streams_affected=111
notification_light_pulse=1
notification_sound=content://media/internal/audio/media/248?title=Argon&canonical=1
notification_sound_set=1
pointer_location=0
pointer_speed=0
radio.data.stall.recovery.action=0
ringtone=content://media/internal/audio/media/72?title=Orion&canonical=1
ringtone_set=1
screen_brightness=102
screen_brightness_for_vr=86
screen_brightness_mode=0
screen_off_timeout=60000
show_touches=0
sound_effects_enabled=0
system_locales=de-DE
tty_mode=0
user_rotation=0
vibrate_when_ringing=0
volume_alarm=6
volume_bluetooth_sco=7
volume_music=5
volume_music_speaker=5
volume_music_usb_headset=3
volume_notification=5
volume_ring=5
volume_system=7
volume_voice=4
volume_voice_earpiece=3
volume_voice_speaker=5
";
        let settings = data.parse::<Settings>()?;
        assert_eq!(
            settings,
            Settings {
                values: hashmap![
                    "accelerometer_rotation".to_string() => "0".to_string(),
                    "alarm_alert".to_string() => "content://media/internal/audio/media/31?title=Hassium&canonical=1".to_string(),
                    "alarm_alert_set".to_string() => "1".to_string(),
                    "dim_screen".to_string() => "1".to_string(),
                    "dtmf_tone".to_string() => "1".to_string(),
                    "dtmf_tone_type".to_string() => "0".to_string(),
                    "end_button_behavior".to_string() => "2".to_string(),
                    "font_scale".to_string() => "1.0".to_string(),
                    "haptic_feedback_enabled".to_string() => "0".to_string(),
                    "hearing_aid".to_string() => "0".to_string(),
                    "lockscreen_sounds_enabled".to_string() => "1".to_string(),
                    "mode_ringer_streams_affected".to_string() => "422".to_string(),
                    "mute_streams_affected".to_string() => "111".to_string(),
                    "notification_light_pulse".to_string() => "1".to_string(),
                    "notification_sound".to_string() => "content://media/internal/audio/media/248?title=Argon&canonical=1".to_string(),
                    "notification_sound_set".to_string() => "1".to_string(),
                    "pointer_location".to_string() => "0".to_string(),
                    "pointer_speed".to_string() => "0".to_string(),
                    "radio.data.stall.recovery.action".to_string() => "0".to_string(),
                    "ringtone".to_string() => "content://media/internal/audio/media/72?title=Orion&canonical=1".to_string(),
                    "ringtone_set".to_string() => "1".to_string(),
                    "screen_brightness".to_string() => "102".to_string(),
                    "screen_brightness_for_vr".to_string() => "86".to_string(),
                    "screen_brightness_mode".to_string() => "0".to_string(),
                    "screen_off_timeout".to_string() => "60000".to_string(),
                    "show_touches".to_string() => "0".to_string(),
                    "sound_effects_enabled".to_string() => "0".to_string(),
                    "system_locales".to_string() => "de-DE".to_string(),
                    "tty_mode".to_string() => "0".to_string(),
                    "user_rotation".to_string() => "0".to_string(),
                    "vibrate_when_ringing".to_string() => "0".to_string(),
                    "volume_alarm".to_string() => "6".to_string(),
                    "volume_bluetooth_sco".to_string() => "7".to_string(),
                    "volume_music".to_string() => "5".to_string(),
                    "volume_music_speaker".to_string() => "5".to_string(),
                    "volume_music_usb_headset".to_string() => "3".to_string(),
                    "volume_notification".to_string() => "5".to_string(),
                    "volume_ring".to_string() => "5".to_string(),
                    "volume_system".to_string() => "7".to_string(),
                    "volume_voice".to_string() => "4".to_string(),
                    "volume_voice_earpiece".to_string() => "3".to_string(),
                    "volume_voice_speaker".to_string() => "5".to_string(),
                ],
            }
        );
        Ok(())
    }

    #[test]
    fn test_parse_lineage_secure_namespace() -> Result<()> {
        init();
        let data = "accessibility_display_inversion_enabled=null
accessibility_display_magnification_enabled=0
accessibility_display_magnification_scale=2.0
accessibility_enabled=1
adaptive_sleep=null
android_id=1df46e6e09677a0
anr_show_background=0
assistant=
autofill_service=
aware_enabled=0
aware_lock_enabled=0
backup_enabled=0
backup_transport=com.google.android.gms/.backup.BackupTransportService
bluetooth_address=A4:6C:DE:AD:F0:0D
bluetooth_name=Samsung Galaxy A Series 2017
charging_sounds_enabled=1
charging_vibration_enabled=1
clock_seconds=null
default_input_method=com.android.inputmethod.latin/.LatinIME
double_tap_to_wake=null
doze_pulse_on_double_tap=null
doze_tap_gesture=null
enabled_accessibility_services=com.wifi0/com.wifi0.AccessibilityReceiver4
enabled_input_methods=com.android.inputmethod.latin/.LatinIME
enabled_notification_assistant=android.ext.services/android.ext.services.notification.Assistant
enabled_notification_policy_access_packages=com.android.camera2
flashlight_available=1
flashlight_enabled=0
global_actions_panel_available=0
global_actions_panel_enabled=1
high_priority=null
hush_gesture_used=0
icon_blacklist=null
immersive_mode_confirmations=
input_methods_subtype_history=com.android.inputmethod.latin/.LatinIME;-921088104
install_non_market_apps=1
keyguard_slice_uri=null
location_changer=1
location_mode=3
location_providers_allowed=gps
lock_screen_allow_private_notifications=1
lock_screen_owner_info_enabled=0
lock_screen_show_notifications=1
lockscreen.disabled=0
long_press_timeout=400
manual_ringer_toggle_count=0
mock_location=0
mount_play_not_snd=1
mount_ums_autostart=0
mount_ums_notify_enabled=1
mount_ums_prompt=1
multi_press_timeout=300
navigation_mode=0
nfc_payment_default_component=null
notification_badging=1
notification_dismiss_rtl=null
notification_history_enabled=null
power_menu_locked_show_content=1
screensaver_activate_on_dock=1
screensaver_activate_on_sleep=0
screensaver_components=com.google.android.deskclock/com.android.deskclock.Screensaver
screensaver_default_component=com.google.android.deskclock/com.android.deskclock.Screensaver
screensaver_enabled=1
selected_input_method_subtype=-1
selected_spell_checker=com.android.inputmethod.latin/.spellcheck.AndroidSpellCheckerService
selected_spell_checker_subtype=0
show_first_crash_dialog_dev_option=0
show_ime_with_hard_keyboard=0
show_media_when_bypassing=null
show_zen_settings_suggestion=1
silence_gesture=0
skip_gesture=0
sleep_timeout=-1
snoozed_schedule_condition_provider=
speak_password=1
sync_parent_sounds=0
sysui_do_not_disturb=null
sysui_keyguard_left=null
sysui_keyguard_right=null
sysui_qqs_count=null
sysui_qs_fancy_anim=null
sysui_qs_move_whole_rows=null
sysui_qs_tiles=wifi,bt,dnd,flashlight,rotation,battery,cell,airplane,cast,screenrecord
sysui_tuner_version=4
sysui_volume_down_silent=null
sysui_volume_up_silent=null
touch_exploration_enabled=0
trust_agents_initialized=1
unknown_sources_default_reversed=1
usb_audio_automatic_routing_disabled=0
user_setup_complete=1
voice_interaction_service=
voice_recognition_service=
volume_hush_gesture=1
volume_link_notification=1
wake_gesture_enabled=1
zen_duration=0
zen_settings_suggestion_viewed=0
zen_settings_updated=1
";
        let settings = data.parse::<Settings>()?;
        assert_eq!(
            settings,
            Settings {
                values: hashmap![
                    "accessibility_display_inversion_enabled".to_string() => "null".to_string(),
                    "accessibility_display_magnification_enabled".to_string() => "0".to_string(),
                    "accessibility_display_magnification_scale".to_string() => "2.0".to_string(),
                    "accessibility_enabled".to_string() => "1".to_string(),
                    "adaptive_sleep".to_string() => "null".to_string(),
                    "android_id".to_string() => "1df46e6e09677a0".to_string(),
                    "anr_show_background".to_string() => "0".to_string(),
                    "assistant".to_string() => "".to_string(),
                    "autofill_service".to_string() => "".to_string(),
                    "aware_enabled".to_string() => "0".to_string(),
                    "aware_lock_enabled".to_string() => "0".to_string(),
                    "backup_enabled".to_string() => "0".to_string(),
                    "backup_transport".to_string() => "com.google.android.gms/.backup.BackupTransportService".to_string(),
                    "bluetooth_address".to_string() => "A4:6C:DE:AD:F0:0D".to_string(),
                    "bluetooth_name".to_string() => "Samsung Galaxy A Series 2017".to_string(),
                    "charging_sounds_enabled".to_string() => "1".to_string(),
                    "charging_vibration_enabled".to_string() => "1".to_string(),
                    "clock_seconds".to_string() => "null".to_string(),
                    "default_input_method".to_string() => "com.android.inputmethod.latin/.LatinIME".to_string(),
                    "double_tap_to_wake".to_string() => "null".to_string(),
                    "doze_pulse_on_double_tap".to_string() => "null".to_string(),
                    "doze_tap_gesture".to_string() => "null".to_string(),
                    "enabled_accessibility_services".to_string() => "com.wifi0/com.wifi0.AccessibilityReceiver4".to_string(),
                    "enabled_input_methods".to_string() => "com.android.inputmethod.latin/.LatinIME".to_string(),
                    "enabled_notification_assistant".to_string() => "android.ext.services/android.ext.services.notification.Assistant".to_string(),
                    "enabled_notification_policy_access_packages".to_string() => "com.android.camera2".to_string(),
                    "flashlight_available".to_string() => "1".to_string(),
                    "flashlight_enabled".to_string() => "0".to_string(),
                    "global_actions_panel_available".to_string() => "0".to_string(),
                    "global_actions_panel_enabled".to_string() => "1".to_string(),
                    "high_priority".to_string() => "null".to_string(),
                    "hush_gesture_used".to_string() => "0".to_string(),
                    "icon_blacklist".to_string() => "null".to_string(),
                    "immersive_mode_confirmations".to_string() => "".to_string(),
                    "input_methods_subtype_history".to_string() => "com.android.inputmethod.latin/.LatinIME;-921088104".to_string(),
                    "install_non_market_apps".to_string() => "1".to_string(),
                    "keyguard_slice_uri".to_string() => "null".to_string(),
                    "location_changer".to_string() => "1".to_string(),
                    "location_mode".to_string() => "3".to_string(),
                    "location_providers_allowed".to_string() => "gps".to_string(),
                    "lock_screen_allow_private_notifications".to_string() => "1".to_string(),
                    "lock_screen_owner_info_enabled".to_string() => "0".to_string(),
                    "lock_screen_show_notifications".to_string() => "1".to_string(),
                    "lockscreen.disabled".to_string() => "0".to_string(),
                    "long_press_timeout".to_string() => "400".to_string(),
                    "manual_ringer_toggle_count".to_string() => "0".to_string(),
                    "mock_location".to_string() => "0".to_string(),
                    "mount_play_not_snd".to_string() => "1".to_string(),
                    "mount_ums_autostart".to_string() => "0".to_string(),
                    "mount_ums_notify_enabled".to_string() => "1".to_string(),
                    "mount_ums_prompt".to_string() => "1".to_string(),
                    "multi_press_timeout".to_string() => "300".to_string(),
                    "navigation_mode".to_string() => "0".to_string(),
                    "nfc_payment_default_component".to_string() => "null".to_string(),
                    "notification_badging".to_string() => "1".to_string(),
                    "notification_dismiss_rtl".to_string() => "null".to_string(),
                    "notification_history_enabled".to_string() => "null".to_string(),
                    "power_menu_locked_show_content".to_string() => "1".to_string(),
                    "screensaver_activate_on_dock".to_string() => "1".to_string(),
                    "screensaver_activate_on_sleep".to_string() => "0".to_string(),
                    "screensaver_components".to_string() => "com.google.android.deskclock/com.android.deskclock.Screensaver".to_string(),
                    "screensaver_default_component".to_string() => "com.google.android.deskclock/com.android.deskclock.Screensaver".to_string(),
                    "screensaver_enabled".to_string() => "1".to_string(),
                    "selected_input_method_subtype".to_string() => "-1".to_string(),
                    "selected_spell_checker".to_string() => "com.android.inputmethod.latin/.spellcheck.AndroidSpellCheckerService".to_string(),
                    "selected_spell_checker_subtype".to_string() => "0".to_string(),
                    "show_first_crash_dialog_dev_option".to_string() => "0".to_string(),
                    "show_ime_with_hard_keyboard".to_string() => "0".to_string(),
                    "show_media_when_bypassing".to_string() => "null".to_string(),
                    "show_zen_settings_suggestion".to_string() => "1".to_string(),
                    "silence_gesture".to_string() => "0".to_string(),
                    "skip_gesture".to_string() => "0".to_string(),
                    "sleep_timeout".to_string() => "-1".to_string(),
                    "snoozed_schedule_condition_provider".to_string() => "".to_string(),
                    "speak_password".to_string() => "1".to_string(),
                    "sync_parent_sounds".to_string() => "0".to_string(),
                    "sysui_do_not_disturb".to_string() => "null".to_string(),
                    "sysui_keyguard_left".to_string() => "null".to_string(),
                    "sysui_keyguard_right".to_string() => "null".to_string(),
                    "sysui_qqs_count".to_string() => "null".to_string(),
                    "sysui_qs_fancy_anim".to_string() => "null".to_string(),
                    "sysui_qs_move_whole_rows".to_string() => "null".to_string(),
                    "sysui_qs_tiles".to_string() => "wifi,bt,dnd,flashlight,rotation,battery,cell,airplane,cast,screenrecord".to_string(),
                    "sysui_tuner_version".to_string() => "4".to_string(),
                    "sysui_volume_down_silent".to_string() => "null".to_string(),
                    "sysui_volume_up_silent".to_string() => "null".to_string(),
                    "touch_exploration_enabled".to_string() => "0".to_string(),
                    "trust_agents_initialized".to_string() => "1".to_string(),
                    "unknown_sources_default_reversed".to_string() => "1".to_string(),
                    "usb_audio_automatic_routing_disabled".to_string() => "0".to_string(),
                    "user_setup_complete".to_string() => "1".to_string(),
                    "voice_interaction_service".to_string() => "".to_string(),
                    "voice_recognition_service".to_string() => "".to_string(),
                    "volume_hush_gesture".to_string() => "1".to_string(),
                    "volume_link_notification".to_string() => "1".to_string(),
                    "wake_gesture_enabled".to_string() => "1".to_string(),
                    "zen_duration".to_string() => "0".to_string(),
                    "zen_settings_suggestion_viewed".to_string() => "0".to_string(),
                    "zen_settings_updated".to_string() => "1".to_string(),
                ],
            }
        );
        Ok(())
    }

    #[test]
    fn test_parse_lineage_global_namespace() -> Result<()> {
        init();
        let data = "adb_allowed_connection_time=604800000
adb_enabled=1
adb_wifi_enabled=0
add_users_when_locked=0
airplane_mode_on=0
airplane_mode_radios=cell,bluetooth,wifi,nfc,wimax
airplane_mode_toggleable_radios=bluetooth,wifi,nfc
always_finish_activities=0
animator_duration_scale=1.0
apply_ramping_ringer=0
art_verifier_verify_debuggable=1
assisted_gps_enabled=1
audio_safe_volume_state=3
auto_time=1
auto_time_zone=1
autofill_logging_level=0
average_time_to_discharge=-1
battery_estimates_last_update_time=1679586174046
bluetooth_disabled_profiles=0
bluetooth_on=1
bluetooth_sanitized_exposure_notification_supported=1
boot_count=22
bugreport_in_power_menu=0
cached_apps_freezer=device_default
call_auto_retry=0
captive_portal_detection_enabled=0
car_dock_sound=/product/media/audio/ui/Dock.ogg
car_undock_sound=/product/media/audio/ui/Undock.ogg
cdma_cell_broadcast_sms=1
charging_started_sound=/product/media/audio/ui/ChargingStarted.ogg
data_roaming=0
database_creation_buildid=RQ3A.211001.001
debug.force_rtl=0
debug_app=null
debug_view_attributes=0
default_install_location=0
default_restrict_background_data=0
desk_dock_sound=/product/media/audio/ui/Dock.ogg
desk_undock_sound=/product/media/audio/ui/Undock.ogg
development_settings_enabled=1
device_name=SM-A520F
device_provisioned=1
dock_audio_media_enabled=1
dock_sounds_enabled=0
dock_sounds_enabled_when_accessbility=0
emergency_tone=0
enable_freeform_support=0
enable_gnss_raw_meas_full_tracking=0
enable_gpu_debug_layers=0
enable_sizecompat_freeform=0
enhanced_mac_randomization_force_enabled=0
force_allow_on_external=0
force_desktop_mode_on_external_displays=0
force_resizable_activities=0
hdmi_control_auto_device_off_enabled=0
heads_up_notifications_enabled=1
isolated_storage_remote=null
lid_behavior=0
location_global_kill_switch=0
lock_sound=/product/media/audio/ui/Lock.ogg
low_battery_sound=/product/media/audio/ui/LowBattery.ogg
low_battery_sound_timeout=0
low_power=0
max_sound_trigger_detection_service_ops_per_day=1000
mobile_data=0
mobile_data_always_on=1
mode_ringer=2
multi_sim_data_call=-1
multi_sim_sms=-1
multi_sim_voice_call=-1
netstats_enabled=1
network_recommendations_enabled=0
network_watchlist_last_report_time=1679526000000
notification_bubbles=1
ota_disable_automatic_update=0
overlay_display_devices=null
power_sounds_enabled=1
preferred_network_mode=9
set_install_location=0
show_notification_channel_warnings=0
sound_trigger_detection_service_op_timeout=15000
stay_on_while_plugged_in=0
subscription_mode=0
sysui_demo_allowed=null
tether_offload_disabled=1
theater_mode_on=0
time_remaining_estimate_based_on_usage=0
time_remaining_estimate_millis=-1
transition_animation_scale=1.0
trusted_sound=/product/media/audio/ui/Trusted.ogg
unlock_sound=/product/media/audio/ui/Unlock.ogg
usb_mass_storage_enabled=1
wait_for_debugger=0
webview_fallback_logic_enabled=0
wifi_display_certification_on=0
wifi_display_on=0
wifi_max_dhcp_retry_count=9
wifi_migration_completed=1
wifi_networks_available_notification_on=1
wifi_on=1
wifi_scan_always_enabled=0
wifi_sleep_policy=2
wifi_wakeup_enabled=1
window_animation_scale=1.0
wireless_charging_started_sound=/product/media/audio/ui/WirelessChargingStarted.ogg
zen_duration=null
zen_mode=0
zen_mode_config_etag=-1318613002
zen_mode_ringer_level=2
";
        let settings = data.parse::<Settings>()?;
        assert_eq!(
            settings,
            Settings {
                values: hashmap![
                    "adb_allowed_connection_time".to_string() => "604800000".to_string(),
                    "adb_enabled".to_string() => "1".to_string(),
                    "adb_wifi_enabled".to_string() => "0".to_string(),
                    "add_users_when_locked".to_string() => "0".to_string(),
                    "airplane_mode_on".to_string() => "0".to_string(),
                    "airplane_mode_radios".to_string() => "cell,bluetooth,wifi,nfc,wimax".to_string(),
                    "airplane_mode_toggleable_radios".to_string() => "bluetooth,wifi,nfc".to_string(),
                    "always_finish_activities".to_string() => "0".to_string(),
                    "animator_duration_scale".to_string() => "1.0".to_string(),
                    "apply_ramping_ringer".to_string() => "0".to_string(),
                    "art_verifier_verify_debuggable".to_string() => "1".to_string(),
                    "assisted_gps_enabled".to_string() => "1".to_string(),
                    "audio_safe_volume_state".to_string() => "3".to_string(),
                    "auto_time".to_string() => "1".to_string(),
                    "auto_time_zone".to_string() => "1".to_string(),
                    "autofill_logging_level".to_string() => "0".to_string(),
                    "average_time_to_discharge".to_string() => "-1".to_string(),
                    "battery_estimates_last_update_time".to_string() => "1679586174046".to_string(),
                    "bluetooth_disabled_profiles".to_string() => "0".to_string(),
                    "bluetooth_on".to_string() => "1".to_string(),
                    "bluetooth_sanitized_exposure_notification_supported".to_string() => "1".to_string(),
                    "boot_count".to_string() => "22".to_string(),
                    "bugreport_in_power_menu".to_string() => "0".to_string(),
                    "cached_apps_freezer".to_string() => "device_default".to_string(),
                    "call_auto_retry".to_string() => "0".to_string(),
                    "captive_portal_detection_enabled".to_string() => "0".to_string(),
                    "car_dock_sound".to_string() => "/product/media/audio/ui/Dock.ogg".to_string(),
                    "car_undock_sound".to_string() => "/product/media/audio/ui/Undock.ogg".to_string(),
                    "cdma_cell_broadcast_sms".to_string() => "1".to_string(),
                    "charging_started_sound".to_string() => "/product/media/audio/ui/ChargingStarted.ogg".to_string(),
                    "data_roaming".to_string() => "0".to_string(),
                    "database_creation_buildid".to_string() => "RQ3A.211001.001".to_string(),
                    "debug.force_rtl".to_string() => "0".to_string(),
                    "debug_app".to_string() => "null".to_string(),
                    "debug_view_attributes".to_string() => "0".to_string(),
                    "default_install_location".to_string() => "0".to_string(),
                    "default_restrict_background_data".to_string() => "0".to_string(),
                    "desk_dock_sound".to_string() => "/product/media/audio/ui/Dock.ogg".to_string(),
                    "desk_undock_sound".to_string() => "/product/media/audio/ui/Undock.ogg".to_string(),
                    "development_settings_enabled".to_string() => "1".to_string(),
                    "device_name".to_string() => "SM-A520F".to_string(),
                    "device_provisioned".to_string() => "1".to_string(),
                    "dock_audio_media_enabled".to_string() => "1".to_string(),
                    "dock_sounds_enabled".to_string() => "0".to_string(),
                    "dock_sounds_enabled_when_accessbility".to_string() => "0".to_string(),
                    "emergency_tone".to_string() => "0".to_string(),
                    "enable_freeform_support".to_string() => "0".to_string(),
                    "enable_gnss_raw_meas_full_tracking".to_string() => "0".to_string(),
                    "enable_gpu_debug_layers".to_string() => "0".to_string(),
                    "enable_sizecompat_freeform".to_string() => "0".to_string(),
                    "enhanced_mac_randomization_force_enabled".to_string() => "0".to_string(),
                    "force_allow_on_external".to_string() => "0".to_string(),
                    "force_desktop_mode_on_external_displays".to_string() => "0".to_string(),
                    "force_resizable_activities".to_string() => "0".to_string(),
                    "hdmi_control_auto_device_off_enabled".to_string() => "0".to_string(),
                    "heads_up_notifications_enabled".to_string() => "1".to_string(),
                    "isolated_storage_remote".to_string() => "null".to_string(),
                    "lid_behavior".to_string() => "0".to_string(),
                    "location_global_kill_switch".to_string() => "0".to_string(),
                    "lock_sound".to_string() => "/product/media/audio/ui/Lock.ogg".to_string(),
                    "low_battery_sound".to_string() => "/product/media/audio/ui/LowBattery.ogg".to_string(),
                    "low_battery_sound_timeout".to_string() => "0".to_string(),
                    "low_power".to_string() => "0".to_string(),
                    "max_sound_trigger_detection_service_ops_per_day".to_string() => "1000".to_string(),
                    "mobile_data".to_string() => "0".to_string(),
                    "mobile_data_always_on".to_string() => "1".to_string(),
                    "mode_ringer".to_string() => "2".to_string(),
                    "multi_sim_data_call".to_string() => "-1".to_string(),
                    "multi_sim_sms".to_string() => "-1".to_string(),
                    "multi_sim_voice_call".to_string() => "-1".to_string(),
                    "netstats_enabled".to_string() => "1".to_string(),
                    "network_recommendations_enabled".to_string() => "0".to_string(),
                    "network_watchlist_last_report_time".to_string() => "1679526000000".to_string(),
                    "notification_bubbles".to_string() => "1".to_string(),
                    "ota_disable_automatic_update".to_string() => "0".to_string(),
                    "overlay_display_devices".to_string() => "null".to_string(),
                    "power_sounds_enabled".to_string() => "1".to_string(),
                    "preferred_network_mode".to_string() => "9".to_string(),
                    "set_install_location".to_string() => "0".to_string(),
                    "show_notification_channel_warnings".to_string() => "0".to_string(),
                    "sound_trigger_detection_service_op_timeout".to_string() => "15000".to_string(),
                    "stay_on_while_plugged_in".to_string() => "0".to_string(),
                    "subscription_mode".to_string() => "0".to_string(),
                    "sysui_demo_allowed".to_string() => "null".to_string(),
                    "tether_offload_disabled".to_string() => "1".to_string(),
                    "theater_mode_on".to_string() => "0".to_string(),
                    "time_remaining_estimate_based_on_usage".to_string() => "0".to_string(),
                    "time_remaining_estimate_millis".to_string() => "-1".to_string(),
                    "transition_animation_scale".to_string() => "1.0".to_string(),
                    "trusted_sound".to_string() => "/product/media/audio/ui/Trusted.ogg".to_string(),
                    "unlock_sound".to_string() => "/product/media/audio/ui/Unlock.ogg".to_string(),
                    "usb_mass_storage_enabled".to_string() => "1".to_string(),
                    "wait_for_debugger".to_string() => "0".to_string(),
                    "webview_fallback_logic_enabled".to_string() => "0".to_string(),
                    "wifi_display_certification_on".to_string() => "0".to_string(),
                    "wifi_display_on".to_string() => "0".to_string(),
                    "wifi_max_dhcp_retry_count".to_string() => "9".to_string(),
                    "wifi_migration_completed".to_string() => "1".to_string(),
                    "wifi_networks_available_notification_on".to_string() => "1".to_string(),
                    "wifi_on".to_string() => "1".to_string(),
                    "wifi_scan_always_enabled".to_string() => "0".to_string(),
                    "wifi_sleep_policy".to_string() => "2".to_string(),
                    "wifi_wakeup_enabled".to_string() => "1".to_string(),
                    "window_animation_scale".to_string() => "1.0".to_string(),
                    "wireless_charging_started_sound".to_string() => "/product/media/audio/ui/WirelessChargingStarted.ogg".to_string(),
                    "zen_duration".to_string() => "null".to_string(),
                    "zen_mode".to_string() => "0".to_string(),
                    "zen_mode_config_etag".to_string() => "-1318613002".to_string(),
                    "zen_mode_ringer_level".to_string() => "2".to_string(),
                ],
            }
        );
        Ok(())
    }
}
