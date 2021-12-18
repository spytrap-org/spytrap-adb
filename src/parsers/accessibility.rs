use crate::errors::*;
use regex::Regex;
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, PartialEq, Default)]
pub struct Accessibility {
    attributes: HashMap<String, String>,
    shortcut_key: Option<String>,
    button: Option<String>,
    button_target: Option<String>,
    pub bound_services: Option<String>,
    pub enabled_services: Option<String>,
    binding_services: Option<String>,
    crashed_services: Option<String>,
}

impl Accessibility {
    fn add_attribute(&mut self, key: &str, value: &str) {
        self.attributes.insert(key.to_string(), value.to_string());
    }
}

impl FromStr for Accessibility {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut out = Accessibility::default();

        let (_, s) = s.split_once("User state[")
            .context("Failed to find `User state[` needle")?;

        let re = Regex::new(r"^\s*(.+):\{(.*)\}]?$").unwrap();
        for line in s.split('\n') {
            debug!("Parsing line of accessibility output: {:?}", line);
            if let Some(cap) = re.captures(line) {
                let key = &cap[1];
                let values = &cap[2];

                match key {
                    "attributes" => {
                        for attr in values.split(", ") {
                            if let Some((key, value)) = attr.split_once('=') {
                                out.add_attribute(key, value);
                            }
                        }
                    },
                    "shortcut key" => out.shortcut_key = values_to_option(values),
                    "button" => out.button = values_to_option(values),
                    "button target" => out.button_target = values_to_option(values),
                    "Bound services" => out.bound_services = values_to_option(values),
                    "Enabled services" => out.enabled_services = values_to_option(values),
                    "Binding services" => out.binding_services = values_to_option(values),
                    "Crashed services" => out.crashed_services = values_to_option(values),
                    _ => warn!("Found unexpected key in output: {:?}", key),
                }
            }
        }

        debug!("Parsed accessibility settings: {:?}", out);

        Ok(out)
    }
}

fn values_to_option(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
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
    fn test_parse_plain() {
        init();
        let data = include_str!("../../test_data/dumpsys/accessibility/plain.txt");
        let a = data.parse::<Accessibility>().unwrap();
        assert_eq!(a, Accessibility {
            attributes: hashmap![
                "id".to_string() => "0".to_string(),
                "touchExplorationEnabled".to_string() => "false".to_string(),
                "serviceHandlesDoubleTap".to_string() => "false".to_string(),
                "requestMultiFingerGestures".to_string() => "false".to_string(),
                "requestTwoFingerPassthrough".to_string() => "false".to_string(),
                "displayMagnificationEnabled".to_string() => "false".to_string(),
                "autoclickEnabled".to_string() => "false".to_string(),
                "nonInteractiveUiTimeout".to_string() => "0".to_string(),
                "interactiveUiTimeout".to_string() => "0".to_string(),
                "installedServiceCount".to_string() => "0".to_string(),
            ],
            shortcut_key: None,
            button: None,
            button_target: Some("null".to_string()),
            bound_services: None,
            enabled_services: None,
            binding_services: None,
            crashed_services: None,
        });
    }

    #[test]
    fn test_parse_plain2() {
        init();
        let data = include_str!("../../test_data/dumpsys/accessibility/plain2.txt");
        let a = data.parse::<Accessibility>().unwrap();
        assert_eq!(a, Accessibility {
            attributes: hashmap![
                "id".to_string() => "0".to_string(),
                "currentUser".to_string() => "true".to_string(),
                "touchExplorationEnabled".to_string() => "false".to_string(),
                "displayMagnificationEnabled".to_string() => "false".to_string(),
                "navBarMagnificationEnabled".to_string() => "false".to_string(),
                "autoclickEnabled".to_string() => "false".to_string(),
                "nonInteractiveUiTimeout".to_string() => "0".to_string(),
                "interactiveUiTimeout".to_string() => "0".to_string(),
                "installedServiceCount".to_string() => "4".to_string(),
            ],
            shortcut_key: None,
            button: None,
            button_target: None,
            bound_services: None,
            enabled_services: None,
            binding_services: None,
            crashed_services: None,
        });
    }

    #[test]
    fn test_parse_spylive360() {
        init();
        let data = include_str!("../../test_data/dumpsys/accessibility/spylive360.txt");
        let a = data.parse::<Accessibility>().unwrap();
        assert_eq!(a, Accessibility {
            attributes: hashmap![
                "id".to_string() => "0".to_string(),
                "touchExplorationEnabled".to_string() => "false".to_string(),
                "serviceHandlesDoubleTap".to_string() => "false".to_string(),
                "requestMultiFingerGestures".to_string() => "false".to_string(),
                "requestTwoFingerPassthrough".to_string() => "false".to_string(),
                "displayMagnificationEnabled".to_string() => "false".to_string(),
                "autoclickEnabled".to_string() => "false".to_string(),
                "nonInteractiveUiTimeout".to_string() => "0".to_string(),
                "interactiveUiTimeout".to_string() => "0".to_string(),
                "installedServiceCount".to_string() => "1".to_string(),
            ],
            shortcut_key: None,
            button: None,
            button_target: Some("null".to_string()),
            bound_services: Some("Service[label=WiFi, feedbackType[FEEDBACK_SPOKEN, FEEDBACK_HAPTIC, FEEDBACK_AUDIBLE, FEEDBACK_VISUAL, FEEDBACK_GENERIC, FEEDBACK_BRAILLE], capabilities=1, eventTypes=TYPES_ALL_MASK, notificationTimeout=1000, requestA11yBtn=false]".to_string()),
            enabled_services: Some("{com.wifi0/com.wifi0.AccessibilityReceiver4}".to_string()),
            binding_services: None,
            crashed_services: None,
        });
    }
}
