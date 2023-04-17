use crate::dumpsys;
use crate::errors::*;
use crate::ioc::{Suspicion, SuspicionLevel};
use crate::parsers::accessibility::Accessibility;
use forensic_adb::Device;

pub async fn dump(device: &Device) -> Result<Accessibility> {
    info!("Reading accessibility settings");
    let out = dumpsys::dump_service(device, "accessibility").await?;
    out.parse::<Accessibility>()
        .context("Failed to parse accessibility service output")
}

impl Accessibility {
    pub fn audit(&self) -> Vec<Suspicion> {
        let mut sus = Vec::new();
        if let Some(services) = &self.bound_services {
            warn!("Found bound accessibility services: {:?}", services);
            sus.push(Suspicion {
                level: SuspicionLevel::High,
                description: "An accessibility service is bound".to_string(),
            });
        }
        if let Some(services) = &self.enabled_services {
            warn!("Found enabled accessibility services: {:?}", services);
            sus.push(Suspicion {
                level: SuspicionLevel::High,
                description: format!("An accessibility service is enabled: {:?}", services),
            });
        }
        sus
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_accessibility_plain() {
        let data = include_str!("../test_data/dumpsys/accessibility/plain.txt");
        let a = data.parse::<Accessibility>().unwrap();
        let sus = a.audit();
        assert_eq!(&sus, &[]);
    }

    #[test]
    fn test_audit_accessibility_plain2() {
        let data = include_str!("../test_data/dumpsys/accessibility/plain2.txt");
        let a = data.parse::<Accessibility>().unwrap();
        let sus = a.audit();
        assert_eq!(&sus, &[]);
    }

    #[test]
    fn test_audit_accessibility_spylive360() {
        let data = include_str!("../test_data/dumpsys/accessibility/spylive360.txt");
        let a = data.parse::<Accessibility>().unwrap();
        let sus = a.audit();
        assert_eq!(&sus, &[
            Suspicion {
                level: SuspicionLevel::High,
                description: "An accessibility service is bound".to_string(),
            },
            Suspicion {
                level: SuspicionLevel::High,
                description: "An accessibility service is enabled: \"{com.wifi0/com.wifi0.AccessibilityReceiver4}\"".to_string(),
            },
        ]);
    }
}
