use crate::dumpsys;
use crate::errors::*;
use crate::iocs::Suspicion;
use crate::parsers::accessibility::Accessibility;
use mozdevice::Device;

pub fn dump(device: &Device) -> Result<Accessibility> {
    info!("Reading accessibility settings");
    let out = dumpsys::dump_service(&device, "accessibility")?;
    out.parse::<Accessibility>()
        .context("Failed to parse accessibility service output")
}

impl Accessibility {
    pub fn audit(&self) -> Vec<Suspicion> {
        vec![]
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
        assert_eq!(&sus, &[]);
    }
}
