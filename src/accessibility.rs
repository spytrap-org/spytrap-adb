use crate::dumpsys;
use crate::errors::*;
use crate::parsers::accessibility::Accessibility;
use mozdevice::Device;

pub fn dump(device: &Device) -> Result<Accessibility> {
    info!("Reading accessibility settings");
    let out = dumpsys::dump_service(&device, "accessibility")?;
    out.parse::<Accessibility>()
        .context("Failed to parse accessibility service output")
}

#[cfg(test)]
mod tests {
    // use super::*;
}
