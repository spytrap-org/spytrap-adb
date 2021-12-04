use crate::errors::*;
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use mozdevice::Device;

const DATE_COMMAND: &str = "date -u '+%Y-%m-%d %T %N'";

pub fn determine(device: &Device) -> Result<(DateTime<Utc>, DateTime<Utc>, Duration)> {
    let output = device
        .execute_host_shell_command(DATE_COMMAND)
        .with_context(|| anyhow!("Failed to run date command: {:?}", DATE_COMMAND))?;
    let local_time = Utc::now();
    let remote_time =
        parse(output.trim()).context("Failed to parse remote time")?;
    let drift = remote_time.signed_duration_since(local_time);
    Ok((local_time, remote_time, drift))
}

fn parse(s: &str) -> Result<DateTime<Utc>> {
    let dt = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %T %f")?;
    Ok(DateTime::<Utc>::from_utc(dt, Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_parse_date() {
        let dt = parse("2021-10-21 22:37:56 716729236").unwrap();
        assert_eq!(
            dt,
            Utc.ymd(2021, 10, 21).and_hms_nano(22, 37, 56, 716729236)
        );
    }
}
