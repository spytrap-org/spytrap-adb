pub fn human_option_str(x: Option<&String>) -> &str {
    if let Some(x) = x {
        x.as_str()
    } else {
        "-"
    }
}
