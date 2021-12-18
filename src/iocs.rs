#[derive(Debug, PartialEq)]
pub struct Suspicion {
    pub level: SuspicionLevel,
    pub description: String,
}

#[derive(Debug, PartialEq)]
pub enum SuspicionLevel {
    High,
    Medium,
    Low,
}
