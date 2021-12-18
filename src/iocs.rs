pub struct Suspicion {
    pub level: SuspicionLevel,
    pub key: String,
    pub description: String,
}

pub enum SuspicionLevel {
    High,
    Medium,
    Low,
}
