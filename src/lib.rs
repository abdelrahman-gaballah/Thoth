use std::pin::Pin;
pub use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuraError {
    #[error("profiler error: {0}")]
    Profiler(String),
    #[error("ast parsing error: {0}")]
    AstParse(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type AuraResult<T> = Result<T, AuraError>;

pub trait AuraModule: Send + Sync {
    fn new() -> Self where Self: Sized;
    fn initialize(&mut self) -> Pin<Box<dyn std::future::Future<Output = AuraResult<()>> + Send + '_>>;
}

// هنا بنعرف المجلدات فقط
pub mod sys;
pub mod security;
pub mod core; // ده السطر اللي هيربط "العقل" ببقية البرنامج
