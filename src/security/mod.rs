
use crate::{AuraModule, AuraResult};
use std::pin::Pin;
pub mod ast_parser;
pub mod guardrails;
pub mod sandbox;
// هنا بنعرف الملف اللي جوه المجلد

pub struct SecurityManager {
    ast_parser: ast_parser::AstParser,
}

impl AuraModule for SecurityManager {
    fn new() -> Self {
        Self {
            ast_parser: ast_parser::AstParser::new(),
        }
    }

    fn initialize(&mut self) -> Pin<Box<dyn std::future::Future<Output = AuraResult<()>> + Send + '_>> {
        Box::pin(async move {
            self.ast_parser.initialize().await?;
            Ok(())
        })
    }
}
