use std::io::Write;

use liquid::{to_object, Parser, ParserBuilder};
use serde_json::Value;
use tracing::{debug, instrument};

// Types

pub type Result<VALUE = ()> = std::result::Result<VALUE, Error>;

// Error

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(#[source] Box<dyn std::error::Error + Send + Sync>);

impl From<liquid::Error> for Error {
    fn from(err: liquid::Error) -> Self {
        Self(Box::new(err))
    }
}

// Traits

#[cfg_attr(feature = "mock", mockall::automock)]
pub trait Renderer: Send + Sync {
    fn render<OUT: Write + 'static>(&self, tpl: &str, vars: &Value, out: &mut OUT) -> Result;
}

// LiquidRenderer

pub struct LiquidRenderer(Parser);

impl LiquidRenderer {
    pub fn new() -> Self {
        let parser = ParserBuilder::with_stdlib().build().unwrap();
        Self(parser)
    }
}

impl Default for LiquidRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl Renderer for LiquidRenderer {
    #[instrument(skip(self, tpl, vars, out))]
    fn render<OUT: Write>(&self, tpl: &str, vars: &Value, out: &mut OUT) -> Result {
        debug!("parsing template");
        let tpl = self.0.parse(tpl)?;
        debug!("rendering template");
        let obj = to_object(vars)?;
        tpl.render_to(out, &obj)?;
        Ok(())
    }
}
