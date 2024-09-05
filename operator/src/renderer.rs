use std::io::Write;

use liquid::{to_object, Parser, ParserBuilder};
use serde::Serialize;
use tracing::{debug, instrument};

use crate::err::Result;

// Traits

#[cfg_attr(test, mockall::automock)]
pub trait Renderer: Send + Sync {
    fn render<OUT: Write + 'static, VARIABLES: Serialize + 'static>(
        &self,
        tpl: &str,
        vars: &VARIABLES,
        out: &mut OUT,
    ) -> Result;
}

// LiquidRenderer

pub struct LiquidRenderer(Parser);

impl LiquidRenderer {
    pub fn new() -> Self {
        let parser = ParserBuilder::with_stdlib().build().unwrap();
        Self(parser)
    }
}

impl Renderer for LiquidRenderer {
    #[instrument(skip(self, tpl, vars, out))]
    fn render<OUT: Write, VARIABLES: Serialize>(
        &self,
        tpl: &str,
        vars: &VARIABLES,
        out: &mut OUT,
    ) -> Result {
        debug!("parsing template");
        let tpl = self.0.parse(tpl)?;
        debug!("rendering template");
        let obj = to_object(vars)?;
        tpl.render_to(out, &obj)?;
        Ok(())
    }
}
