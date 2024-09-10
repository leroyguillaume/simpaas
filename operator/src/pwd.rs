use tracing::{debug, instrument};

// Traits

#[cfg_attr(test, mockall::automock)]
pub trait PasswordGenerator: Send + Sync {
    fn generate(&self) -> String;
}

// DefaultPasswordGenerator

pub struct DefaultPasswordGenerator(passwords::PasswordGenerator);

impl DefaultPasswordGenerator {
    pub fn new() -> Self {
        Self(passwords::PasswordGenerator {
            exclude_similar_characters: true,
            length: 12,
            lowercase_letters: true,
            numbers: true,
            spaces: false,
            strict: true,
            symbols: false,
            uppercase_letters: true,
        })
    }
}

impl PasswordGenerator for DefaultPasswordGenerator {
    #[instrument(skip(self))]
    fn generate(&self) -> String {
        debug!("generating password");
        self.0.generate_one().unwrap()
    }
}
