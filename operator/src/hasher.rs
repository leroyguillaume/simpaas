use sha2::{Digest, Sha256};
use tracing::instrument;

// Hasher

#[cfg_attr(test, mockall::automock)]
pub trait Hasher: Send + Sync {
    fn hash<DATA: AsRef<[u8]> + 'static>(&self, data: &DATA) -> String;
}

// Sha256Hasher

pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    #[instrument(skip(self, data))]
    fn hash<DATA: AsRef<[u8]>>(&self, data: &DATA) -> String {
        let mut digest = Sha256::new();
        digest.update(data.as_ref());
        let checksum = digest.finalize();
        hex::encode(checksum)
    }
}

// Tests

#[cfg(test)]
mod test {
    use crate::test::*;

    use super::*;

    // Mods

    mod sha256_hasher {
        use super::*;

        // Mods

        mod hash {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                data: &'static str,
            }

            impl Default for Data {
                fn default() -> Self {
                    Self { data: "test" }
                }
            }

            // Tests

            #[test]
            fn test() {
                init_tracer();
                let data = Data::default();
                let hasher = Sha256Hasher;
                let checksum = hasher.hash(&data.data);
                assert_eq!(
                    checksum,
                    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                );
            }
        }
    }
}
