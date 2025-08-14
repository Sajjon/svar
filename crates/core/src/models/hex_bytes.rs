use crate::prelude::*;

/// A wrapper for `Vec<u8>` that serializes as hex string
#[derive(
    Clone,
    PartialEq,
    Eq,
    Hash,
    SerializeDisplay,
    DeserializeFromStr,
    derive_more::Debug,
    derive_more::Display,
    From,
    AsRef,
)]
#[display("{}", hex_encode(self.0.clone()))]
#[debug("{}", self.to_string())]
pub struct HexBytes(Vec<u8>);

impl std::str::FromStr for HexBytes {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex_decode(s)
            .map_err(|e| Error::InvalidHex {
                underlying: e.to_string(),
            })
            .map(Self)
    }
}

impl HasSampleValues for HexBytes {
    fn sample() -> Self {
        Self::from_str("deadbeef")
            .expect("Failed to create sample HexBytes from string")
    }

    fn sample_other() -> Self {
        Self::from_str("cafebabe")
            .expect("Failed to create sample_other HexBytes from string")
    }
}

#[cfg(test)]
mod tests {
    use insta::{assert_debug_snapshot, assert_json_snapshot, assert_snapshot};

    use super::*;

    type Sut = HexBytes;

    #[test]
    fn test_hex_bytes_display() {
        assert_snapshot!(Sut::sample())
    }

    #[test]
    fn test_hex_bytes_debug() {
        assert_debug_snapshot!(Sut::sample_other())
    }

    #[test]
    fn serde() {
        assert_json_snapshot!(Sut::sample());
    }

    #[test]
    fn from_str_invalid() {
        let invalid_hex = "not_a_hex_string";
        assert!(Sut::from_str(invalid_hex).is_err());
    }

    #[test]
    fn from_str_valid() {
        let valid_hex = "deadbeef";
        let hex_bytes =
            Sut::from_str(valid_hex).expect("Failed to parse valid hex");
        assert_eq!(
            hex_bytes.0,
            hex_decode(valid_hex).expect("Failed to decode hex")
        );
    }
}
