use crate::prelude::*;

pub struct Mnemonic(bip39::Mnemonic);

impl Mnemonic {
    pub fn to_entropy(&self) -> [u8; 32] {
        // Convert the mnemonic words to entropy
        todo!()
    }

    pub(crate) fn from_internal(internal: bip39::Mnemonic) -> Self {
        Self(internal)
    }

    pub fn from_32bytes_entropy(entropy: Exactly32Bytes) -> Self {
        bip39::Mnemonic::from_entropy(entropy.bytes())
            .map(Self::from_internal)
            .expect("Should be able to create mnemonic from 32 bytes entropy")
    }

    pub fn from_phrase(phrase: &str) -> Result<Self> {
        bip39::Mnemonic::from_str(phrase)
            .map_err(|e| Error::InvalidMnemonicPhrase {
                underlying: e.to_string(),
            })
            .map(Self::from_internal)
    }
}

impl HasSampleValues for Mnemonic {
    /// A sample used to facilitate unit tests.
    fn sample() -> Self {
        Self::from_phrase("bright club bacon dinner achieve pull grid save ramp cereal blush woman humble limb repeat video sudden possible story mask neutral prize goose mandate").expect("Valid mnemonic")
    }

    fn sample_other() -> Self {
        Self::from_phrase("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
            .expect("Valid mnemonic")
    }
}
