use crate::prelude::*;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct SecurityQuestionsEncryptionKeysByXorEntropies;

impl SecurityQuestionsEncryptionKeysByXorEntropies {
    fn encryption_keys_from_xor_between_all_combinations(
        &self,
        entropies: Vec<Exactly32Bytes>,
        minus: usize,
    ) -> Vec<EncryptionKey> {
        let size = entropies.len() - minus;

        let key_from_combination_by_xor = |combination: Vec<&Exactly32Bytes>| -> EncryptionKey {
            let bytes = combination
                .into_iter()
                .copied()
                .reduce(|acc, x| acc.xor(&x))
                .unwrap();
            EncryptionKey::from(bytes)
        };

        let combinations = entropies.iter().combinations(size);

        combinations
            .into_iter()
            .map(|combination| key_from_combination_by_xor(combination))
            .collect()
    }

    pub fn derive_encryption_keys_from(
        &self,
        entropies: Vec<Exactly32Bytes>,
    ) -> Vec<EncryptionKey> {
        let minus = 2;
        assert!((entropies.len() - minus) > 1);

        self.encryption_keys_from_xor_between_all_combinations(entropies, minus)
    }
}

impl HasSampleValues for SecurityQuestionsEncryptionKeysByXorEntropies {
    fn sample() -> Self {
        Self
    }

    fn sample_other() -> Self {
        Self
    }
}
