use crate::prelude::*;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct SecurityQuestionsEncryptionKeysByXorEntropies;

impl SecurityQuestionsEncryptionKeysByXorEntropies {
    fn encryption_keys_from_xor_between_all_combinations<
        const QUESTION_COUNT: usize,
        const MIN_CORRECT_ANSWERS: usize,
    >(
        &self,
        entropies: [Exactly32Bytes; QUESTION_COUNT],
    ) -> Vec<EncryptionKey> {
        let size = MIN_CORRECT_ANSWERS;

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

    pub fn derive_encryption_keys_from<
        const QUESTION_COUNT: usize,
        const MIN_CORRECT_ANSWERS: usize,
    >(
        &self,
        entropies: [Exactly32Bytes; QUESTION_COUNT],
    ) -> Vec<EncryptionKey> {
        assert!(QUESTION_COUNT >= MIN_CORRECT_ANSWERS);
        self.encryption_keys_from_xor_between_all_combinations::<QUESTION_COUNT, MIN_CORRECT_ANSWERS>(entropies)
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
