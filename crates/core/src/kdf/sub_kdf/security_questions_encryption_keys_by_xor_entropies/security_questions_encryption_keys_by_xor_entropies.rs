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
    ) -> Result<EncryptionKeys<QUESTION_COUNT, MIN_CORRECT_ANSWERS>> {
        let size = MIN_CORRECT_ANSWERS;

        let key_from_combination_by_xor =
            |combination: Vec<&Exactly32Bytes>| -> EncryptionKey {
                let bytes = combination
                    .into_iter()
                    .copied()
                    .reduce(|acc, x| acc.xor(&x))
                    .unwrap();
                EncryptionKey::from(bytes)
            };

        let combinations = entropies.iter().combinations(size);

        let keys = combinations
            .into_iter()
            .map(|combination| key_from_combination_by_xor(combination))
            .collect::<IndexSet<EncryptionKey>>();

        EncryptionKeys::<QUESTION_COUNT, MIN_CORRECT_ANSWERS>::new(keys)
    }

    pub fn derive_encryption_keys_from<
        const QUESTION_COUNT: usize,
        const MIN_CORRECT_ANSWERS: usize,
    >(
        &self,
        entropies: [Exactly32Bytes; QUESTION_COUNT],
    ) -> Result<EncryptionKeys<QUESTION_COUNT, MIN_CORRECT_ANSWERS>> {
        assert!(QUESTION_COUNT >= MIN_CORRECT_ANSWERS);
        self.encryption_keys_from_xor_between_all_combinations::<QUESTION_COUNT, MIN_CORRECT_ANSWERS>(entropies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Sut = SecurityQuestionsEncryptionKeysByXorEntropies;

    #[test]
    fn derive_encryption_keys_from_order_does_not_matter() {
        let sut: Sut = SecurityQuestionsEncryptionKeysByXorEntropies;
        let entropies = [
            Exactly32Bytes::sample_aced(),
            Exactly32Bytes::sample_babe(),
            Exactly32Bytes::sample_cafe(),
        ];

        let keys1 = sut.derive_encryption_keys_from::<3, 2>(entropies).unwrap();
        let keys2 = sut
            .derive_encryption_keys_from::<3, 2>([
                entropies[2],
                entropies[0],
                entropies[1],
            ])
            .unwrap();

        assert_eq!(keys1, keys2);
    }
}
