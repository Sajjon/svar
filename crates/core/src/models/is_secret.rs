/// A trait for types that can be treated as secrets.
///
/// You can easily implement this for your own types by implementing
/// `from_bytes` and `to_bytes` methods. We allow `to_bytes` to fail, but
///  typically it would not.
///
/// If you want to implement this trait for e.g. a BIP39 mnemonic, you should
/// convert the mnemonic to entropy bytes and converting from bytes use from
/// entropy bytes to mnemonic, that is the proper bytes encoding for a mnemonic.
pub trait IsSecret: Sized {
    fn from_bytes(
        bytes: Vec<u8>,
    ) -> std::result::Result<Self, Box<dyn std::error::Error>>;
    fn to_bytes(
        &self,
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>>;
}

impl IsSecret for String {
    fn from_bytes(
        bytes: Vec<u8>,
    ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        String::from_utf8(bytes).map_err(|e| e.into())
    }

    fn to_bytes(
        &self,
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.as_bytes().to_vec())
    }
}

impl IsSecret for Vec<u8> {
    fn from_bytes(
        bytes: Vec<u8>,
    ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        Ok(bytes)
    }

    fn to_bytes(
        &self,
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.clone())
    }
}
