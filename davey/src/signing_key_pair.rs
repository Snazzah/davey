use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;

/// A signing key pair. This is needed if you want to pass your own key pair or store the key pair for later.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKeyPair {
  pub private: Vec<u8>,
  pub public: Vec<u8>,
}

impl SigningKeyPair {
  /// Generate a signing key pair.
  pub fn generate() -> Self {
    let signing_key = SigningKey::random(&mut OsRng);

    SigningKeyPair {
      private: signing_key.to_bytes().to_vec(),
      public: signing_key
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes()
        .to_vec(),
    }
  }
}
