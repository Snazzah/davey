use pyo3::prelude::*;

#[pyclass(get_all)]
#[derive(Clone)]
pub struct SigningKeyPair {
  pub private: Vec<u8>,
  pub public: Vec<u8>,
}

#[pymethods]
impl SigningKeyPair {
  #[new]
  fn new(private: Vec<u8>, public: Vec<u8>) -> Self {
    Self { private, public }
  }

  fn __repr__(&self) -> &'static str {
    let public_key = &self.public;
    let hex = public_key
      .iter()
      .map(|b| format!("{:02x}", b))
      .collect::<String>();
    Box::leak(format!("<SigningKeyPair public={}>", hex).into_boxed_str())
  }
}

impl From<davey::SigningKeyPair> for SigningKeyPair {
  fn from(skp: davey::SigningKeyPair) -> Self {
    SigningKeyPair {
      private: skp.private,
      public: skp.public,
    }
  }
}

#[pyfunction]
pub fn generate_p256_keypair() -> PyResult<SigningKeyPair> {
  let signing_key_pair = davey::SigningKeyPair::generate();
  Ok(SigningKeyPair::from(signing_key_pair))
}
