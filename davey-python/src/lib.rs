use pyo3::prelude::*;

macro_rules! py_value_error {
  ($($arg:tt)*) => {
    pyo3::exceptions::PyValueError::new_err(format!($($arg)*))
  };
}

mod displayable_code;
mod fingerprint;
mod session;
mod signing_key_pair;

pub use displayable_code::*;
pub use fingerprint::*;
pub use session::*;
pub use signing_key_pair::*;

/// The Python module initialization.
#[pymodule(name = "davey")]
fn davey_python(m: &Bound<'_, PyModule>) -> PyResult<()> {
  let version = env!("CARGO_PKG_VERSION").replace("-pre.", "rc");
  m.add("__version__", version)?;
  m.add("__author__", "Snazzah")?;
  m.add("__copyright__", "Copyright 2025-present Snazzah")?;
  m.add("__license__", "MIT")?;
  m.add("DEBUG_BUILD", cfg!(debug_assertions))?;
  m.add("DAVE_PROTOCOL_VERSION", davey::DAVE_PROTOCOL_VERSION)?;

  m.add_class::<SigningKeyPair>()?;
  m.add_class::<davey::Codec>()?;
  m.add_class::<davey::MediaType>()?;
  m.add_class::<davey::ProposalsOperationType>()?;
  m.add_class::<davey::SessionStatus>()?;
  m.add_class::<DaveSession>()?;
  m.add_class::<CommitWelcome>()?;
  m.add_class::<davey::EncryptionStats>()?;
  m.add_class::<davey::DecryptionStats>()?;

  m.add_function(wrap_pyfunction!(generate_p256_keypair, m)?)?;
  m.add_function(wrap_pyfunction!(generate_displayable_code, m)?)?;
  m.add_function(wrap_pyfunction!(generate_key_fingerprint, m)?)?;
  m.add_function(wrap_pyfunction!(generate_pairwise_fingerprint, m)?)?;

  Ok(())
}
