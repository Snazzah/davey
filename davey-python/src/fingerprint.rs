use pyo3::prelude::*;

#[pyfunction]
pub fn generate_key_fingerprint(version: u16, key: &[u8], user_id: u64) -> PyResult<Vec<u8>> {
  davey::generate_key_fingerprint(version, key, user_id)
    .map_err(|e| py_value_error!("failed to generate key fingerprint: {:?}", e))
}

#[pyfunction]
pub fn generate_pairwise_fingerprint(
  version: u16,
  local_key: &[u8],
  local_user_id: u64,
  remote_key: &[u8],
  remote_user_id: u64,
) -> PyResult<Vec<u8>> {
  davey::generate_pairwise_fingerprint(
    version,
    local_key,
    local_user_id,
    remote_key,
    remote_user_id,
  )
  .map_err(|e| py_value_error!("failed to generate pairwise fingerprint: {:?}", e))
}
