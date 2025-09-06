use pyo3::prelude::*;

#[pyfunction]
pub fn generate_displayable_code(
  data: &[u8],
  desired_length: u32,
  group_size: u32,
) -> PyResult<String> {
  let result = davey::generate_displayable_code(data, desired_length, group_size)
    .map_err(|e| py_value_error!("failed to generate displayable code: {:?}", e))?;

  Ok(result)
}
