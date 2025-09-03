use napi::bindgen_prelude::*;

/// Generate a displayable code.
/// @see https://daveprotocol.com/#displayable-codes
#[napi]
pub fn generate_displayable_code(
  data: Buffer,
  desired_length: u32,
  group_size: u32,
) -> Result<String> {
  let result = davey::generate_displayable_code(&data, desired_length, group_size)
    .map_err(|e| napi_invalid_arg_error!("failed to generate displayable code: {:?}", e))?;

  Ok(result)
}
