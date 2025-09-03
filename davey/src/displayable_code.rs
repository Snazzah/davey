use crate::errors::DisplayableCodeError;

pub const MAX_GROUP_SIZE: u32 = 8;

/// Generate a [displayable code](https://daveprotocol.com/#displayable-codes).
pub fn generate_displayable_code(
  data: &[u8],
  desired_length: u32,
  group_size: u32,
) -> Result<String, DisplayableCodeError> {
  if data.len() < desired_length as usize {
    return Err(DisplayableCodeError::DataLessThanDesiredLength);
  }

  if desired_length % group_size != 0 {
    return Err(DisplayableCodeError::DesiredLengthNotMultipleOfGroupSize);
  }

  if group_size > MAX_GROUP_SIZE {
    return Err(DisplayableCodeError::GroupSizeGreaterThanMaxGroupSize);
  }

  generate_displayable_code_internal(data, desired_length as usize, group_size as usize)
}

pub fn generate_displayable_code_internal(
  data: &[u8],
  desired_length: usize,
  group_size: usize,
) -> Result<String, DisplayableCodeError> {
  let group_modulus: u64 = 10u64.pow(group_size as u32);
  let mut result = String::with_capacity(desired_length);

  for i in (0..desired_length).step_by(group_size) {
    let mut group_value: u64 = 0;

    for j in (1..=group_size).rev() {
      let Some(next_byte) = data.get(i + (group_size - j)) else {
        return Err(DisplayableCodeError::OutOfBoundsDataIndex);
      };

      group_value = (group_value << 8) | (*next_byte as u64);
    }

    result.push_str(
      format!(
        "{:0width$}",
        group_value % group_modulus,
        width = group_size
      )
      .as_str(),
    );
  }

  Ok(result)
}
