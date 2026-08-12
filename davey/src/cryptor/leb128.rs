const LEB128_MAX_SIZE: usize = 10;

pub fn leb128_size(value: u64) -> usize {
  let mut size: usize = 0;
  let mut value = value;
  while value >= 0x80 {
    size += 1;
    value >>= 7;
  }
  size + 1
}

pub fn read_leb128(slice: &[u8]) -> Option<(u64, usize)> {
  let mut value = 0u64;
  let mut shift = 0;
  let mut size = 0;

  for (index, &byte) in slice.iter().take(LEB128_MAX_SIZE).enumerate() {
    if index == LEB128_MAX_SIZE - 1 && byte > 1 {
      return None;
    }

    value |= ((byte & 0x7F) as u64) << shift;
    size += 1;
    if byte & 0x80 == 0 {
      return Some((value, size));
    }
    shift += 7;
  }

  None
}

pub fn write_leb128(mut value: u64, buffer: &mut [u8]) -> usize {
  let mut size = 0;
  while value >= 0x80 {
    buffer[size] = 0x80 | (value & 0x7F) as u8;
    size += 1;
    value >>= 7;
  }
  buffer[size] = value as u8;
  size += 1;
  size
}

#[cfg(test)]
mod tests {
  use super::{LEB128_MAX_SIZE, read_leb128};

  #[test]
  fn reads_maximum_u64() {
    let encoded = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

    assert_eq!(read_leb128(&encoded), Some((u64::MAX, encoded.len())));
  }

  #[test]
  fn rejects_unterminated_value_at_maximum_size() {
    assert_eq!(read_leb128(&[0x80; LEB128_MAX_SIZE]), None);
  }

  #[test]
  fn rejects_overflow_in_tenth_byte() {
    let encoded = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];

    assert_eq!(read_leb128(&encoded), None);
  }

  #[test]
  fn rejects_value_longer_than_maximum_size() {
    let encoded = [0x80; LEB128_MAX_SIZE + 1];

    assert_eq!(read_leb128(&encoded), None);
  }
}
