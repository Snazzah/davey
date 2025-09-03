// const LEB128_MAX_SIZE = 10

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

  for &byte in slice {
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
