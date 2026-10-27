pub const LEB128_MAX_SIZE: usize = 10;

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
  let mut fill_bits = 0;
  let mut size = 0;

  while size < slice.len() && fill_bits < 64 - 7 {
    let byte = slice[size];
    value |= ((byte & 0x7F) as u64) << fill_bits;
    size += 1;
    fill_bits += 7;
    if byte & 0x80 == 0 {
      return Some((value, size));
    }
  }

  // Read 9 bytes and didn't find the terminator byte. Check if 10th byte
  // is that terminator, however to fit result into u64 it may carry only
  // single bit.
  match slice.get(size) {
    Some(&byte) if byte <= 1 => Some((value | (byte as u64) << fill_bits, size + 1)),
    _ => None,
  }
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
