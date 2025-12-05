use tracing::warn;

use crate::{
  cryptor::{AES_GCM_127_TRUNCATED_TAG_BYTES, MARKER_BYTES},
  errors::FrameTooSmall,
};

use super::{
  Codec,
  codec_utils::*,
  leb128::{leb128_size, read_leb128, write_leb128},
};

#[derive(Debug, Clone)]
pub struct Range {
  pub offset: usize,
  pub size: usize,
}

pub type Ranges = Vec<Range>;

pub fn unencrypted_ranges_size(unencrypted_ranges: &Ranges) -> u8 {
  let mut size: usize = 0;
  for range in unencrypted_ranges {
    size += leb128_size(range.offset as u64);
    size += leb128_size(range.size as u64);
  }
  size as u8
}

pub fn serialize_unencrypted_ranges(unencrypted_ranges: &Ranges, buffer: &mut [u8]) -> u8 {
  let mut write_at = 0;
  for range in unencrypted_ranges {
    let range_size = leb128_size(range.offset as u64) + leb128_size(range.size as u64);
    if range_size > buffer.len() - write_at {
      break;
    }

    write_at += write_leb128(range.offset as u64, &mut buffer[write_at..]);
    write_at += write_leb128(range.size as u64, &mut buffer[write_at..]);
  }
  write_at as u8
}

pub fn deserialize_unencrypted_ranges(
  read_at: &[u8],
  unencrypted_ranges: &mut Ranges,
) -> Option<u8> {
  let mut bytes_read = 0;
  while bytes_read < read_at.len() {
    let offset_read = read_leb128(&read_at[bytes_read..]);
    if offset_read.is_none() {
      unencrypted_ranges.clear();
      return None;
    }
    let (offset, read_offset) = offset_read.unwrap();
    bytes_read += read_offset;
    if bytes_read > read_at.len() {
      unencrypted_ranges.clear();
      return None;
    }

    let size_read = read_leb128(&read_at[bytes_read..]);
    if size_read.is_none() {
      unencrypted_ranges.clear();
      return None;
    }
    let (size, read_offset) = size_read.unwrap();
    bytes_read += read_offset;
    if bytes_read > read_at.len() {
      unencrypted_ranges.clear();
      return None;
    }

    unencrypted_ranges.push(Range {
      offset: offset as usize,
      size: size as usize,
    });
  }

  Some(bytes_read as u8)
}

pub fn validate_unencrypted_ranges(unencrypted_ranges: &Ranges, frame_size: usize) -> bool {
  if unencrypted_ranges.is_empty() {
    return true;
  }

  for i in 0..unencrypted_ranges.len() {
    let current = &unencrypted_ranges[i];
    let max_end = {
      if i + 1 < unencrypted_ranges.len() {
        unencrypted_ranges[i + 1].offset
      } else {
        frame_size
      }
    };
    let current_end = current.offset.saturating_add(current.size);
    if current_end > max_end {
      return false;
    }
  }

  true
}

pub fn do_reconstruct(
  ranges: &Ranges,
  range_bytes: &[u8],
  other_bytes: &[u8],
  output: &mut [u8],
) -> usize {
  let mut frame_index = 0;
  let mut range_bytes_index = 0;
  let mut other_bytes_index = 0;

  for range in ranges {
    if range.offset > frame_index {
      // copy_other_bytes(range.offset - frame_index)
      let size = range.offset - frame_index;
      output[frame_index..frame_index + size]
        .copy_from_slice(&other_bytes[other_bytes_index..other_bytes_index + size]);
      other_bytes_index += size;
      frame_index += size;
    }

    // copy_range_bytes(range.size)
    let size = range.size;
    output[frame_index..frame_index + size]
      .copy_from_slice(&range_bytes[range_bytes_index..range_bytes_index + size]);
    range_bytes_index += size;
    frame_index += size;
  }

  if frame_index < other_bytes.len() {
    // copy_other_bytes(other_bytes.size() - other_bytes_index)
    let size = other_bytes.len() - other_bytes_index;
    output[frame_index..frame_index + size]
      .copy_from_slice(&other_bytes[other_bytes_index..other_bytes_index + size]);
    frame_index += size;
  }

  frame_index
}

/// A frame processor for inbound (recieving) frames.
pub struct InboundFrameProcessor {
  pub encrypted: bool,
  original_size: usize,
  pub truncated_nonce: u32,
  unencrypted_ranges: Ranges,
  pub authenticated: Vec<u8>,
  pub ciphertext: Vec<u8>,
  pub plaintext: Vec<u8>,
  pub tag: Vec<u8>,
}

impl InboundFrameProcessor {
  pub fn new() -> Self {
    Self {
      encrypted: false,
      original_size: 0,
      truncated_nonce: u32::MAX,
      unencrypted_ranges: Vec::new(),
      authenticated: Vec::new(),
      ciphertext: Vec::new(),
      plaintext: Vec::new(),
      tag: Vec::new(),
    }
  }

  pub fn clear(&mut self) {
    self.encrypted = false;
    self.original_size = 0;
    self.truncated_nonce = u32::MAX;
    self.unencrypted_ranges.clear();
    self.authenticated.clear();
    self.ciphertext.clear();
    self.plaintext.clear();
  }

  pub fn parse_frame(&mut self, frame: &[u8]) {
    self.clear();

    const MIN_SUPPLEMENTAL_BYTES_SIZE: usize = AES_GCM_127_TRUNCATED_TAG_BYTES + 1 + 2;
    if frame.len() < MIN_SUPPLEMENTAL_BYTES_SIZE {
      warn!("Encrypted frame is too small to contain min supplemental bytes");
      return;
    }

    // Check the frame ends with the magic marker
    let magic_marker_buffer = &frame[frame.len() - MARKER_BYTES.len()..];
    if magic_marker_buffer != MARKER_BYTES {
      tracing::error!("no magic marker");
      return;
    }

    // Read the supplemental bytes size
    let bytes_size_buffer =
      &frame[frame.len() - MARKER_BYTES.len() - 1..frame.len() - MARKER_BYTES.len()];
    let bytes_size = bytes_size_buffer[0] as usize;

    // Check the frame is large enough to contain the supplemental bytes
    if frame.len() < bytes_size {
      warn!("Encrypted frame is too small to contain supplemental bytes");
      return;
    }

    // Check that supplemental bytes size is large enough to contain the supplemental bytes
    if bytes_size < MIN_SUPPLEMENTAL_BYTES_SIZE {
      warn!("Supplemental bytes size is too small to contain supplemental bytes");
      return;
    }

    let supplemental_bytes_buffer = &frame[frame.len() - bytes_size..];

    // Read the tag
    self.tag = supplemental_bytes_buffer[..AES_GCM_127_TRUNCATED_TAG_BYTES].to_vec();

    // Read the nonce
    let nonce_buffer = &supplemental_bytes_buffer[AES_GCM_127_TRUNCATED_TAG_BYTES..];
    let read_at = &nonce_buffer[..nonce_buffer.len() - MARKER_BYTES.len() - 1];
    let nonce_read = read_leb128(read_at);
    if nonce_read.is_none() {
      warn!("Failed to read truncated nonce");
      return;
    }
    let (truncated_nonce, nonce_size) = nonce_read.unwrap();
    self.truncated_nonce = truncated_nonce as u32;

    // Read the unencrypted ranges
    let mut unencrypted_ranges = Vec::new();
    if read_at.len() > nonce_size {
      let bytes_read =
        deserialize_unencrypted_ranges(&read_at[nonce_size..], &mut unencrypted_ranges);
      if bytes_read.is_none() {
        warn!("Failed to read unencrypted ranges");
        return;
      }
    }
    self.unencrypted_ranges = unencrypted_ranges;

    if !validate_unencrypted_ranges(&self.unencrypted_ranges, frame.len()) {
      warn!("Invalid unencrypted ranges");
      return;
    }

    // This is overly aggressive but will keep reallocations to a minimum
    self.authenticated.reserve(frame.len());
    self.ciphertext.reserve(frame.len());
    self.plaintext.reserve(frame.len());

    self.original_size = frame.len();

    // Split the frame into authenticated and ciphertext bytes
    let mut frame_index = 0;
    let ranges = self.unencrypted_ranges.clone();
    for range in &ranges {
      let encrypted_bytes = range.offset - frame_index;
      if encrypted_bytes > 0 {
        self.add_ciphertext_bytes(&frame[frame_index..frame_index + encrypted_bytes]);
      }

      self.add_authenticated_bytes(&frame[range.offset..range.offset + range.size]);
      frame_index = range.offset + range.size;
    }
    let actual_frame_size = frame.len() - bytes_size;
    if frame_index < actual_frame_size {
      self.add_ciphertext_bytes(&frame[frame_index..actual_frame_size]);
    }

    // Make sure the plaintext buffer is the same size as the ciphertext buffer
    self.plaintext.resize(self.ciphertext.len(), 0);

    // We've successfully parsed the frame
    // Mark the frame as encrypted
    self.encrypted = true;
  }

  pub fn reconstruct_frame(&self, frame: &mut [u8]) -> usize {
    if !self.encrypted {
      warn!("Cannot reconstruct an invalid encrypted frame");
      return 0;
    }

    if self.authenticated.len() + self.plaintext.len() > frame.len() {
      warn!("Frame is too small to contain the decrypted frame");
      return 0;
    }

    do_reconstruct(
      &self.unencrypted_ranges,
      &self.authenticated,
      &self.plaintext,
      frame,
    )
  }

  fn add_authenticated_bytes(&mut self, data: &[u8]) {
    self.authenticated.extend_from_slice(data);
  }

  fn add_ciphertext_bytes(&mut self, data: &[u8]) {
    self.ciphertext.extend_from_slice(data);
  }
}

/// A frame processor for outbound (sending) frames.
pub struct OutboundFrameProcessor {
  pub frame_codec: Codec,
  pub frame_index: usize,
  pub unencrypted_bytes: Vec<u8>,
  pub encrypted_bytes: Vec<u8>,
  pub ciphertext_bytes: Vec<u8>,
  pub unencrypted_ranges: Ranges,
}

impl OutboundFrameProcessor {
  pub fn new() -> Self {
    Self {
      frame_codec: Codec::UNKNOWN,
      frame_index: 0,
      unencrypted_bytes: Vec::new(),
      encrypted_bytes: Vec::new(),
      ciphertext_bytes: Vec::new(),
      unencrypted_ranges: Vec::new(),
    }
  }

  pub fn reset(&mut self) {
    self.frame_codec = Codec::UNKNOWN;
    self.frame_index = 0;
    self.unencrypted_bytes.clear();
    self.encrypted_bytes.clear();
    self.ciphertext_bytes.clear();
    self.unencrypted_ranges.clear();
  }

  pub fn process_frame(&mut self, frame: &[u8], codec: Codec) {
    self.reset();

    self.frame_codec = codec;
    self.unencrypted_bytes.reserve(frame.len());
    self.encrypted_bytes.reserve(frame.len());

    let success = match codec {
      Codec::OPUS => process_frame_opus(self, frame),
      Codec::H264 => process_frame_h264(self, frame),
      Codec::H265 => process_frame_h265(self, frame),
      Codec::VP8 => process_frame_vp8(self, frame),
      Codec::VP9 => process_frame_vp9(self, frame),
      Codec::AV1 => process_frame_av1(self, frame),
      _ => {
        // TODO we dont need to but maybe add more codecs later
        unimplemented!("h264, h265, vp8, vp9, av1 and opus are the only supported codecs currently")
      }
    };

    if !success {
      self.frame_index = 0;
      self.unencrypted_bytes.clear();
      self.encrypted_bytes.clear();
      self.unencrypted_ranges.clear();
      self.add_encrypted_bytes(frame);
    }

    self.ciphertext_bytes.resize(self.encrypted_bytes.len(), 0);
  }

  pub fn reconstruct_frame(&self, frame: &mut [u8]) -> Result<usize, FrameTooSmall> {
    if self.unencrypted_bytes.len() + self.ciphertext_bytes.len() > frame.len() {
      return Err(FrameTooSmall);
    }

    Ok(do_reconstruct(
      &self.unencrypted_ranges,
      &self.unencrypted_bytes,
      &self.ciphertext_bytes,
      frame,
    ))
  }

  pub fn add_unencrypted_bytes(&mut self, data: &[u8]) {
    if let Some(last_range) = self.unencrypted_ranges.last_mut() {
      if last_range.offset + last_range.size == self.frame_index {
        // extend the last range
        last_range.size += data.len();
      } else {
        // add a new range
        self.unencrypted_ranges.push(Range {
          offset: self.frame_index,
          size: data.len(),
        });
      }
    } else {
      // add the first range
      self.unencrypted_ranges.push(Range {
        offset: self.frame_index,
        size: data.len(),
      });
    }

    self.unencrypted_bytes.extend_from_slice(data);
    self.frame_index += data.len();
  }

  pub fn add_encrypted_bytes(&mut self, data: &[u8]) {
    self.encrypted_bytes.extend_from_slice(data);
    self.frame_index += data.len();
  }
}
