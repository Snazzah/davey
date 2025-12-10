use core::matches;

use tracing::warn;

use super::{
  Codec,
  frame_processors::OutboundFrameProcessor,
  leb128::{leb128_size, read_leb128, write_leb128},
};

const NALU_SHORT_START_SEQUENCE_SIZE: usize = 3;

const NALU_LONG_START_CODE: &[u8] = &[0x00, 0x00, 0x00, 0x01];

pub fn bytes_covering_h264_pps(payload: &[u8], size_remaining: usize) -> u16 {
  // the payload starts with three exponential golomb encoded values
  // (first_mb_in_slice, sps_id, pps_id)
  // the depacketizer needs the pps_id unencrypted
  // and the payload has RBSP encoding that we need to work around

  const EMULATION_PREVENTION_BYTE: u8 = 0x03;

  let mut payload_bit_index = 0;
  let mut zero_bit_count = 0;
  let mut parsed_exp_golomb_values = 0;

  while payload_bit_index < size_remaining as u64 * 8 && parsed_exp_golomb_values < 3 {
    let bit_index = payload_bit_index % 8;
    let byte_index = payload_bit_index as usize / 8;
    let payload_byte = payload[byte_index];

    // if we're starting a new byte
    // check if this is an emulation prevention byte
    // which we skip over
    if bit_index == 0
      && byte_index >= 2
      && payload_byte == EMULATION_PREVENTION_BYTE
      && payload[byte_index - 1] == 0
      && payload[byte_index - 2] == 0
    {
      payload_bit_index += 8;
      continue;
    }

    if (payload_byte & (1 << (7 - bit_index))) == 0 {
      // still in the run of leading zero bits
      zero_bit_count += 1;
      payload_bit_index += 1;

      if zero_bit_count >= 32 {
        warn!("Unexpectedly large exponential golomb encoded value");
        return 0;
      }
    } else {
      // we hit a one
      // skip forward the number of bits dictated by the leading number of zeroes
      parsed_exp_golomb_values += 1;
      payload_bit_index = payload_bit_index + 1 + zero_bit_count;
      zero_bit_count = 0;
    }
  }

  // this frame can be packetized as a STAP-A or a FU-A
  let result = (payload_bit_index / 8) + 1;
  let mut bytes = 0;
  if result <= u16::MAX as u64 {
    // only bytes not covering H264 PPS result can fit into unencrypted frame header size
    bytes = result as u16;
  }
  bytes
}

pub fn next_h26x_nalu_index(buffer: &[u8], search_start_index: usize) -> Option<(usize, usize)> {
  const START_CODE_HIGHEST_POSSIBLE_VALUE: u8 = 1;
  const START_CODE_END_BYTE_VALUE: u8 = 1;
  const START_CODE_LEADING_BYTES_VALUE: u8 = 0;

  // we can't find the pattern with less than 3 bytes
  if buffer.len() < NALU_SHORT_START_SEQUENCE_SIZE {
    return None;
  }

  // look for NAL unit 3 or 4 byte start code
  let mut i = search_start_index;
  while i < (buffer.len() - NALU_SHORT_START_SEQUENCE_SIZE) {
    if buffer[i + 2] > START_CODE_HIGHEST_POSSIBLE_VALUE {
      // third byte is not 0 or 1, can't be a start code
      i += NALU_SHORT_START_SEQUENCE_SIZE;
    } else if buffer[i + 1] != START_CODE_LEADING_BYTES_VALUE {
      // third byte is 0 or 1, confirmed start sequence {x, x, 0} or {x, x, 1}
      // second byte is not 0, can't be a start code
      i += 2;
    } else if buffer[i] != START_CODE_LEADING_BYTES_VALUE
      || buffer[i + 2] != START_CODE_END_BYTE_VALUE
    {
      // second byte is 0, confirmed start sequence {x, 0, 0} or {x, 0, 1}
      // third byte is 0, might be a four byte start code
      // first byte is not 0, can't be a start code
      i += 1;
    } else {
      // first byte is 0, third byte is 1, confirmed start sequence {0, 0, 1}
      let nal_unit_start_index = i + NALU_SHORT_START_SEQUENCE_SIZE;
      if i >= 1 && buffer[i - 1] == START_CODE_LEADING_BYTES_VALUE {
        // 4 byte start code
        return Some((nal_unit_start_index, 4));
      } else {
        // 3 byte start code
        return Some((nal_unit_start_index, 3));
      }
    }
  }

  // nothing found
  None
}

pub fn process_frame_opus(processor: &mut OutboundFrameProcessor, frame: &[u8]) -> bool {
  processor.add_encrypted_bytes(frame);
  true
}

pub fn process_frame_h264(processor: &mut OutboundFrameProcessor, frame: &[u8]) -> bool {
  // minimize the amount of unencrypted header data for H264 depending on the NAL unit
  // type from WebRTC, see: src/modules/rtp_rtcp/source/rtp_format_h264.cc
  // src/common_video/h264/h264_common.cc
  // src/modules/rtp_rtcp/source/video_rtp_depacketizer_h264.cc

  const NAL_HEADER_TYPE_MASK: u8 = 0x1F;
  const NAL_TYPE_SLICE: u8 = 1;
  const NAL_TYPE_IDR: u8 = 5;
  const NAL_UNIT_HEADER_SIZE: usize = 1;

  // this frame can be packetized as a STAP-A or a FU-A
  // so we need to look at the first NAL units to determine how many bytes
  // the packetizer/depacketizer will need into the payload
  if frame.len() < (NALU_SHORT_START_SEQUENCE_SIZE + NAL_UNIT_HEADER_SIZE) {
    warn!("H264 frame is too small to contain a NAL unit");
    return false;
  }

  let mut nalu_index_pair = next_h26x_nalu_index(frame, 0);
  loop {
    let Some((nal_unit_start_index, _start_code_size)) = nalu_index_pair.take() else {
      break;
    };
    if nal_unit_start_index >= frame.len() - 1 {
      break;
    }

    let nal_type = frame[nal_unit_start_index] & NAL_HEADER_TYPE_MASK;

    // copy the start code and then the NAL unit

    // Because WebRTC will convert them all start codes to 4-byte on the receiver side
    // always write a long start code and then the NAL unit
    processor.add_unencrypted_bytes(NALU_LONG_START_CODE);

    let next_nalu_index_pair = next_h26x_nalu_index(frame, nal_unit_start_index);
    let next_nalu_start = match next_nalu_index_pair {
      Some(next_nalu_index_pair) => next_nalu_index_pair.0 - next_nalu_index_pair.1,
      None => frame.len(),
    };

    if nal_type == NAL_TYPE_SLICE || nal_type == NAL_TYPE_IDR {
      // once we've hit a slice or an IDR
      // we just need to cover getting to the PPS ID
      let nal_unit_payload_start = nal_unit_start_index + NAL_UNIT_HEADER_SIZE;
      let nal_unit_pps_bytes = bytes_covering_h264_pps(
        &frame[nal_unit_payload_start..],
        frame.len() - nal_unit_payload_start,
      );

      processor.add_unencrypted_bytes(
        &frame[nal_unit_start_index..][..(NAL_UNIT_HEADER_SIZE + nal_unit_pps_bytes as usize)],
      );
      processor.add_encrypted_bytes(
        &frame[(nal_unit_start_index + NAL_UNIT_HEADER_SIZE + nal_unit_pps_bytes as usize)
          ..next_nalu_start],
      );
    } else {
      // copy the whole NAL unit
      processor.add_unencrypted_bytes(&frame[nal_unit_start_index..next_nalu_start]);
    }

    nalu_index_pair = next_nalu_index_pair;
  }

  true
}

pub fn process_frame_h265(processor: &mut OutboundFrameProcessor, frame: &[u8]) -> bool {
  // minimize the amount of unencrypted header data for H265 depending on the NAL unit
  // type from WebRTC, see: src/modules/rtp_rtcp/source/rtp_format_h265.cc
  // src/common_video/h265/h265_common.cc
  // src/modules/rtp_rtcp/source/video_rtp_depacketizer_h265.cc

  const NAL_HEADER_TYPE_MASK: u8 = 0x7E;
  const NAL_TYPE_VCL_CUTOFF: u8 = 32;
  const NAL_UNIT_HEADER_SIZE: usize = 2;

  if frame.len() < NALU_SHORT_START_SEQUENCE_SIZE + NAL_UNIT_HEADER_SIZE {
    warn!("H265 frame is too small to contain a NAL unit");
    return false;
  }

  let mut nalu_index_pair = next_h26x_nalu_index(frame, 0);
  loop {
    let Some((nal_unit_start_index, _start_code_size)) = nalu_index_pair.take() else {
      break;
    };
    if nal_unit_start_index >= frame.len() - 1 {
      break;
    }

    let nal_type = (frame[nal_unit_start_index] & NAL_HEADER_TYPE_MASK) >> 1;

    // copy the start code and then the NAL unit

    // Because WebRTC will convert them all start codes to 4-byte on the receiver side
    // always write a long start code and then the NAL unit
    processor.add_unencrypted_bytes(NALU_LONG_START_CODE);

    let next_nalu_index_pair = next_h26x_nalu_index(frame, nal_unit_start_index);
    let next_nalu_start = match next_nalu_index_pair {
      Some(next_nalu_index_pair) => next_nalu_index_pair.0 - next_nalu_index_pair.1,
      None => frame.len(),
    };

    if nal_type < NAL_TYPE_VCL_CUTOFF {
      // found a VCL NAL, encrypt the payload only
      processor.add_unencrypted_bytes(&frame[nal_unit_start_index..][..NAL_UNIT_HEADER_SIZE]);
      processor.add_encrypted_bytes(
        &frame[(nal_unit_start_index + NAL_UNIT_HEADER_SIZE)..next_nalu_start],
      );
    } else {
      // copy the whole NAL unit
      processor.add_encrypted_bytes(&frame[nal_unit_start_index..next_nalu_start]);
    }

    nalu_index_pair = next_nalu_index_pair;
  }

  true
}

pub fn process_frame_vp8(processor: &mut OutboundFrameProcessor, frame: &[u8]) -> bool {
  const KEY_FRAME_UNENCRYPTED_BYTES: usize = 10;
  const DELTA_FRAME_UNENCRYPTED_BYTES: usize = 1;

  // parse the VP8 payload header to determine if it's a key frame
  // https://datatracker.ietf.org/doc/html/rfc7741#section-4.3

  // 0 1 2 3 4 5 6 7
  // +-+-+-+-+-+-+-+-+
  // |Size0|H| VER |P|
  // +-+-+-+-+-+-+-+-+
  // P is an inverse key frame flag

  // if this is a key frame the depacketizer will read 10 bytes into the payload header
  // if this is a delta frame the depacketizer only needs the first byte of the payload
  // header (since that's where the key frame flag is)

  let unencrypted_header_bytes: usize = if frame[0] & 0x01 == 0 {
    KEY_FRAME_UNENCRYPTED_BYTES
  } else {
    DELTA_FRAME_UNENCRYPTED_BYTES
  };

  processor.add_unencrypted_bytes(&frame[..unencrypted_header_bytes]);
  processor.add_encrypted_bytes(&frame[unencrypted_header_bytes..]);

  true
}

pub fn process_frame_vp9(processor: &mut OutboundFrameProcessor, frame: &[u8]) -> bool {
  // payload descriptor is unencrypted in each packet
  // and includes all information the depacketizer needs
  processor.add_encrypted_bytes(frame);
  true
}

#[allow(
  clippy::unusual_byte_groupings,
  reason = "following upstream libdave byte groupings"
)]
pub fn process_frame_av1(processor: &mut OutboundFrameProcessor, frame: &[u8]) -> bool {
  const OBU_HEADER_HAS_EXTENSION_MASK: u8 = 0b0_0000_100;
  const OBU_HEADER_HAS_SIZE_MASK: u8 = 0b0_0000_010;
  const OBU_HEADER_TYPE_MASK: u8 = 0b0_1111_000;
  const OBU_TYPE_TEMPORAL_DELIMITER: u8 = 2;
  const OBU_TYPE_TILE_LIST: u8 = 8;
  const OBU_TYPE_PADDING: u8 = 15;
  const OBU_EXTENSION_SIZE_BYTES: usize = 1;

  let mut i = 0;
  while i < frame.len() {
    // Read the OBU header.
    let obu_header_index = i;
    let mut obu_header = frame[i];
    i += size_of_val(&obu_header);

    let obu_has_extension: bool = (obu_header & OBU_HEADER_HAS_EXTENSION_MASK) != 0;
    let obu_has_size: bool = (obu_header & OBU_HEADER_HAS_SIZE_MASK) != 0;
    let obu_type: u8 = (obu_header & OBU_HEADER_TYPE_MASK) >> 3;

    if obu_has_extension {
      // Skip extension byte
      i += OBU_EXTENSION_SIZE_BYTES;
    }

    if i >= frame.len() {
      warn!("Malformed AV1 frame: header overflows frame");
      return false;
    }

    let obu_payload_size: usize;
    if obu_has_size {
      let Some((obu_payload_size_explicit, leb128_size)) = read_leb128(&frame[i..]) else {
        warn!("Malformed AV1 frame: invalid LEB128 size");
        return false;
      };
      obu_payload_size = obu_payload_size_explicit as usize;
      i += leb128_size;
    } else {
      // If the size is not present, the OBU extends to the end of the frame.
      obu_payload_size = frame.len() - i;
    }

    let obu_payload_index = i;

    if i + obu_payload_size > frame.len() {
      warn!("Malformed AV1 frame: payload overflows frame");
      return false;
    }

    i += obu_payload_size;

    // We only copy the OBUs that will not get dropped by the packetizer
    if matches!(
      obu_type,
      OBU_TYPE_TEMPORAL_DELIMITER | OBU_TYPE_TILE_LIST | OBU_TYPE_PADDING
    ) {
      continue;
    }

    // if this is the last OBU, we may need to flip the "has size" bit
    // which allows us to append necessary protocol data to the frame
    let rewritten_without_size = i == frame.len() && obu_has_size;
    if rewritten_without_size {
      obu_header &= !OBU_HEADER_HAS_SIZE_MASK;
    }

    // write the OBU header unencrypted
    processor.add_unencrypted_bytes(&[obu_header]);
    if obu_has_extension {
      // write the extension byte unencrypted
      processor.add_unencrypted_bytes(
        &frame[(obu_header_index + size_of_val(&obu_header))..][..OBU_EXTENSION_SIZE_BYTES],
      );
    }

    // write the OBU payload size unencrypted if it was present and we didn't rewrite
    // without it
    if obu_has_size && !rewritten_without_size {
      let mut leb128_buffer = vec![0u8; leb128_size(obu_payload_size as u64)];
      write_leb128(obu_payload_size as u64, leb128_buffer.as_mut_slice());
      processor.add_unencrypted_bytes(&leb128_buffer);
    }

    // add the OBU payload, encrypted
    processor.add_encrypted_bytes(&frame[obu_payload_index..][..obu_payload_size]);
  }

  true
}

pub fn validate_encrypted_frame(processor: &OutboundFrameProcessor, frame: &[u8]) -> bool {
  let codec = &processor.frame_codec;
  if *codec != Codec::H264 && *codec != Codec::H265 {
    return true;
  }

  const PADDING: usize = NALU_SHORT_START_SEQUENCE_SIZE - 1;

  // H264 and H265 ciphertexts cannot contain a 3 or 4 byte start code {0, 0, 1}
  // otherwise the packetizer gets confused
  // and the frame we get on the decryption side will be shifted and fail to decrypt
  let mut encrypted_section_start: usize = 0;

  for range in &processor.unencrypted_ranges {
    if encrypted_section_start == range.offset {
      encrypted_section_start += range.size;
      continue;
    }

    let start = encrypted_section_start - std::cmp::min(encrypted_section_start, PADDING);
    let end = std::cmp::min(range.offset + PADDING, frame.len());
    if next_h26x_nalu_index(&frame[start..end], 0).is_some() {
      return false;
    }

    encrypted_section_start = range.offset + range.size;
  }

  if encrypted_section_start == frame.len() {
    return true;
  }

  let start = encrypted_section_start - std::cmp::min(encrypted_section_start, PADDING);
  let end = frame.len();
  if next_h26x_nalu_index(&frame[start..end], 0).is_some() {
    return false;
  }

  true
}
