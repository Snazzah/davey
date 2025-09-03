use super::{Codec, frame_processors::OutboundFrameProcessor};

// const NALU_SHORT_START_SEQUENCE_SIZE: u8 = 3;

pub fn process_frame_opus(processor: &mut OutboundFrameProcessor, frame: &[u8]) -> bool {
  processor.add_encrypted_bytes(frame);
  true
}

pub fn validate_encrypted_frame(processor: &OutboundFrameProcessor, _frame: &[u8]) -> bool {
  let codec = &processor.frame_codec;
  if *codec != Codec::H264 && *codec != Codec::H265 {
    return true;
  }

  // const PADDING: usize = NALU_SHORT_START_SEQUENCE_SIZE as usize - 1;

  // let unencrypted_ranges = processor.get_unencrypted_ranges();

  // // H264 and H265 ciphertexts cannot contain a 3 or 4 byte start code {0, 0, 1}
  // // otherwise the packetizer gets confused
  // // and the frame we get on the decryption side will be shifted and fail to decrypt
  // let mut encrypted_section_start: usize = 0;

  // for range in unencrypted_ranges {
  //   if encrypted_section_start == range.offset {
  // 		encrypted_section_start += range.size;
  // 		continue;
  // 	}

  // 	let start = encrypted_section_start - min(encrypted_section_start, PADDING);
  // 	let end = min(range.offset + PADDING, frame.len());
  // 	if (next_h26x_nalu_index(frame.data() + start, end - start)) {
  // 		return false;
  // 	}
  // }

  // if (encrypted_section_start == frame.size()) {
  // 	return true;
  // }

  // auto start = encrypted_section_start - std::min(encrypted_section_start, size_t{padding});
  // auto end = frame.size();
  // if (next_h26x_nalu_index(frame.data() + start, end - start)) {
  // 	return false;
  // }

  true
}
