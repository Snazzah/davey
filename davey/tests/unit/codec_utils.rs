//! Ported from libdave
//! [`cpp/test/codec_utils_tests.cpp`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp)

use crate::cryptor::{
  Codec,
  frame_processors::{InboundFrameProcessor, OutboundFrameProcessor, Range},
};

use super::common::{RANDOM_BYTES, from_hex};

fn process(hex: &str, codec: Codec) -> OutboundFrameProcessor {
  let frame = from_hex(hex);
  let mut frame_processor = OutboundFrameProcessor::new();
  frame_processor.process_frame(&frame, codec);
  frame_processor
}

fn ranges(frame_processor: &OutboundFrameProcessor) -> Vec<(usize, usize)> {
  frame_processor
    .unencrypted_ranges
    .iter()
    .map(|&Range { offset, size }| (offset, size))
    .collect()
}

/// libdave: [`CodecUtilsTests.RandomOpusFrame`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L21)
#[test]
fn random_opus_frame() {
  let incoming_frame = from_hex(RANDOM_BYTES);

  let mut frame_processor = OutboundFrameProcessor::new();
  frame_processor.process_frame(&incoming_frame, Codec::OPUS);

  assert_eq!(incoming_frame.len(), 76);
  assert_eq!(frame_processor.unencrypted_bytes.len(), 0);
  assert_eq!(frame_processor.encrypted_bytes.len(), incoming_frame.len());
  assert_eq!(frame_processor.unencrypted_ranges.len(), 0);
}

/// libdave: [`CodecUtilsTests.SplitReconstruct`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L46)
#[test]
fn split_reconstruct() {
  let incoming_frame = from_hex(&format!(
    "{RANDOM_BYTES} 0000000000000000 00 000a 140a 280a 3c0a 14 fafa"
  ));
  let mut reconstructed_frame = vec![0u8; incoming_frame.len()];

  let mut frame_processor = InboundFrameProcessor::new();
  frame_processor.parse_frame(&incoming_frame);
  frame_processor
    .plaintext
    .copy_from_slice(&frame_processor.ciphertext);
  let bytes_written = frame_processor.reconstruct_frame(&mut reconstructed_frame);

  assert_eq!(bytes_written, 76);
  assert_eq!(
    incoming_frame[..bytes_written],
    reconstructed_frame[..bytes_written]
  );
}

/// libdave: [`CodecUtilsTests.H264SliceOneByteExpGolomb`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L73)
#[test]
fn h264_slice_one_byte_exp_golomb() {
  // start code, nal unit header
  // 3 exponential golomb values (first_mb_in_slice, slice_type, pic_parameter_set_id)
  // then slice payloads
  let frame_processor = process("0000000161e0fafafa", Codec::H264);
  assert_eq!(ranges(&frame_processor), [(0, 6)]);
}

/// libdave: [`CodecUtilsTests.H264ShortIDROneByteExpGolomb`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L96)
#[test]
fn h264_short_idr_one_byte_exp_golomb() {
  // SPS NAL UNIT, PPS NAL UNIT, then IDR NAL Unit
  // for IDR: nal unit header, then 3 exponential golomb values (first_mb_in_slice, slice_type,
  // pic_parameter_set_id) then IDR payloads
  let frame_processor = process(
    "000000016742c00d8c8d40d0fbc900f08846a00000000168ce3c800000000165b8fafafa",
    Codec::H264,
  );
  assert_eq!(ranges(&frame_processor), [(0, 33)]);
}

/// libdave: [`CodecUtilsTests.H264ShortIDRTwoByteExpGolomb`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L119)
#[test]
fn h264_short_idr_two_byte_exp_golomb() {
  // SPS NAL UNIT, PPS NAL UNIT, then IDR NAL Unit
  // for IDR: nal unit header, then 3 exponential golomb values (first_mb_in_slice, slice_type,
  // pic_parameter_set_id) then IDR payloads
  let frame_processor = process(
    "000000016742c00d8c8d40d0fbc900f08846a00000000168ce3c8000000001654760fafafa",
    Codec::H264,
  );
  assert_eq!(ranges(&frame_processor), [(0, 34)]);
}

/// libdave: [`CodecUtilsTests.H264LongIDROneByteExpGolomb`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L142)
#[test]
fn h264_long_idr_one_byte_exp_golomb() {
  // SPS NAL UNIT, PPS NAL UNIT, SEI NAL unit, then IDR NAL Unit
  // which has nal unit header,
  // then 3 exponential golomb values (first_mb_in_slice, slice_type, pic_parameter_set_id)
  // then IDR payloads
  let frame_processor = process(
    "00000001274d0033ab402802dd00da08846a000000000128ee3c800000000106051a47564adc5c4c433f94efc511\
     3cd143a801ffccccff020004ca90800000000125b8fafafa",
    Codec::H264,
  );
  assert_eq!(ranges(&frame_processor), [(0, 67)]);
}

/// libdave: [`CodecUtilsTests.H264LongIDRTwoByteExpGolomb`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L167)
#[test]
fn h264_long_idr_two_byte_exp_golomb() {
  // SPS NAL UNIT, PPS NAL UNIT, SEI NAL unit, then IDR NAL Unit
  // which has nal unit header, then 3 exponential golomb values
  // (first_mb_in_slice, slice_type, pic_parameter_set_id) then IDR payloads
  let frame_processor = process(
    "00000001274d0033ab402802dd00da08846a000000000128ee3c800000000106051a47564adc5c4c433f94efc5\
     11\
     3cd143a801ffccccff020004ca908000000001254760fafafa",
    Codec::H264,
  );
  assert_eq!(ranges(&frame_processor), [(0, 68)]);
}

/// libdave: [`CodecUtilsTests.H264EmulationPreventionInEarlyExpGolomb`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L192)
#[test]
fn h264_emulation_prevention_in_early_exp_golomb() {
  let frame_processor = process("00000001610000038000e0fafafa", Codec::H264);
  assert_eq!(ranges(&frame_processor), [(0, 11)]);
}

/// libdave: [`CodecUtilsTests.H264ThreeByteShortCodeExtension`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L212)
#[test]
fn h264_three_byte_short_code_extension() {
  let incoming_frame = from_hex(
    "000000012764001fac2b602802dd8088000003000800000301b46d0e1970\
     00000128ee3cb0000001258880ababab",
  );
  let mut encrypted_frame = vec![0u8; incoming_frame.len() * 2];

  let mut frame_processor = OutboundFrameProcessor::new();
  frame_processor.process_frame(&incoming_frame, Codec::H264);

  assert_eq!(ranges(&frame_processor), [(0, 45)]);

  let bytes_to_encrypt = &frame_processor.encrypted_bytes;
  let encrypted_bytes = &frame_processor.ciphertext_bytes;
  assert_eq!(bytes_to_encrypt.len(), encrypted_bytes.len());
  encrypted_frame[..bytes_to_encrypt.len()].copy_from_slice(bytes_to_encrypt);

  let reconstructed_size = bytes_to_encrypt.len() + frame_processor.unencrypted_bytes.len();
  frame_processor
    .reconstruct_frame(&mut encrypted_frame[..reconstructed_size])
    .expect("frame should be large enough");

  let expected_unencrypted_header = from_hex(
    "000000012764001fac2b602802dd8088000003000800000301b46d0e19700000000128ee3cb000000001258880",
  );
  assert_eq!(
    encrypted_frame[..expected_unencrypted_header.len()],
    expected_unencrypted_header
  );
}

/// libdave: [`CodecUtilsTests.H264TwoSliceTest`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L250)
#[test]
fn h264_two_slice() {
  // start code, nal unit header
  // 3 exponential golomb values (first_mb_in_slice, slice_type, pic_parameter_set_id)
  // then slice payload
  // and repeated again
  let frame_processor = process("0000000161e0fafafa0000000161e0fafafa", Codec::H264);
  assert_eq!(ranges(&frame_processor), [(0, 6), (9, 6)]);
}

/// libdave: [`CodecUtilsTests.H265IdrSlice`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L276)
#[test]
fn h265_idr_slice() {
  let frame_processor = process(
    "0000000140010c01ffff016000000300b0000003000003005d17024\
     000000001420101016000000300b0000003000003005da00280802d16205ee45914bff2e7f13fa2\
     000000014401c072f05324000000014e01051a47564adc5c4c433f94efc5113cd143a803ee0000ee02001fc8b88\
     0000000012801abab",
    Codec::H265,
  );
  assert_eq!(ranges(&frame_processor), [(0, 119)]);
}

/// libdave: [`CodecUtilsTests.H265TsaSlice`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L299)
#[test]
fn h265_tsa_slice() {
  let frame_processor = process("000000010201abab", Codec::H265);
  assert_eq!(ranges(&frame_processor), [(0, 6)]);
}

/// libdave: [`CodecUtilsTests.H265SimpleThreeByteCodeExtension`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L318)
#[test]
fn h265_simple_three_byte_code_extension() {
  let frame_processor = process("0000010201abab", Codec::H265);
  assert_eq!(ranges(&frame_processor), [(0, 6)]);
}

/// libdave: [`CodecUtilsTests.H265MultipleThreeByteCodeExtensions`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L337)
#[test]
fn h265_multiple_three_byte_code_extensions() {
  let frame_processor = process(
    "00000140010c01ffff016000000300b0000003000003005d17024\
     0000001420101016000000300b0000003000003005da00280802d16205ee45914bff2e7f13fa2\
     000000014401c072f05324000000014e01051a47564adc5c4c433f94efc5113cd143a803ee0000ee02001fc8b88\
     00000012801abab",
    Codec::H265,
  );
  assert_eq!(ranges(&frame_processor), [(0, 119)]);
}

/// libdave: [`CodecUtilsTests.H265TwoIdrSlice`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/codec_utils_tests.cpp#L360)
#[test]
fn h265_two_idr_slice() {
  let frame_processor = process("0000010201abab0000010201abab", Codec::H265);
  assert_eq!(ranges(&frame_processor), [(0, 6), (8, 6)]);
}
