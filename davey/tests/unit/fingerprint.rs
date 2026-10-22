//! Ported from libdave
//! [`js/__tests__/KeyFingerprint-test.ts`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/js/__tests__/KeyFingerprint-test.ts) &
//! [`js/__tests__/PairwiseFingerprint-test.ts`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/js/__tests__/PairwiseFingerprint-test.ts)

use crate::{generate_key_fingerprint, generate_pairwise_fingerprint};

fn join(fingerprint: &[u8]) -> String {
  fingerprint.iter().map(|byte| byte.to_string()).collect()
}

/// libdave: [`KeyFingerprint expectedOutput`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/js/__tests__/KeyFingerprint-test.ts#L5)
#[test]
fn key_fingerprint_expected_output() {
  let short_data = [0u8; 33];
  assert_eq!(
    join(&generate_key_fingerprint(0, &short_data, 1234).unwrap()),
    "000000000000000000000000000000000000000004210"
  );

  let long_data = [0u8; 65];
  assert_eq!(
    join(&generate_key_fingerprint(0, &long_data, 12345678).unwrap()),
    "0000000000000000000000000000000000000000000000000000000000000000000000001889778"
  );
}

/// libdave: [`KeyFingerprint expectedFailure`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/js/__tests__/KeyFingerprint-test.ts#L17)
#[test]
fn key_fingerprint_expected_failure() {
  let data = [0u8; 33];
  assert!(generate_key_fingerprint(1, &data, 1234).is_err());

  assert!(generate_key_fingerprint(0, &[], 1234).is_err());
}

/// libdave: [`PairwiseFingerprint expectedOutput`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/js/__tests__/PairwiseFingerprint-test.ts#L5)
#[test]
fn pairwise_fingerprint_expected_output() {
  let data1 = [0u8; 33];
  let data2 = [0u8; 65];
  assert_eq!(
    generate_pairwise_fingerprint(0, &data1, 1234, &data2, 5678).unwrap(),
    [
      133, 129, 241, 44, 36, 135, 79, 195, 27, 28, 151, 69, 124, 197, 189, 41, 192, 7, 16, 45, 79,
      247, 138, 58, 126, 161, 178, 136, 12, 109, 96, 164, 169, 92, 2, 232, 136, 174, 74, 156, 173,
      144, 191, 184, 34, 45, 242, 136, 41, 133, 14, 158, 119, 79, 204, 48, 6, 220, 121, 6, 242, 11,
      164, 60,
    ]
  );
}

/// libdave: [`PairwiseFingerprint badSort`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/js/__tests__/PairwiseFingerprint-test.ts#L17)
#[test]
fn pairwise_fingerprint_bad_sort() {
  let data1 = [0, 100];
  let data2 = [0, 20];
  assert_eq!(
    generate_pairwise_fingerprint(0, &data1, 1, &data2, 2).unwrap(),
    [
      141, 169, 194, 143, 22, 72, 22, 245, 13, 140, 66, 228, 159, 195, 101, 106, 119, 240, 69, 191,
      178, 227, 194, 126, 162, 255, 222, 148, 138, 5, 33, 215, 240, 167, 234, 245, 149, 182, 46,
      20, 4, 83, 191, 31, 165, 74, 253, 165, 199, 16, 29, 71, 193, 205, 169, 154, 255, 154, 34, 30,
      94, 171, 247, 43,
    ]
  );
}

/// libdave: [`PairwiseFingerprint expectedFailure`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/js/__tests__/PairwiseFingerprint-test.ts#L29)
#[test]
fn pairwise_fingerprint_expected_failure() {
  let data = [0u8; 33];
  assert!(generate_pairwise_fingerprint(1, &data, 1234, &data, 5678).is_err());

  assert!(generate_pairwise_fingerprint(0, &[], 1234, &data, 5678).is_err());
}
