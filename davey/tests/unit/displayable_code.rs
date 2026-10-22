//! Ported from libdave
//! [`js/__tests__/DisplayableCode-test.ts`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/js/__tests__/DisplayableCode-test.ts)

use rand::RngCore;

use crate::generate_displayable_code;

use super::common::from_hex;

/// libdave: [`DisplayableCode expectedOutput`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/js/__tests__/DisplayableCode-test.ts#L5)
#[test]
fn expected_output() {
  let short_data = [0xaa, 0xbb, 0xcc, 0xdd, 0xee];
  assert_eq!(
    generate_displayable_code(&short_data, 5, 5).unwrap(),
    "05870"
  );

  let long_data = from_hex("aabbccddeebbccddeeffccddeeffaaddeeffaabbeeffaabbccffaabbccdd");
  assert_eq!(
    generate_displayable_code(&long_data, 30, 5).unwrap(),
    "058708105556138052119572494877"
  );
}

/// libdave: [`DisplayableCode expectedFailure`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/js/__tests__/DisplayableCode-test.ts#L14)
#[test]
fn expected_failure() {
  let too_short_data = [0xaa, 0xbb, 0xcc, 0xdd];
  assert!(generate_displayable_code(&too_short_data, 5, 5).is_err());

  let good_data = [0xaa, 0xbb, 0xcc, 0xdd];
  assert!(generate_displayable_code(&good_data, 4, 3).is_err());

  let mut random_data = [0u8; 1024];
  rand::thread_rng().fill_bytes(&mut random_data);
  assert!(generate_displayable_code(&random_data, 1024, 11).is_err());
}
