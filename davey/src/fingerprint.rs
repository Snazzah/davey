use scrypt::{Params, scrypt};

use crate::errors::{GenerateKeyFingerprintError, GeneratePairwiseFingerprintError};

pub const FINGERPRINT_SALT: [u8; 16] = [
  0x24, 0xca, 0xb1, 0x7a, 0x7a, 0xf8, 0xec, 0x2b, 0x82, 0xb4, 0x12, 0xb9, 0x2d, 0xab, 0x19, 0x2e,
];

/// Generate a [key fingerprint](https://daveprotocol.com/#verification-fingerprint).
pub fn generate_key_fingerprint(
  version: u16,
  key: &[u8],
  user_id: u64,
) -> Result<Vec<u8>, GenerateKeyFingerprintError> {
  if version != 0 {
    return Err(GenerateKeyFingerprintError::UnsupportedFormatVersion);
  }

  if key.is_empty() {
    return Err(GenerateKeyFingerprintError::KeyIsEmpty);
  }

  let mut result: Vec<u8> = vec![];
  result.extend(version.to_be_bytes());
  result.extend(key);
  result.extend(user_id.to_be_bytes());
  Ok(result)
}

/// Generate a [pairwise fingerprint](https://daveprotocol.com/#verification-fingerprint).
pub fn generate_pairwise_fingerprint(
  version: u16,
  local_key: &[u8],
  local_user_id: u64,
  remote_key: &[u8],
  remote_user_id: u64,
) -> Result<Vec<u8>, GeneratePairwiseFingerprintError> {
  let fingerprints = [
    generate_key_fingerprint(version, local_key, local_user_id)?,
    generate_key_fingerprint(version, remote_key, remote_user_id)?,
  ];

  pairwise_fingerprints_internal(fingerprints)
}

pub fn pairwise_fingerprints_internal(
  mut fingerprints: [Vec<u8>; 2],
) -> Result<Vec<u8>, GeneratePairwiseFingerprintError> {
  // Similar to compareArrays in libdave/js
  fingerprints.sort_by(|a, b| {
    for i in 0..std::cmp::min(a.len(), b.len()) {
      if a[i] != b[i] {
        return a[i].cmp(&b[i]);
      }
    }

    a.len().cmp(&b.len())
  });

  let params = Params::new(14, 8, 2, 64).expect("Failed to create scrypt params");

  let mut output = vec![0u8; 64];

  scrypt(
    fingerprints.concat().as_slice(),
    &FINGERPRINT_SALT,
    &params,
    &mut output,
  )
  .map_err(GeneratePairwiseFingerprintError::HashingFailed)?;

  Ok(output)
}
