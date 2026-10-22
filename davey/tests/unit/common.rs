use crate::cryptor::{AES_GCM_128_KEY_BYTES, hash_ratchet::HashRatchet};

pub const RANDOM_BYTES: &str = "0dc5aedd5bdc3f20be5697e54dd1f437b896a36f858c6f20bbd69e2a493ca170c4f0c1b9acd4\
   9d324b92afa788d09b12b29115a2feb3552b60fff983234a6c9608af3933683efc6b0f5579a9";

/// Decodes a hex string, ignoring whitespace.
pub fn from_hex(hex: &str) -> Vec<u8> {
  let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
  assert!(hex.len().is_multiple_of(2), "hex string has an odd length");
  (0..hex.len())
    .step_by(2)
    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex"))
    .collect()
}

/// libdave: `MakeStaticSenderKey` in
/// [`cpp/test/static_key_ratchet.cpp`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/static_key_ratchet.cpp#L13-L28)
pub fn make_static_sender_key(user_id: &str) -> Vec<u8> {
  let user_id: u64 = user_id.parse().expect("user id is not a u64");
  let mut key = Vec::with_capacity(AES_GCM_128_KEY_BYTES);
  key.extend_from_slice(&user_id.to_ne_bytes());
  key.extend_from_slice(&user_id.to_ne_bytes());
  key
}

/// libdave: `StaticKeyRatchet` in
/// [`cpp/test/static_key_ratchet.cpp`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/static_key_ratchet.cpp#L30-L52)
pub fn static_key_ratchet(user_id: &str) -> HashRatchet {
  HashRatchet::new(make_static_sender_key(user_id))
}
