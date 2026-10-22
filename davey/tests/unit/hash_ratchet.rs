use crate::cryptor::{AES_GCM_128_KEY_BYTES, hash_ratchet::HashRatchet};

#[test]
fn expected_result() {
  let mut ratchet = HashRatchet::new(vec![
    206, 221, 97, 177, 184, 161, 202, 105, 4, 101, 84, 40, 44, 247, 11, 123,
  ]);

  let (key, nonce) = ratchet.get(0).expect("Expected success from ratchet");
  assert_eq!(
    *key,
    vec![
      117, 48, 249, 169, 148, 94, 45, 46, 6, 208, 101, 31, 123, 42, 134, 75
    ]
  );
  assert_eq!(
    *nonce,
    vec![48, 30, 95, 75, 116, 9, 15, 152, 94, 114, 107, 178]
  );
}

fn make_base_secret(fill: u8) -> Vec<u8> {
  vec![fill; AES_GCM_128_KEY_BYTES]
}

/// libdave: [`MlsKeyRatchetTests.MlsKeyRatchetDomainIdentity`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/mls_key_ratchet_tests.cpp#L25)
#[test]
fn domain_identity() {
  let ratchet_a = HashRatchet::new(make_base_secret(0xA5));
  let same_domain_as_a = HashRatchet::new(make_base_secret(0xA5));
  let ratchet_b = HashRatchet::new(make_base_secret(0x5A));

  // the base secret is derived per (epoch, user), so ratchets built from the
  // same base secret share a key domain
  assert!(!ratchet_a.domain_identity().is_empty());
  assert_eq!(
    ratchet_a.domain_identity(),
    same_domain_as_a.domain_identity()
  );
  assert_ne!(ratchet_a.domain_identity(), ratchet_b.domain_identity());
}

/// libdave: [`MlsKeyRatchetTests.MlsKeyRatchetDomainIdentityStableAcrossUse`](https://github.com/discord/libdave/blob/8de72b1f8a2ac3c5a5270755bb8091a62e3c6169/cpp/test/mls_key_ratchet_tests.cpp#L38)
#[test]
fn domain_identity_stable_across_use() {
  let mut ratchet = HashRatchet::new(make_base_secret(0xA5));
  let identity_at_creation = ratchet.domain_identity().to_vec();

  ratchet.get(0).unwrap();
  ratchet.get(3).unwrap();
  ratchet.erase(0);

  assert_eq!(ratchet.domain_identity(), identity_at_creation);
}
