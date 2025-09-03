import test from 'ava';

import { generateKeyFingerprint } from '../index';

test('returns valid fingerprints', (t) => {
  const shortData = Buffer.alloc(33);
  t.is(generateKeyFingerprint(0, shortData, '1234').join(''), '000000000000000000000000000000000000000004210');

  const longData = Buffer.alloc(65);
  t.is(
    generateKeyFingerprint(0, longData, '12345678').join(''),
    '0000000000000000000000000000000000000000000000000000000000000000000000001889778',
  );
});

test('throws on invalid arguments', (t) => {
  const data = Buffer.alloc(33);
  // Invalid fingerprint version
  t.throws(() => generateKeyFingerprint(1, data, '1234'));
  // Invalid User ID
  t.throws(() => generateKeyFingerprint(0, data, 'abcd'));
  // Zero-length key
  t.throws(() => generateKeyFingerprint(0, Buffer.alloc(0), 'abcd'));
});
