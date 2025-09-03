import test from 'ava';

import { generatePairwiseFingerprint } from '../index';

test('returns valid fingerprints', async (t) => {
  const data1 = Buffer.alloc(33);
  const data2 = Buffer.alloc(65);
  t.deepEqual(
    await generatePairwiseFingerprint(0, data1, '1234', data2, '5678'),
    Buffer.from([
      133, 129, 241, 44, 36, 135, 79, 195, 27, 28, 151, 69, 124, 197, 189, 41, 192, 7, 16, 45, 79, 247, 138, 58, 126,
      161, 178, 136, 12, 109, 96, 164, 169, 92, 2, 232, 136, 174, 74, 156, 173, 144, 191, 184, 34, 45, 242, 136, 41,
      133, 14, 158, 119, 79, 204, 48, 6, 220, 121, 6, 242, 11, 164, 60,
    ]),
  );
});

test('resolves bad sorts', async (t) => {
  const data1 = Buffer.from([0, 100]);
  const data2 = Buffer.from([0, 20]);
  t.deepEqual(
    await generatePairwiseFingerprint(0, data1, '1', data2, '2'),
    Buffer.from([
      141, 169, 194, 143, 22, 72, 22, 245, 13, 140, 66, 228, 159, 195, 101, 106, 119, 240, 69, 191, 178, 227, 194, 126,
      162, 255, 222, 148, 138, 5, 33, 215, 240, 167, 234, 245, 149, 182, 46, 20, 4, 83, 191, 31, 165, 74, 253, 165, 199,
      16, 29, 71, 193, 205, 169, 154, 255, 154, 34, 30, 94, 171, 247, 43,
    ]),
  );
});

test('throws on invalid arguments', async (t) => {
  const data = Buffer.alloc(33);
  // Invalid fingerprint version
  await t.throwsAsync(generatePairwiseFingerprint(1, data, '1234', data, '5678'));
  // Invalid User ID
  await t.throwsAsync(generatePairwiseFingerprint(0, data, 'abcd', data, '5678'));
  // Zero-length key
  await t.throwsAsync(generatePairwiseFingerprint(0, Buffer.alloc(0), '1234', data, '5678'));
});
