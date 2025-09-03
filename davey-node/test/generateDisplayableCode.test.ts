import test from 'ava';
import crypto from 'node:crypto';

import { generateDisplayableCode } from '../index';

test('returns valid codes', (t) => {
  const shortData = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
  t.is(generateDisplayableCode(shortData, 5, 5), '05870');

  const longData = Buffer.from('aabbccddeebbccddeeffccddeeffaaddeeffaabbeeffaabbccffaabbccdd', 'hex');
  t.is(generateDisplayableCode(longData, 30, 5), '058708105556138052119572494877');
});

test('throws on invalid arguments', (t) => {
  const tooShortData = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]);
  t.throws(() => generateDisplayableCode(tooShortData, 5, 5));

  const goodData = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]);
  t.throws(() => generateDisplayableCode(goodData, 4, 3));

  const randomData = crypto.getRandomValues(new Uint8Array(1024));
  t.throws(() => generateDisplayableCode(Buffer.from(randomData), 1024, 11));
});
