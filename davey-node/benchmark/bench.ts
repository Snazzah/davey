import { run, bench, summary, do_not_optimize } from 'mitata';
import { generateKeyFingerprint, generatePairwiseFingerprint, generateDisplayableCode } from '..';
import {
  generateKeyFingerprint as libdave_generateKeyFingerprint,
  generatePairwiseFingerprint as libdave_generatePairwiseFingerprint,
  generateDisplayableCode as libdave_generateDisplayableCode,
} from './libdave/libdave';

// generateKeyFingerprint
summary(() => {
  bench('@snazzah/davey/generateKeyFingerprint', async () =>
    do_not_optimize(generateKeyFingerprint(0, Buffer.alloc(33), '1234')),
  ).gc('inner');
  bench('libdave/generateKeyFingerprint', async () =>
    do_not_optimize(await libdave_generateKeyFingerprint(0, new Uint8Array(33), '1234')),
  ).gc('inner');
});

// generatePairwiseFingerprint
summary(() => {
  bench('@snazzah/davey/generatePairwiseFingerprint', async () =>
    do_not_optimize(await generatePairwiseFingerprint(0, Buffer.alloc(33), '1234', Buffer.alloc(65), '5678')),
  ).gc('inner');
  bench('libdave/generatePairwiseFingerprint', async () =>
    do_not_optimize(
      await libdave_generatePairwiseFingerprint(0, new Uint8Array(33), '1234', new Uint8Array(65), '5678'),
    ),
  ).gc('inner');
});

// generateDisplayableCode
summary(() => {
  bench('@snazzah/davey/generateDisplayableCode', async () =>
    do_not_optimize(generateDisplayableCode(Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee]), 5, 5)),
  ).gc('inner');
  bench('libdave/generateDisplayableCode', async () =>
    do_not_optimize(libdave_generateDisplayableCode(new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee]), 5, 5)),
  ).gc('inner');
});

await run();
