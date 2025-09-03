import test from 'ava';

import { DEBUG_BUILD, VERSION, DAVE_PROTOCOL_VERSION } from '../index';
import pkg from '../package.json';

test('VERSION returns the package version', (t) => {
  t.is(VERSION, pkg.version);
});

test('DEBUG_BUILD returns a bool', (t) => {
  t.true(typeof DEBUG_BUILD === 'boolean', 'Expected DEBUG_BUILD to be a boolean');
});

test('DAVE_PROTOCOL_VERSION returns an integer', (t) => {
  t.true(
    typeof DAVE_PROTOCOL_VERSION === 'number' && Number.isInteger(DAVE_PROTOCOL_VERSION),
    'Expected DAVE_PROTOCOL_VERSION to be an integer',
  );
});
