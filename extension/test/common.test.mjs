import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const BEGIN = '// <oncl-common>';
const END = '// </oncl-common>';

/** The `<oncl-common>` block of `extension/src/<name>`, markers included. */
function commonBlock(name) {
  const text = readFileSync(new URL(`../src/${name}`, import.meta.url), 'utf8');
  const start = text.indexOf(BEGIN);
  const end = text.indexOf(END);
  assert.ok(start >= 0 && end > start, `${name}: no ${BEGIN} … ${END} block`);
  assert.equal(text.indexOf(BEGIN, start + 1), -1, `${name}: more than one block`);
  return text.slice(start, end + END.length);
}

// The scripts run in three separate worlds (page, content script, background) and cannot
// share a helper file without leaking globals into the page, so each carries a copy.
test('the <oncl-common> block is identical in shim, bridge and background', () => {
  const shim = commonBlock('shim.js');
  assert.ok(shim.includes('function socketUrl('));
  assert.equal(commonBlock('bridge.js'), shim);
  assert.equal(commonBlock('background.js'), shim);
});
