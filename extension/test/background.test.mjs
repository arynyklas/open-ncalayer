import assert from 'node:assert/strict';
import test from 'node:test';

import { HOST_NAME, backgroundChrome, loadScript } from './env.mjs';

const createBackground = loadScript('background.js');
const URL_13579 = 'wss://127.0.0.1:13579/';
const SITE = { origin: 'https://site.example', url: 'https://site.example/login' };
const OTHER = { origin: 'https://other.example', url: 'https://other.example/' };

// The background logs host errors and unknown frames; keep the test output clean.
test.beforeEach((t) => {
  for (const level of ['debug', 'warn', 'error']) t.mock.method(console, level, () => {});
});

function setup() {
  const env = backgroundChrome();
  createBackground(env.chrome, HOST_NAME);
  return env;
}

/** Frames the background posted to a bridge. */
const received = (port) => port.posted;

test('background stamps sender.origin and drops page-supplied origin', () => {
  const env = setup();
  const site = env.connectBridge(SITE);
  assert.equal(env.natives.length, 0, 'the native port opens lazily');
  site.deliver({ t: 'open', sid: 1, url: URL_13579, origin: 'https://evil.example' });
  assert.equal(env.natives.length, 1);
  const native = env.natives[0];
  assert.equal(native.name, HOST_NAME);
  assert.deepEqual(native.posted, [{ t: 'open', sid: 1, origin: 'https://site.example', url: URL_13579 }]);

  // Without `sender.origin` (Firefox) the origin comes from `sender.url`.
  const firefox = env.connectBridge({ url: 'http://127.0.0.1:8080/page?q=1#x' });
  firefox.deliver({ t: 'open', sid: 7, url: URL_13579 });
  assert.deepEqual(native.posted[1], { t: 'open', sid: 2, origin: 'http://127.0.0.1:8080', url: URL_13579 });

  // Frames for unknown sids and malformed frames never reach the daemon.
  site.deliver({ t: 'msg', sid: 9, data: 'x' });
  site.deliver({ t: 'open', sid: -1, url: URL_13579 });
  site.deliver({ t: 'open', sid: 2, url: 42 });
  site.deliver({ t: 'whatever', sid: 1 });
  assert.equal(native.posted.length, 2);
});

test('background maps local sids of two bridges to distinct global sids and routes replies', () => {
  const env = setup();
  const a = env.connectBridge(SITE);
  const b = env.connectBridge(OTHER);
  a.deliver({ t: 'open', sid: 1, url: URL_13579 });
  b.deliver({ t: 'open', sid: 1, url: URL_13579 });
  assert.equal(env.natives.length, 1, 'one native port for every bridge');
  const native = env.natives[0];
  assert.deepEqual(
    native.posted.map((f) => [f.sid, f.origin]),
    [
      [1, SITE.origin],
      [2, OTHER.origin],
    ],
  );

  native.deliver({ t: 'relay', v: 1, version: '0.1.0' });
  native.deliver({ t: 'hello', v: 1, version: '0.1.0', compat: '1.4' });
  native.deliver({ t: 'open', sid: 2 });
  native.deliver({ t: 'msg', sid: 2, data: '{"result":{"version":"1.4"}}' });
  native.deliver({ t: 'open', sid: 1 });
  native.deliver({ t: 'msg', sid: 1, data: 'Қаз', more: true });
  native.deliver({ t: 'msg', sid: 1, data: 'ақ' });
  native.deliver({ t: 'msg', sid: 99, data: 'unknown sid' });
  native.deliver({ t: 'future', sid: 1 });
  assert.deepEqual(received(a), [
    { t: 'open', sid: 1 },
    { t: 'msg', sid: 1, data: 'Қаз', more: true },
    { t: 'msg', sid: 1, data: 'ақ' },
  ]);
  assert.deepEqual(received(b), [
    { t: 'open', sid: 1 },
    { t: 'msg', sid: 1, data: '{"result":{"version":"1.4"}}' },
  ]);

  a.deliver({ t: 'msg', sid: 1, data: 'from a', more: true });
  a.deliver({ t: 'msg', sid: 1, data: 'x\uD800' });
  b.deliver({ t: 'msg', sid: 1, data: 'from b' });
  b.deliver({ t: 'close', sid: 1 });
  b.deliver({ t: 'msg', sid: 1, data: 'after close' });
  assert.deepEqual(native.posted.slice(2), [
    { t: 'msg', sid: 1, data: 'from a', more: true },
    { t: 'msg', sid: 1, data: 'x\uFFFD' },
    { t: 'msg', sid: 2, data: 'from b' },
    { t: 'close', sid: 2 },
  ]);

  // A reused local sid replaces the old socket; global sids never repeat.
  a.deliver({ t: 'open', sid: 1, url: URL_13579 });
  assert.deepEqual(native.posted.slice(-2), [
    { t: 'close', sid: 1 },
    { t: 'open', sid: 3, origin: SITE.origin, url: URL_13579 },
  ]);
  // The daemon closing a sid reaches only its bridge.
  native.deliver({ t: 'close', sid: 3 });
  assert.deepEqual(received(a).at(-1), { t: 'close', sid: 1 });
  assert.equal(received(b).length, 2);
});

test('relay error before open → fallback; after open → close; next open reconnects', () => {
  const env = setup();
  const a = env.connectBridge(SITE);
  a.deliver({ t: 'open', sid: 1, url: URL_13579 });
  a.deliver({ t: 'open', sid: 2, url: URL_13579 });
  const first = env.natives[0];
  first.deliver({ t: 'relay', v: 1, version: '0.1.0' });
  first.deliver({ t: 'hello', v: 1, version: '0.1.0', compat: '1.4' });
  first.deliver({ t: 'open', sid: 1 });
  first.deliver({ t: 'error', code: 'DAEMON_GONE', message: 'daemon exited' });
  assert.ok(first.disconnectedByOwner);
  assert.deepEqual(received(a), [
    { t: 'open', sid: 1 },
    { t: 'close', sid: 1 },
    { t: 'fallback', sid: 2 },
  ]);
  // Late frames of the dead session are ignored.
  first.deliver({ t: 'open', sid: 2 });
  assert.equal(received(a).length, 3);

  // The daemon had answered, so this is not a connection failure: reconnect at once.
  a.deliver({ t: 'open', sid: 3, url: URL_13579 });
  assert.equal(env.natives.length, 2);
  const second = env.natives[1];
  assert.deepEqual(second.posted, [{ t: 'open', sid: 3, origin: SITE.origin, url: URL_13579 }]);
  second.deliver({ t: 'relay', v: 1, version: '0.1.0' });
  second.deliver({ t: 'hello', v: 1, version: '0.1.0', compat: '1.4' });
  second.deliver({ t: 'open', sid: 3 });
  a.deliver({ t: 'open', sid: 4, url: URL_13579 });
  // The browser drops the native port (relay crashed) without an `error` frame.
  second.drop(env.runtime, 'Native host has exited.');
  assert.deepEqual(received(a).slice(3), [
    { t: 'open', sid: 3 },
    { t: 'close', sid: 3 },
    { t: 'fallback', sid: 4 },
  ]);
  a.deliver({ t: 'msg', sid: 3, data: 'to nowhere' });
  assert.equal(second.posted.length, 2);
  a.deliver({ t: 'open', sid: 5, url: URL_13579 });
  assert.equal(env.natives.length, 3);
  assert.equal(env.natives[2].posted[0].sid, 5);
});

test('probe ok on relay frame; negative result cached 2 s', (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  const env = setup();
  const a = env.connectBridge(SITE);

  // The host is not installed: the browser disconnects the port right away.
  a.deliver({ t: 'probe' });
  assert.equal(env.natives.length, 1);
  assert.deepEqual(received(a), []);
  env.natives[0].drop(env.runtime, 'Specified native messaging host not found.');
  assert.deepEqual(received(a), [{ t: 'probe', ok: false }]);

  t.mock.timers.tick(1999);
  a.deliver({ t: 'probe' });
  a.deliver({ t: 'open', sid: 1, url: URL_13579 });
  assert.equal(env.natives.length, 1, 'a failure is remembered for 2 s');
  assert.deepEqual(received(a).slice(1), [
    { t: 'probe', ok: false },
    { t: 'fallback', sid: 1 },
  ]);

  t.mock.timers.tick(1);
  a.deliver({ t: 'probe' });
  a.deliver({ t: 'probe' });
  assert.equal(env.natives.length, 2);
  const native = env.natives[1];
  assert.deepEqual(native.posted, [], 'probes are answered by the background itself');
  native.deliver({ t: 'relay', v: 1, version: '0.1.0' });
  assert.deepEqual(received(a).slice(3), [
    { t: 'probe', ok: true },
    { t: 'probe', ok: true },
  ]);
  a.deliver({ t: 'probe' });
  assert.deepEqual(received(a).at(-1), { t: 'probe', ok: true });

  // The relay starts but cannot reach the daemon: a failure too.
  native.deliver({ t: 'error', code: 'DAEMON_UNAVAILABLE', message: 'no daemon' });
  a.deliver({ t: 'probe' });
  assert.deepEqual(received(a).at(-1), { t: 'probe', ok: false });
  assert.equal(env.natives.length, 2);
});

test('closing one bridge port closes only its sids', () => {
  const env = setup();
  const a = env.connectBridge(SITE);
  const b = env.connectBridge(OTHER);
  a.deliver({ t: 'open', sid: 1, url: URL_13579 });
  a.deliver({ t: 'open', sid: 2, url: URL_13579 });
  b.deliver({ t: 'open', sid: 1, url: URL_13579 });
  b.deliver({ t: 'probe' });
  const native = env.natives[0];
  for (const sid of [1, 2, 3]) native.deliver({ t: 'open', sid });

  a.drop(env.runtime);
  assert.deepEqual(native.posted.slice(3), [
    { t: 'close', sid: 1 },
    { t: 'close', sid: 2 },
  ]);
  native.deliver({ t: 'msg', sid: 1, data: 'for a' });
  native.deliver({ t: 'msg', sid: 3, data: 'for b' });
  assert.deepEqual(received(b), [
    { t: 'open', sid: 1 },
    { t: 'msg', sid: 1, data: 'for b' },
  ]);
  b.drop(env.runtime);
  native.deliver({ t: 'relay', v: 1, version: '0.1.0' });
  assert.deepEqual(native.posted.at(-1), { t: 'close', sid: 3 });
  assert.equal(received(b).length, 2);
});

test('registers the MAIN-world shim at install and startup, once', async () => {
  const env = setup();
  const shim = {
    id: 'oncl-shim',
    js: ['shim.js'],
    matches: ['<all_urls>'],
    runAt: 'document_start',
    allFrames: true,
    world: 'MAIN',
    persistAcrossSessions: true,
  };
  env.runtime.onInstalled.fire({ reason: 'install' });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual([...env.registered.values()], [shim]);
  env.runtime.onStartup.fire();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(
    env.scriptingCalls.map(([call]) => call),
    ['get', 'register', 'get', 'update'],
  );
  assert.deepEqual([...env.registered.values()], [shim]);
});
