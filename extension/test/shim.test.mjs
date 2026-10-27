import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { bridgeEnd, bridgeLink, loadScript, pageWindow, tick, until } from './env.mjs';

const installShim = loadScript('shim.js');
const GREETING = '{"result":{"version":"1.4"}}';

/**
 * Where the shim runs: in the page's own world (Chromium, Firefox 128+), or as a Firefox
 * content script reaching the page through Xray vision (Firefox before 128).
 */
const MODES = [
  { name: 'page world', xray: false },
  { name: 'Firefox Xray', xray: true },
];

/**
 * A page with the shim installed; the fake bridge has answered `ready` unless told not to.
 * The bridge is reached over `document` events, or directly in the content-script global.
 */
function setupPage({ ready = true, xray = false } = {}) {
  const env = pageWindow({ xray });
  const bridge = xray ? bridgeLink(env.sandbox) : bridgeEnd(env.document);
  installShim(env.window, env.sandbox);
  if (ready) bridge.send({ t: 'ready' });
  // From now on the fake bridge, like the real one, answers the shim's `ready` at once.
  bridge.answerReady = true;
  const frames = () => bridge.frames.filter((f) => f.t !== 'ready');
  return { ...env, bridge, frames };
}

/** Records every event of a socket as a compact tuple. */
function record(ws) {
  const events = [];
  ws.addEventListener('open', () => events.push(['open', ws.readyState]));
  ws.addEventListener('message', (e) => events.push(['message', e.data, e.origin]));
  ws.addEventListener('error', () => events.push(['error', ws.readyState]));
  ws.addEventListener('close', (e) => events.push(['close', e.code, e.reason, e.wasClean, ws.readyState]));
  return events;
}

/** A virtual socket the fake bridge has accepted (sid 1 on a fresh page). */
function openSocket(env, url = 'wss://127.0.0.1:13579/') {
  const ws = new env.window.WebSocket(url);
  const sid = env.frames().findLast((f) => f.t === 'open').sid;
  env.bridge.send({ t: 'open', sid });
  return { ws, sid };
}

for (const { name, xray } of MODES) {
  describe(name, () => {
    const setup = (options) => setupPage({ ...options, xray });

    test('non-loopback and out-of-range ports use the native WebSocket', () => {
      const env = setup();
      const { window, nativeSockets } = env;
      const passThrough = [
        'wss://127.0.0.1:13578/',
        'wss://127.0.0.1:13680/',
        'wss://example.com:13579/',
        'ws://10.0.0.1:13579/',
        'wss://127.0.0.1/',
        'https://127.0.0.1:13579/',
        // Longer than the extension carries.
        `wss://127.0.0.1:13579/${'a'.repeat(2048)}`,
      ];
      for (const url of passThrough) {
        const ws = new window.WebSocket(url, ['p']);
        assert.equal(nativeSockets.at(-1), ws, url);
        assert.deepEqual(ws.args, [url, ['p']]);
        assert.ok(ws instanceof window.WebSocket);
      }
      assert.deepEqual(env.frames(), []);

      const virtual = ['wss://127.0.0.1:13579', 'ws://localhost:13679/x?y', 'wss://[::1]:13600/'];
      for (const url of virtual) new window.WebSocket(url);
      assert.equal(nativeSockets.length, passThrough.length);
      assert.deepEqual(
        env.frames().map((f) => f.url),
        ['wss://127.0.0.1:13579/', 'ws://localhost:13679/x?y', 'wss://[::1]:13600/'],
      );
      assert.throws(() => window.WebSocket('wss://127.0.0.1:13579/'), TypeError);
    });

    test('virtual socket: open then greeting message, instanceof WebSocket', () => {
      const env = setup();
      const { window } = env;
      const ws = new window.WebSocket('wss://127.0.0.1:13579');
      assert.ok(ws instanceof window.WebSocket);
      assert.ok(ws instanceof EventTarget);
      assert.equal(ws.constructor, window.WebSocket);
      assert.equal(env.nativeSockets.length, 0);
      assert.equal(ws.url, 'wss://127.0.0.1:13579/');
      assert.equal(ws.readyState, 0);
      assert.equal(ws.protocol, '');
      assert.equal(ws.extensions, '');
      assert.equal(ws.bufferedAmount, 0);
      assert.equal(ws.binaryType, 'blob');
      ws.binaryType = 'arraybuffer';
      assert.equal(ws.binaryType, 'arraybuffer');
      ws.binaryType = 'bogus';
      assert.equal(ws.binaryType, 'arraybuffer');
      for (const [name, value] of [['CONNECTING', 0], ['OPEN', 1], ['CLOSING', 2], ['CLOSED', 3]]) {
        assert.equal(window.WebSocket[name], value);
        assert.equal(ws[name], value);
      }
      assert.deepEqual(env.frames(), [{ t: 'open', sid: 1, url: 'wss://127.0.0.1:13579/' }]);

      const events = record(ws);
      const handled = [];
      ws.onopen = (e) => handled.push(['onopen', e.type, ws.readyState]);
      ws.onmessage = (e) => handled.push(['onmessage', e.data]);
      assert.equal(typeof ws.onopen, 'function');
      env.bridge.send({ t: 'open', sid: 1 });
      env.bridge.send({ t: 'msg', sid: 1, data: GREETING });
      assert.deepEqual(events, [
        ['open', 1],
        ['message', GREETING, 'wss://127.0.0.1:13579'],
      ]);
      assert.deepEqual(handled, [
        ['onopen', 'open', 1],
        ['onmessage', GREETING],
      ]);
      ws.onmessage = null;
      env.bridge.send({ t: 'msg', sid: 1, data: 'again' });
      assert.equal(handled.length, 2);
      assert.equal(events.length, 3);
    });

    test('send while CONNECTING throws InvalidStateError', () => {
      const env = setup();
      const ws = new env.window.WebSocket('wss://127.0.0.1:13579/');
      assert.throws(() => ws.send('x'), { name: 'InvalidStateError' });
      assert.deepEqual(
        env.frames().map((f) => f.t),
        ['open'],
      );
    });

    test('binary send arrives as UTF-8 text in order (Blob then string)', async () => {
      const env = setup();
      const { ws, sid } = openSocket(env);
      const bytes = new TextEncoder().encode('Ж!');
      ws.send(new env.window.Blob(['Сәлем, ']));
      ws.send('мир');
      ws.send(bytes.buffer);
      ws.send(new Uint8Array([0xd0, 0x96, 0xff]).subarray(0, 2));
      ws.send(new DataView(new TextEncoder().encode('ә').buffer));
      ws.send(new env.window.Blob([new Uint8Array([0xff])]));
      const sent = () => env.frames().filter((f) => f.t === 'msg');
      await until(() => sent().length === 6);
      assert.deepEqual(sent(), [
        { t: 'msg', sid, data: 'Сәлем, ' },
        { t: 'msg', sid, data: 'мир' },
        { t: 'msg', sid, data: 'Ж!' },
        { t: 'msg', sid, data: 'Ж' },
        { t: 'msg', sid, data: 'ә' },
        { t: 'msg', sid, data: '\uFFFD' },
      ]);
    });

    test('fallback before open proxies a native socket with the same url and protocols', () => {
      const env = setup();
      const ws = new env.window.WebSocket('ws://localhost:13600', ['a', 'b']);
      const events = record(ws);
      ws.binaryType = 'arraybuffer';
      env.bridge.send({ t: 'fallback', sid: 1 });
      assert.equal(env.nativeSockets.length, 1);
      const native = env.nativeSockets[0];
      assert.deepEqual(native.args, ['ws://localhost:13600', ['a', 'b']]);
      assert.equal(native.binaryType, 'arraybuffer');
      assert.equal(ws.readyState, 0);
      assert.throws(() => ws.send('early'), { name: 'InvalidStateError' });

      native.serverOpen();
      assert.equal(ws.readyState, 1);
      native.serverMessage('{"result":{"version":"fake-original"}}');
      ws.send('hi');
      assert.deepEqual(native.sent, ['hi']);
      // The bridge has forgotten the sid: daemon frames for it no longer reach the socket.
      env.bridge.send({ t: 'msg', sid: 1, data: 'stale' });
      ws.close(4001, 'bye');
      assert.deepEqual(native.closeCalls, [[4001, 'bye']]);
      native.serverClose(4001, 'bye', true);
      assert.equal(ws.readyState, 3);
      assert.deepEqual(events, [
        ['open', 1],
        ['message', '{"result":{"version":"fake-original"}}', 'ws://localhost:13600'],
        ['close', 4001, 'bye', true, 3],
      ]);
      // Only the `open` ever went to the bridge.
      assert.deepEqual(
        env.frames().map((f) => f.t),
        ['open'],
      );

      // Without `protocols` the native constructor gets a single argument.
      new env.window.WebSocket('wss://127.0.0.1:13579/');
      env.bridge.send({ t: 'fallback', sid: 2 });
      assert.deepEqual(env.nativeSockets[1].args, ['wss://127.0.0.1:13579/']);
    });

    test('daemon close → error then close 1006 wasClean=false', () => {
      const env = setup();
      const { ws, sid } = openSocket(env);
      const events = record(ws);
      env.bridge.send({ t: 'close', sid });
      assert.deepEqual(events, [
        ['error', 3],
        ['close', 1006, '', false, 3],
      ]);
      // A reset before the daemon accepted the socket looks the same.
      const pending = new env.window.WebSocket('wss://127.0.0.1:13579/');
      const pendingEvents = record(pending);
      env.bridge.send({ t: 'close', sid: sid + 1 });
      assert.deepEqual(pendingEvents, [
        ['error', 3],
        ['close', 1006, '', false, 3],
      ]);
    });

    test('page close(4000) → close event code 4000 wasClean=true and close frame to bridge', async () => {
      const env = setup();
      const { ws, sid } = openSocket(env);
      const events = record(ws);
      assert.throws(() => ws.close(1001), { name: 'InvalidAccessError' });
      assert.throws(() => ws.close(4000, 'я'.repeat(62)), { name: 'SyntaxError' });
      ws.close(4000, 'done');
      assert.equal(ws.readyState, 2);
      assert.deepEqual(env.frames().at(-1), { t: 'close', sid });
      ws.send('ignored after close');
      ws.close(4000, 'again');
      await tick();
      assert.equal(ws.readyState, 3);
      assert.deepEqual(events, [['close', 4000, 'done', true, 3]]);
      assert.equal(env.frames().filter((f) => f.t === 'close').length, 1);

      const second = openSocket(env);
      const secondEvents = record(second.ws);
      second.ws.close();
      await tick();
      assert.deepEqual(secondEvents, [['close', 1000, '', true, 3]]);

      // Closing before the daemon accepted fails the connection, like the browser does.
      const pending = new env.window.WebSocket('wss://127.0.0.1:13579/');
      const pendingEvents = record(pending);
      pending.close();
      await tick();
      assert.deepEqual(pendingEvents, [
        ['error', 3],
        ['close', 1006, '', false, 3],
      ]);
      assert.deepEqual(env.frames().at(-1), { t: 'close', sid: second.sid + 1 });
    });

    test('fetch probe resolves 200 when probe ok, calls native fetch otherwise, honours abort', async () => {
      const env = setup();
      const { window } = env;
      const probes = () => env.frames().filter((f) => f.t === 'probe');

      const ok = window.fetch('https://127.0.0.1:13579/', { mode: 'no-cors' });
      assert.deepEqual(probes(), [{ t: 'probe' }]);
      env.bridge.send({ t: 'probe', ok: true });
      const response = await ok;
      assert.ok(response instanceof Response);
      assert.equal(response.status, 200);
      assert.equal(await response.text(), '');
      assert.equal(env.fetchCalls.length, 0);

      const init = { mode: 'no-cors' };
      const refused = window.fetch('http://localhost:13579/x', init);
      env.bridge.send({ t: 'probe', ok: false });
      assert.equal(await refused, 'native fetch response');
      assert.deepEqual(env.fetchCalls, [['http://localhost:13579/x', init]]);

      assert.equal(await window.fetch('https://example.com/'), 'native fetch response');
      assert.equal(await window.fetch('https://127.0.0.1:13680/'), 'native fetch response');
      assert.equal(probes().length, 2);

      const controller = new AbortController();
      const aborted = window.fetch('https://127.0.0.1:13579/', { signal: controller.signal });
      controller.abort();
      await assert.rejects(aborted, { name: 'AbortError' });
      // A refusal arriving after the abort must not start the page's own fetch.
      env.bridge.send({ t: 'probe', ok: false });
      await tick();
      await assert.rejects(window.fetch('https://127.0.0.1:13579/', { signal: AbortSignal.abort() }), {
        name: 'AbortError',
      });
      const fromRequest = window.fetch(new Request('https://[::1]:13600/', { signal: AbortSignal.abort() }));
      await assert.rejects(fromRequest, { name: 'AbortError' });
      assert.equal(env.fetchCalls.length, 3);
    });

    test('shim buffers frames until bridge ready', async () => {
      const env = setup({ ready: false });
      // The shim announces itself, so a bridge that started first can answer.
      assert.deepEqual(env.bridge.frames, [{ t: 'ready' }]);
      const ws = new env.window.WebSocket('wss://127.0.0.1:13579/');
      const probe = env.window.fetch('https://127.0.0.1:13579/');
      assert.deepEqual(env.frames(), []);
      env.bridge.send({ t: 'ready' });
      assert.deepEqual(env.frames(), [{ t: 'open', sid: 1, url: 'wss://127.0.0.1:13579/' }, { t: 'probe' }]);
      env.bridge.send({ t: 'ready' });
      assert.equal(env.frames().length, 2);
      env.bridge.send({ t: 'probe', ok: true });
      assert.equal((await probe).status, 200);
      assert.equal(ws.readyState, 0);
    });

    test('WebSocket and fetch keep the names, lengths and prototype of the originals', () => {
      const env = setup();
      const { window } = env;
      assert.equal(window.WebSocket.name, 'WebSocket');
      assert.equal(window.WebSocket.length, 1);
      assert.equal(window.fetch.name, 'fetch');
      assert.equal(window.fetch.length, 1);
      // Writable, as for any script function (the page's own is read-only).
      assert.deepEqual(Object.getOwnPropertyDescriptor(window.WebSocket, 'prototype'), {
        value: env.NativeWebSocket.prototype,
        writable: true,
        enumerable: false,
        configurable: false,
      });
      assert.equal(Object.getPrototypeOf(window.WebSocket), Object.getPrototypeOf(env.NativeWebSocket));
      const ws = new window.WebSocket('wss://127.0.0.1:13579/');
      const members = Object.getPrototypeOf(ws);
      assert.equal(Object.getPrototypeOf(members), env.NativeWebSocket.prototype);
      assert.deepEqual(Object.keys(members).sort(), [
        'binaryType',
        'bufferedAmount',
        'close',
        'extensions',
        'onclose',
        'onerror',
        'onmessage',
        'onopen',
        'protocol',
        'readyState',
        'send',
        'url',
      ]);
      assert.equal(members.send.length, 1);
      assert.equal(members.close.length, 0);
      // Members called on something else fail like the browser's.
      assert.throws(() => members.send.call({}, 'x'), TypeError);
      assert.throws(() => Object.getOwnPropertyDescriptor(members, 'url').get.call(env.window), TypeError);
    });

    test('a page Blob.text that returns no promise skips that message only', async () => {
      const env = setup();
      const { ws, sid } = openSocket(env);
      const blob = new env.window.Blob(['skipped']);
      blob.text = () => 'not a promise';
      ws.send(blob);
      ws.send('after');
      await until(() => env.frames().some((f) => f.data === 'after'));
      assert.deepEqual(
        env.frames().filter((f) => f.t === 'msg'),
        [{ t: 'msg', sid, data: 'after' }],
      );
    });

    test("a bridge that stops answering hands everything to the page's own WebSocket and fetch", async () => {
      const env = setup();
      const { ws: accepted } = openSocket(env);
      const acceptedEvents = record(accepted);
      const pending = new env.window.WebSocket('ws://localhost:13600', ['p']);
      const probe = env.window.fetch('https://127.0.0.1:13579/');
      assert.deepEqual(
        env.frames().map((f) => f.t),
        ['open', 'open', 'probe'],
      );

      // The extension went away; the page notices on its next NCALayer socket.
      env.bridge.answerReady = false;
      const later = new env.window.WebSocket('wss://127.0.0.1:13579/');
      assert.deepEqual(
        env.nativeSockets.map((s) => s.args),
        [['ws://localhost:13600', ['p']], ['wss://127.0.0.1:13579/']],
      );
      assert.equal(env.nativeSockets[1], later);
      env.nativeSockets[0].serverOpen();
      assert.equal(pending.readyState, 1);
      assert.deepEqual(acceptedEvents, [
        ['error', 3],
        ['close', 1006, '', false, 3],
      ]);
      assert.equal(await probe, 'native fetch response');
      const direct = env.window.fetch('https://127.0.0.1:13579/');
      // Straight to the page's own fetch, without asking the extension.
      assert.equal(env.fetchCalls.length, 2);
      assert.equal(await direct, 'native fetch response');
      // Nothing more went to the bridge but the checks.
      assert.equal(env.frames().length, 3);
    });

    test('a socket the page closes while the bridge is found gone gets one close event', async () => {
      const env = setup();
      const { ws: first } = openSocket(env);
      const { ws: second } = openSocket(env);
      const secondEvents = record(second);
      // The page reacts to the first reset by closing the second socket.
      first.addEventListener('error', () => second.close());
      env.bridge.answerReady = false;
      new env.window.WebSocket('wss://127.0.0.1:13579/');
      await tick();
      assert.deepEqual(secondEvents, [['close', 1000, '', true, 3]]);
    });

    test('an open socket that sends after the bridge went away is reset, not left hanging', () => {
      const env = setup();
      const { ws } = openSocket(env);
      const events = record(ws);
      env.bridge.answerReady = false;
      ws.send('lost');
      assert.deepEqual(events, [
        ['error', 3],
        ['close', 1006, '', false, 3],
      ]);
      assert.equal(env.frames().filter((f) => f.t === 'msg').length, 0);
    });
  });
}

test('Firefox Xray: the page gets exported functions only, the bridge direct calls only', () => {
  const env = pageWindow({ xray: true });
  const { window, sandbox } = env;
  // What the page could see or forge on `document`.
  const events = bridgeEnd(env.document);
  const bridge = bridgeLink(sandbox);
  installShim(window, sandbox);
  assert.deepEqual(bridge.frames, [{ t: 'ready' }]);
  bridge.send({ t: 'ready' });
  bridge.answerReady = true;

  assert.ok(sandbox.exported.has(window.WebSocket));
  assert.ok(sandbox.exported.has(window.fetch));
  const ws = new window.WebSocket('wss://127.0.0.1:13579/');
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(Object.getPrototypeOf(ws)))) {
    for (const fn of [descriptor.get, descriptor.set, descriptor.value]) {
      if (typeof fn === 'function') assert.ok(sandbox.exported.has(fn), key);
    }
  }
  assert.deepEqual(bridge.frames.at(-1), { t: 'open', sid: 1, url: 'wss://127.0.0.1:13579/' });

  // Frames forged on `document` reach neither side.
  events.send({ t: 'open', sid: 1 });
  assert.equal(ws.readyState, 0);
  bridge.send({ t: 'open', sid: 1 });
  assert.equal(ws.readyState, 1);
  ws.send('hello');
  assert.deepEqual(bridge.frames.at(-1), { t: 'msg', sid: 1, data: 'hello' });
  assert.deepEqual(events.frames, []);

  // Listeners the shim adds to page objects are exported too, their options cloned.
  ws.onmessage = () => {};
  assert.ok(sandbox.exported.has(env.socketListeners.at(-1)[1]), 'on<type> listener');
  const signal = new AbortController().signal;
  const added = [];
  signal.addEventListener = (type, listener, options) => added.push([type, listener, options]);
  window.fetch('https://127.0.0.1:13579/', { signal });
  assert.equal(added.length, 1);
  assert.ok(sandbox.exported.has(added[0][1]), 'abort listener');
  assert.ok(sandbox.cloned.has(added[0][2]), 'abort listener options');
});
