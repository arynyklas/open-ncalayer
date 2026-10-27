import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { contentWindow, loadScript, pageEnd, pageLink, pageWindow, until, withoutToWellFormed } from './env.mjs';

const installBridge = loadScript('bridge.js');
const installShim = loadScript('shim.js');
const PIECE = 8 * 1024 * 1024;
const URL_13579 = 'wss://127.0.0.1:13579/';

/**
 * Where the shim runs: in the page's own world, reached over `document` events, or in the
 * bridge's own content-script global (Firefox before 128), reached directly.
 */
const MODES = [
  { name: 'shim in the page world', direct: false },
  { name: 'shim in the content script', direct: true },
];

/** A bridge and the fake shim it talks to; Firefox runs the shim's content script first. */
function setupBridge({ direct }) {
  const env = contentWindow();
  const sandbox = {};
  const page = direct ? pageLink(sandbox) : pageEnd(env.document);
  installBridge(env.window, env.runtime, sandbox);
  return { ...env, page, sandbox };
}

/** The real shim and bridge on one document, as in a real page. */
function setupShimAndBridge({ direct }) {
  const document = new EventTarget();
  const pageSide = pageWindow({ document, xray: direct });
  const env = contentWindow({ document });
  installShim(pageSide.window, pageSide.sandbox);
  installBridge(env.window, env.runtime, direct ? pageSide.sandbox : {});
  return { pageSide, env };
}

/** Opens `sid` from the page; returns the port the bridge opened to the background. */
function open(env, sid) {
  env.page.send({ t: 'open', sid, url: URL_13579, origin: 'https://evil.example' });
  return env.ports.at(-1);
}

/** `open` frames a page could forge; none may reach the background. */
const BAD_URLS = [
  ['lone surrogate', `${URL_13579}\uD800`],
  ['oversized', `${URL_13579}${'a'.repeat(4096)}`],
  ['non-loopback', 'wss://example.com:13579/'],
  ['port out of range', 'wss://127.0.0.1:13680/'],
  ['not a WebSocket URL', 'https://127.0.0.1:13579/'],
  ['not a string', 42],
  ['missing', undefined],
];

for (const mode of MODES) {
  describe(mode.name, () => {
    const setup = () => setupBridge(mode);
    const shimAndBridge = () => setupShimAndBridge(mode);

    test('bridge announces ready, answers the shim handshake and connects lazily', () => {
      const env = setup();
      assert.deepEqual(env.page.frames, [{ t: 'ready' }]);
      assert.equal(env.ports.length, 0);
      env.page.send({ t: 'ready' });
      assert.deepEqual(env.page.frames, [{ t: 'ready' }, { t: 'ready' }]);
      const port = open(env, 1);
      assert.equal(port.name, 'oncl');
      // The page-supplied origin is never forwarded.
      assert.deepEqual(port.posted, [{ t: 'open', sid: 1, url: URL_13579 }]);
      open(env, 2);
      assert.equal(env.ports.length, 1);
      // Malformed frames from the page are ignored.
      env.page.send({ t: 'open', sid: 0, url: URL_13579 });
      env.page.send({ t: 'open', sid: 3 });
      env.page.send({ t: 'msg', sid: 1, data: 5 });
      env.page.send({ t: 'nope', sid: 1 });
      env.document.dispatchEvent(new CustomEvent('__oncl_to_ext', { detail: '{not json' }));
      assert.equal(port.posted.length, 2);
    });

    test('bridge reassembles more-chunks with Cyrillic split points into one message', () => {
      const env = setup();
      const port = open(env, 1);
      port.deliver({ t: 'open', sid: 1 });
      const message = '{"result":"Қазақстан Республикасы 🇰🇿 — Электрондық қолтаңба"}';
      const cuts = [3, 14, 15, 27, 33];
      let start = 0;
      for (const cut of cuts) {
        port.deliver({ t: 'msg', sid: 1, data: message.slice(start, cut), more: true });
        start = cut;
      }
      port.deliver({ t: 'msg', sid: 1, data: message.slice(start) });
      port.deliver({ t: 'msg', sid: 1, data: 'next' });
      assert.deepEqual(env.page.frames.slice(1), [
        { t: 'open', sid: 1 },
        { t: 'msg', sid: 1, data: message },
        { t: 'msg', sid: 1, data: 'next' },
      ]);

      // A daemon close mid-message discards the unfinished part.
      open(env, 2);
      port.deliver({ t: 'open', sid: 2 });
      port.deliver({ t: 'msg', sid: 2, data: 'partial', more: true });
      port.deliver({ t: 'close', sid: 2 });
      port.deliver({ t: 'msg', sid: 2, data: 'late' });
      assert.deepEqual(env.page.frames.slice(4), [
        { t: 'open', sid: 2 },
        { t: 'close', sid: 2 },
      ]);
    });

    test('bridge splits a 20 MiB send into ≤ 8 MiB pieces', () => {
      const env = setup();
      const port = open(env, 1);
      const data = 'Ж'.repeat(20 * 1024 * 1024);
      env.page.send({ t: 'msg', sid: 1, data });
      const pieces = port.posted.slice(1);
      assert.equal(pieces.length, 3);
      for (const [i, piece] of pieces.entries()) {
        assert.equal(piece.t, 'msg');
        assert.equal(piece.sid, 1);
        assert.ok(piece.data.length <= PIECE);
        assert.equal(piece.more, i < pieces.length - 1 ? true : undefined);
        assert.equal('more' in piece, i < pieces.length - 1);
      }
      assert.equal(pieces.map((p) => p.data).join(''), data);

      env.page.send({ t: 'msg', sid: 1, data: '' });
      assert.deepEqual(port.posted.at(-1), { t: 'msg', sid: 1, data: '' });
    });

    test('bridge keeps surrogate pairs whole and replaces lone surrogates', () => {
      const env = setup();
      const port = open(env, 1);
      const data = 'a'.repeat(PIECE - 1) + '😀' + 'b';
      env.page.send({ t: 'msg', sid: 1, data });
      const pieces = port.posted.slice(1).map((p) => p.data);
      assert.deepEqual(
        pieces.map((p) => p.length),
        [PIECE - 1, 3],
      );
      assert.equal(pieces.join(''), data);

      env.page.send({ t: 'msg', sid: 1, data: 'x\uD800y\uDC00z\uDBFF' });
      assert.deepEqual(port.posted.at(-1), { t: 'msg', sid: 1, data: 'x\uFFFDy\uFFFDz\uFFFD' });
    });

    test('bridge port loss closes all page sockets with 1006', () => {
      const { pageSide, env } = shimAndBridge();

      const events = [];
      const sockets = [0, 1].map((i) => {
        const ws = new pageSide.window.WebSocket(URL_13579);
        ws.addEventListener('error', () => events.push([i, 'error']));
        ws.addEventListener('close', (e) => events.push([i, 'close', e.code, e.wasClean]));
        return ws;
      });
      const port = env.ports[0];
      port.deliver({ t: 'open', sid: 1 });
      assert.equal(sockets[0].readyState, 1);
      const probe = pageSide.window.fetch('https://127.0.0.1:13579/');

      port.drop(env.runtime, 'The message port closed before a response was received.');
      assert.deepEqual(events, [
        [0, 'error'],
        [0, 'close', 1006, false],
        [1, 'error'],
        [1, 'close', 1006, false],
      ]);
      return probe.then((result) => {
        // The probe was refused, so the page's own fetch ran.
        assert.equal(result, 'native fetch response');

        // The next socket reconnects; if the extension is gone it falls back to the native one.
        new pageSide.window.WebSocket(URL_13579);
        assert.equal(env.ports.length, 2);
        assert.deepEqual(env.ports[1].posted, [{ t: 'open', sid: 3, url: URL_13579 }]);
        env.runtime.failConnect = true;
        env.ports[1].drop();
        new pageSide.window.WebSocket(URL_13579, ['p']);
        assert.equal(env.ports.length, 2);
        assert.deepEqual(pageSide.nativeSockets.at(-1).args, [URL_13579, ['p']]);
      });
    });

    test('bridge closes forged opens with bad URLs and keeps other sockets working', () => {
      const env = setup();
      const port = open(env, 1);
      port.deliver({ t: 'open', sid: 1 });
      BAD_URLS.forEach(([, url], i) => env.page.send({ t: 'open', sid: 10 + i, url }));
      assert.deepEqual(
        env.page.frames.slice(2),
        BAD_URLS.map((_, i) => ({ t: 'close', sid: 10 + i })),
      );
      env.page.send({ t: 'msg', sid: 10, data: 'to a rejected sid' });
      assert.deepEqual(port.posted, [{ t: 'open', sid: 1, url: URL_13579 }]);

      // The accepted socket and the port are untouched.
      env.page.send({ t: 'msg', sid: 1, data: 'still here' });
      port.deliver({ t: 'msg', sid: 1, data: 'reply' });
      assert.deepEqual(port.posted.at(-1), { t: 'msg', sid: 1, data: 'still here' });
      assert.deepEqual(env.page.frames.at(-1), { t: 'msg', sid: 1, data: 'reply' });
      assert.equal(env.ports.length, 1);

      // A valid URL is forwarded in normalized form.
      env.page.send({ t: 'open', sid: 2, url: 'WSS://LOCALHOST:13600' });
      assert.deepEqual(port.posted.at(-1), { t: 'open', sid: 2, url: 'wss://localhost:13600/' });
      // Reusing a live sid with a bad URL closes that socket at the background too.
      env.page.send({ t: 'open', sid: 2, url: 'wss://evil.example:13579/' });
      assert.deepEqual(port.posted.at(-1), { t: 'close', sid: 2 });
      assert.deepEqual(env.page.frames.at(-1), { t: 'close', sid: 2 });
    });

    test('bridge without String.prototype.toWellFormed (Chrome 109–110)', () => {
      withoutToWellFormed(() => {
        assert.equal(''.toWellFormed, undefined);
        const env = setup();
        const port = open(env, 1);
        env.page.send({ t: 'msg', sid: 1, data: 'x\uD800y\uDC00z😀\uDBFF' });
        assert.deepEqual(port.posted.at(-1), { t: 'msg', sid: 1, data: 'x\uFFFDy\uFFFDz😀\uFFFD' });
        env.page.send({ t: 'open', sid: 2, url: `${URL_13579}\uDC00` });
        assert.deepEqual(env.page.frames.at(-1), { t: 'close', sid: 2 });
        assert.equal(port.posted.length, 2);
      });
    });

    test('a probe made by a close handler during port loss gets the new port answer', { timeout: 5000 }, async () => {
      const { pageSide, env } = shimAndBridge();

      const ws = new pageSide.window.WebSocket(URL_13579);
      env.ports[0].deliver({ t: 'open', sid: 1 });
      const stale = pageSide.window.fetch('https://127.0.0.1:13579/');
      let retry;
      ws.onclose = () => {
        retry = pageSide.window.fetch('https://127.0.0.1:13579/');
      };
      env.ports[0].drop(env.runtime);
      assert.equal(await stale, 'native fetch response');
      assert.equal(env.ports.length, 2);
      await until(() => env.ports[1].posted.length === 1);
      assert.deepEqual(env.ports[1].posted, [{ t: 'probe' }]);
      env.ports[1].deliver({ t: 'probe', ok: true });
      assert.equal((await retry).status, 200);
      assert.equal(pageSide.fetchCalls.length, 1);
    });
  });
}

test('shim in the content script: page events reach neither side', () => {
  const env = contentWindow();
  const sandbox = {};
  // What a page could see or forge on `document`.
  const events = pageEnd(env.document);
  const page = pageLink(sandbox);
  installBridge(env.window, env.runtime, sandbox);
  assert.deepEqual(page.frames, [{ t: 'ready' }]);
  events.send({ t: 'ready' });
  events.send({ t: 'open', sid: 1, url: URL_13579 });
  events.send({ t: 'probe' });
  assert.equal(env.ports.length, 0);
  assert.deepEqual(events.frames, []);
  assert.deepEqual(page.frames, [{ t: 'ready' }]);

  page.send({ t: 'open', sid: 1, url: URL_13579 });
  assert.deepEqual(env.ports[0].posted, [{ t: 'open', sid: 1, url: URL_13579 }]);
  env.ports[0].deliver({ t: 'open', sid: 1 });
  assert.deepEqual(page.frames.at(-1), { t: 'open', sid: 1 });
  assert.deepEqual(events.frames, []);
});

test('a shim that links up after the bridge started turns the page events off', () => {
  const env = contentWindow();
  const sandbox = {};
  const events = pageEnd(env.document);
  installBridge(env.window, env.runtime, sandbox);
  // No shim in this global yet: the bridge serves the page world.
  assert.deepEqual(events.frames, [{ t: 'ready' }]);

  const page = pageLink(sandbox);
  page.send({ t: 'ready' });
  assert.deepEqual(page.frames, [{ t: 'ready' }]);
  events.send({ t: 'open', sid: 1, url: URL_13579 });
  assert.equal(env.ports.length, 0);
  page.send({ t: 'open', sid: 2, url: URL_13579 });
  assert.deepEqual(env.ports[0].posted, [{ t: 'open', sid: 2, url: URL_13579 }]);
  assert.deepEqual(events.frames, [{ t: 'ready' }]);
});

test('shim in the content script: a throw in the shim does not stop the bridge', () => {
  const env = contentWindow();
  const sandbox = {};
  const page = pageLink(sandbox);
  installBridge(env.window, env.runtime, sandbox);
  const channel = sandbox.__oncl_link;
  const receive = channel.toPage;
  // E.g. page code the shim calls throws while it handles a close.
  channel.toPage = (frame) => {
    receive(frame);
    if (frame.t === 'close') throw new Error('page code threw');
  };
  page.send({ t: 'open', sid: 1, url: URL_13579 });
  page.send({ t: 'open', sid: 2, url: URL_13579 });
  page.send({ t: 'probe' });
  env.ports[0].drop(env.runtime);
  assert.deepEqual(page.frames.slice(1), [
    { t: 'close', sid: 1 },
    { t: 'close', sid: 2 },
    { t: 'probe', ok: false },
  ]);
});
