import assert from 'node:assert/strict';
import test from 'node:test';

import { contentWindow, loadScript, pageEnd, pageWindow } from './env.mjs';

const installBridge = loadScript('bridge.js');
const installShim = loadScript('shim.js');
const PIECE = 8 * 1024 * 1024;
const URL_13579 = 'wss://127.0.0.1:13579/';

function setup() {
  const env = contentWindow();
  const page = pageEnd(env.document);
  installBridge(env.window, env.runtime);
  return { ...env, page };
}

/** Opens `sid` from the page; returns the port the bridge opened to the background. */
function open(env, sid) {
  env.page.send({ t: 'open', sid, url: URL_13579, origin: 'https://evil.example' });
  return env.ports.at(-1);
}

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
  // Shim and bridge share one document, as in a real page.
  const document = new EventTarget();
  const pageSide = pageWindow({ document });
  const env = contentWindow({ document });
  installShim(pageSide.window);
  installBridge(env.window, env.runtime);

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
