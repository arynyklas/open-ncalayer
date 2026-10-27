// OpenNCALayer bridge (ISOLATED world content script, document_start, every frame).
//
// Relays bridge protocol frames between the page shim and the background
// (`runtime.connect({name: "oncl"})`, one port per frame, opened on first use). The shim is
// reached by `CustomEvent`s on `document` with JSON strings in `detail` when it runs in the
// page's own world, or by plain calls when it runs in this same content-script global
// (Firefox before 128); then page events are not listened to at all. Sids on this port are
// the shim's local ones; the background maps them to the daemon's. Outgoing messages are cut
// into pieces of at most 8 MiB (UTF-16 code units) so every native frame stays under the
// daemon's frame limit; incoming pieces are joined back into whole messages.
(function () {
  'use strict';

  const TO_EXT = '__oncl_to_ext';
  const TO_PAGE = '__oncl_to_page';
  const PORT_NAME = 'oncl';
  // The property of the content-script global where the shim and the bridge meet (Xray).
  const LINK = '__oncl_link';

  // <oncl-common> Kept identical in shim.js, bridge.js and background.js (test/common.test.mjs).
  const LOOPBACK = ['127.0.0.1', 'localhost', '[::1]'];
  const FIRST_PORT = 13579;
  const LAST_PORT = 13679;
  // Longest socket URL the extension carries; longer ones stay with the page's own WebSocket.
  const MAX_URL_LENGTH = 2048;
  // Largest `msg` piece towards the daemon (UTF-16 code units): the bridge cuts, the background checks.
  const PIECE = 8 * 1024 * 1024;
  const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

  /** A socket id: a positive safe integer. */
  const isSid = (value) => Number.isSafeInteger(value) && value > 0;

  /**
   * `text` with lone surrogates replaced by U+FFFD, as a browser's WebSocket sends it. The
   * daemon cannot parse JSON with lone surrogates and drops the whole connection on them.
   */
  function wellFormed(text) {
    return typeof text.toWellFormed === 'function' ? text.toWellFormed() : text.replace(LONE_SURROGATE, '\uFFFD');
  }

  /** `url` (a parsed `URL`) is an NCALayer endpoint with one of `schemes`. */
  function isNcaLayer(url, schemes) {
    if (!schemes.includes(url.protocol) || !LOOPBACK.includes(url.hostname)) return false;
    const port = Number(url.port);
    return port >= FIRST_PORT && port <= LAST_PORT;
  }

  /**
   * The normalized `href` of an NCALayer WebSocket URL of at most `MAX_URL_LENGTH` code units;
   * `null` for anything else (not a string, too long, lone surrogates, another endpoint).
   */
  function socketUrl(text) {
    if (typeof text !== 'string' || text.length > MAX_URL_LENGTH || wellFormed(text) !== text) return null;
    let url;
    try {
      url = new URL(text);
    } catch {
      return null;
    }
    return url.href.length <= MAX_URL_LENGTH && isNcaLayer(url, ['ws:', 'wss:']) ? url.href : null;
  }
  // </oncl-common>

  /** Cuts well-formed `text` into pieces of at most `PIECE` code units, never inside a pair. */
  function split(text) {
    const pieces = [];
    let start = 0;
    while (text.length - start > PIECE) {
      let end = start + PIECE;
      const last = text.charCodeAt(end - 1);
      if (last >= 0xd800 && last <= 0xdbff) end -= 1;
      pieces.push(text.slice(start, end));
      start = end;
    }
    pieces.push(text.slice(start));
    return pieces;
  }

  /** The meeting point of shim and bridge in the content-script global `sandbox`. */
  function linkChannel(sandbox) {
    if (!Object.prototype.hasOwnProperty.call(sandbox, LINK)) {
      Object.defineProperty(sandbox, LINK, { value: { toExt: null, toPage: null } });
    }
    return sandbox[LINK];
  }

  /**
   * Relays between the shim of the page `win` and the background over `runtime`. `sandbox`:
   * this content script's global, where a shim running next to the bridge links up.
   */
  function installBridge(win, runtime, sandbox) {
    const doc = win.document;
    let port = null;
    const sockets = new Map(); // sid → pieces of the message being received
    let pendingProbes = 0;

    // --- Link to the shim -----------------------------------------------------------------
    const channel = linkChannel(sandbox);
    let direct = false;

    function toPage(frame) {
      if (direct) channel.toPage(frame);
      else doc.dispatchEvent(new win.CustomEvent(TO_PAGE, { detail: JSON.stringify(frame) }));
    }

    function fromEvent(event) {
      if (typeof event.detail !== 'string') return;
      let frame;
      try {
        frame = JSON.parse(event.detail);
      } catch {
        return;
      }
      if (frame !== null && typeof frame === 'object') fromPage(frame);
    }

    /** The shim runs in this global: plain calls from now on, page events are ignored. */
    function goDirect() {
      if (direct) return;
      direct = true;
      doc.removeEventListener(TO_EXT, fromEvent);
    }

    /** The port to the background, connecting if needed; `null` if the extension is gone. */
    function connect() {
      if (port) return port;
      try {
        port = runtime.connect({ name: PORT_NAME });
      } catch {
        // The extension was reloaded or removed while the page stayed open.
        return null;
      }
      const current = port;
      current.onMessage.addListener((frame) => {
        if (port === current) fromBackground(frame);
      });
      current.onDisconnect.addListener(() => {
        void runtime.lastError; // read, so it is not reported as unchecked
        if (port === current) lost();
      });
      return port;
    }

    /** The background went away: every socket of this frame is reset. */
    function lost() {
      port = null;
      const sids = [...sockets.keys()];
      sockets.clear();
      // Snapshot first: page handlers run inside `toPage` and may probe on a new port.
      const refused = pendingProbes;
      pendingProbes = 0;
      for (const sid of sids) toPage({ t: 'close', sid });
      for (let i = 0; i < refused; i++) toPage({ t: 'probe', ok: false });
    }

    function toBackground(frame) {
      try {
        port.postMessage(frame);
      } catch {
        lost();
      }
    }

    function fromPage(frame) {
      switch (frame.t) {
        case 'ready':
          // The shim started after our own `ready`: answer its announcement.
          toPage({ t: 'ready' });
          break;
        case 'open': {
          if (!isSid(frame.sid)) return;
          const url = socketUrl(frame.url);
          if (url === null) {
            // Only a page forging frames gets here (the shim sends valid URLs only). Nothing
            // goes to the daemon: the socket is reset, as if the connection failed.
            if (sockets.delete(frame.sid)) toBackground({ t: 'close', sid: frame.sid });
            toPage({ t: 'close', sid: frame.sid });
            return;
          }
          if (!connect()) {
            toPage({ t: 'fallback', sid: frame.sid });
            return;
          }
          sockets.set(frame.sid, []);
          toBackground({ t: 'open', sid: frame.sid, url });
          break;
        }
        case 'msg': {
          if (!sockets.has(frame.sid) || typeof frame.data !== 'string') return;
          const pieces = split(wellFormed(frame.data));
          pieces.forEach((data, i) => {
            if (port) toBackground(i < pieces.length - 1 ? { t: 'msg', sid: frame.sid, data, more: true } : { t: 'msg', sid: frame.sid, data });
          });
          break;
        }
        case 'close':
          if (sockets.delete(frame.sid)) toBackground({ t: 'close', sid: frame.sid });
          break;
        case 'probe':
          if (!connect()) {
            toPage({ t: 'probe', ok: false });
            return;
          }
          pendingProbes++;
          toBackground({ t: 'probe' });
          break;
      }
    }

    function fromBackground(frame) {
      if (frame === null || typeof frame !== 'object') return;
      switch (frame.t) {
        case 'open':
          if (sockets.has(frame.sid)) toPage({ t: 'open', sid: frame.sid });
          break;
        case 'msg': {
          const pieces = sockets.get(frame.sid);
          if (!pieces || typeof frame.data !== 'string') return;
          pieces.push(frame.data);
          if (frame.more === true) return;
          sockets.set(frame.sid, []);
          toPage({ t: 'msg', sid: frame.sid, data: pieces.join('') });
          break;
        }
        case 'close':
        case 'fallback':
          // Unfinished pieces of a message are dropped with the socket.
          if (sockets.delete(frame.sid)) toPage({ t: frame.t, sid: frame.sid });
          break;
        case 'probe':
          if (pendingProbes === 0) return;
          pendingProbes--;
          toPage({ t: 'probe', ok: frame.ok === true });
          break;
      }
    }

    channel.toExt = (frame) => {
      goDirect();
      if (frame !== null && typeof frame === 'object') fromPage(frame);
    };
    if (channel.toPage) goDirect();
    else doc.addEventListener(TO_EXT, fromEvent);
    toPage({ t: 'ready' });
  }

  if (typeof module === 'object' && module !== null) module.exports = installBridge;
  else installBridge(window, chrome.runtime, globalThis);
})();
