// OpenNCALayer bridge (ISOLATED world content script, document_start, every frame).
//
// Relays bridge protocol frames between the page shim (`CustomEvent`s on `document`, JSON
// strings in `detail`) and the background (`runtime.connect({name: "oncl"})`, one port per
// frame, opened on first use). Sids on this port are the shim's local ones; the background
// maps them to the daemon's. Outgoing messages are cut into pieces of at most 8 MiB (UTF-16
// code units) so every native frame stays under the daemon's frame limit; incoming pieces are
// joined back into whole messages.
(function () {
  'use strict';

  const TO_EXT = '__oncl_to_ext';
  const TO_PAGE = '__oncl_to_page';
  const PORT_NAME = 'oncl';
  const PIECE = 8 * 1024 * 1024;
  const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

  const isSid = (value) => Number.isSafeInteger(value) && value > 0;

  /**
   * `text` with lone surrogates replaced by U+FFFD, as a browser's WebSocket sends it. The
   * daemon cannot parse JSON with lone surrogates and drops the whole connection on them.
   */
  function wellFormed(text) {
    return typeof text.toWellFormed === 'function' ? text.toWellFormed() : text.replace(LONE_SURROGATE, '\uFFFD');
  }

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

  function installBridge(win, runtime) {
    const doc = win.document;
    let port = null;
    const sockets = new Map(); // sid → pieces of the message being received
    let pendingProbes = 0;

    function toPage(frame) {
      doc.dispatchEvent(new win.CustomEvent(TO_PAGE, { detail: JSON.stringify(frame) }));
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
      for (const sid of sids) toPage({ t: 'close', sid });
      for (; pendingProbes > 0; pendingProbes--) toPage({ t: 'probe', ok: false });
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
          if (!isSid(frame.sid) || typeof frame.url !== 'string') return;
          if (!connect()) {
            toPage({ t: 'fallback', sid: frame.sid });
            return;
          }
          sockets.set(frame.sid, []);
          toBackground({ t: 'open', sid: frame.sid, url: frame.url });
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

    doc.addEventListener(TO_EXT, (event) => {
      if (typeof event.detail !== 'string') return;
      let frame;
      try {
        frame = JSON.parse(event.detail);
      } catch {
        return;
      }
      if (frame !== null && typeof frame === 'object') fromPage(frame);
    });
    toPage({ t: 'ready' });
  }

  if (typeof module === 'object' && module !== null) module.exports = installBridge;
  else installBridge(window, chrome.runtime);
})();
