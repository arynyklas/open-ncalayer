// OpenNCALayer background (Chromium MV3 service worker, Firefox MV2 background page).
//
// Owns one native messaging port to the relay (`nmhost`), opened on first need and shared by
// every bridge. Maps each bridge's local sids to global sids (1, 2, … per native session, never
// reused while live) and stamps `open` with the origin the browser reports for the bridge's
// frame; the page never chooses it. A tab holds at most `MAX_TAB_SOCKETS` live sockets.
// When the relay or the daemon is unavailable, sockets the daemon has not accepted yet get
// `fallback` (the page's own WebSocket takes over) and accepted ones get `close`.
if (typeof importScripts === 'function') importScripts('host.js');

(function () {
  'use strict';

  const PORT_NAME = 'oncl';
  // How long a failed connection to the relay/daemon answers `fallback` without retrying.
  const FAILURE_MEMORY_MS = 2000;
  // Live sockets of one tab, across its frames; browsers cap a page's own WebSockets similarly.
  const MAX_TAB_SOCKETS = 256;
  // Global sids are u32 values above 0, as the daemon expects.
  const MAX_SID = 0xffffffff;
  // Chromium: the page shim is registered at run time (a static MAIN-world content script needs
  // Chrome 111; `registerContentScripts` with `world` works from 109).
  const SHIM_SCRIPT = {
    id: 'oncl-shim',
    js: ['shim.js'],
    matches: ['<all_urls>'],
    runAt: 'document_start',
    allFrames: true,
    world: 'MAIN',
    persistAcrossSessions: true,
  };

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

  /** Origin of the frame behind a port, as reported by the browser. */
  function senderOrigin(sender) {
    if (sender && typeof sender.origin === 'string' && sender.origin !== '') return sender.origin;
    try {
      return new URL(sender.url).origin;
    } catch {
      return 'null';
    }
  }

  function createBackground(chrome, hostName) {
    const runtime = chrome.runtime;
    let native = null; // { port, relay, hello, nextSid } of the live native session
    let failedAt = -Infinity;
    const sockets = new Map(); // global sid → { bridge, sid (local), accepted }
    const tabs = new Map(); // tab id → Set of the tab's bridges
    let probeWaiters = []; // bridges waiting for the relay frame, one entry per probe

    // --- Native side ----------------------------------------------------------------------
    /** The live native session, connecting if needed; `null` while a failure is remembered. */
    function connectNative() {
      if (native) return native;
      if (Date.now() - failedAt < FAILURE_MEMORY_MS) return null;
      let port;
      try {
        port = runtime.connectNative(hostName);
      } catch (error) {
        console.warn('OpenNCALayer: cannot start the native host:', error);
        failedAt = Date.now();
        return null;
      }
      // Global sids need only be unique within a session.
      const session = { port, relay: false, hello: false, nextSid: 1 };
      native = session;
      port.onMessage.addListener((frame) => fromNative(session, frame));
      port.onDisconnect.addListener(() => {
        const error = runtime.lastError ?? port.error;
        if (native === session) console.warn('OpenNCALayer: native host disconnected:', error?.message ?? error);
        endNative(session);
      });
      return session;
    }

    /** A free global sid of `session`: counts up within u32, skipping live sids. */
    function allocateSid(session) {
      let sid = session.nextSid;
      while (sockets.has(sid)) sid = sid === MAX_SID ? 1 : sid + 1;
      session.nextSid = sid === MAX_SID ? 1 : sid + 1;
      return sid;
    }

    function toNative(frame) {
      const session = native;
      if (!session) return;
      try {
        session.port.postMessage(frame);
      } catch (error) {
        console.warn('OpenNCALayer: cannot write to the native host:', error);
        // Stop the relay too, so the daemon closes this session's sids now.
        session.port.disconnect();
        endNative(session);
      }
    }

    /** The native session is over: fall back or close every socket, refuse waiting probes. */
    function endNative(session) {
      if (native !== session) return;
      native = null;
      // Failing before the daemon said hello is a connection failure; losing a working
      // daemon is not (the relay restarts it on the next connection).
      if (!session.hello) failedAt = Date.now();
      const waiters = probeWaiters;
      probeWaiters = [];
      for (const bridge of waiters) bridge.post({ t: 'probe', ok: false });
      const lost = [...sockets.values()];
      sockets.clear();
      for (const { bridge, sid, accepted } of lost) {
        bridge.sids.delete(sid);
        bridge.post({ t: accepted ? 'close' : 'fallback', sid });
      }
    }

    function fromNative(session, frame) {
      if (native !== session || frame === null || typeof frame !== 'object') return;
      const socket = sockets.get(frame.sid);
      switch (frame.t) {
        case 'relay': {
          session.relay = true;
          const waiters = probeWaiters;
          probeWaiters = [];
          for (const bridge of waiters) bridge.post({ t: 'probe', ok: true });
          break;
        }
        case 'hello':
          session.hello = true;
          break;
        case 'error':
          console.warn(`OpenNCALayer: native host error ${frame.code}: ${frame.message}`);
          session.port.disconnect();
          endNative(session);
          break;
        case 'open':
          if (!socket || socket.accepted) return;
          socket.accepted = true;
          socket.bridge.post({ t: 'open', sid: socket.sid });
          break;
        case 'msg':
          if (!socket || typeof frame.data !== 'string') return;
          socket.bridge.post(
            frame.more === true
              ? { t: 'msg', sid: socket.sid, data: frame.data, more: true }
              : { t: 'msg', sid: socket.sid, data: frame.data },
          );
          break;
        case 'close':
          if (!socket) return;
          sockets.delete(frame.sid);
          socket.bridge.sids.delete(socket.sid);
          socket.bridge.post({ t: 'close', sid: socket.sid });
          break;
        default:
          console.debug('OpenNCALayer: unknown frame from the native host:', frame.t);
      }
    }

    // --- Bridge side ----------------------------------------------------------------------
    /** Forgets a bridge's local sid and closes it at the daemon. */
    function closeLocal(bridge, sid) {
      const global = bridge.sids.get(sid);
      if (global === undefined) return;
      bridge.sids.delete(sid);
      sockets.delete(global);
      toNative({ t: 'close', sid: global });
    }

    /** Live sockets of the tab `bridge` belongs to. */
    function tabSockets(bridge) {
      let live = 0;
      for (const member of bridge.tab) live += member.sids.size;
      return live;
    }

    function fromBridge(bridge, frame) {
      if (frame === null || typeof frame !== 'object') return;
      switch (frame.t) {
        case 'open': {
          if (!isSid(frame.sid)) return;
          closeLocal(bridge, frame.sid);
          // The bridge checks this too; a bad URL reaching the daemon would cost every tab
          // its connection (lone surrogates: unparsable JSON; huge: over the frame limit).
          const url = socketUrl(frame.url);
          if (url === null) {
            bridge.post({ t: 'close', sid: frame.sid });
            return;
          }
          if (tabSockets(bridge) >= MAX_TAB_SOCKETS) {
            // Refused like a failed connection; nothing reaches the daemon.
            bridge.post({ t: 'close', sid: frame.sid });
            return;
          }
          const session = connectNative();
          if (!session) {
            bridge.post({ t: 'fallback', sid: frame.sid });
            return;
          }
          const sid = allocateSid(session);
          bridge.sids.set(frame.sid, sid);
          sockets.set(sid, { bridge, sid: frame.sid, accepted: false });
          // `origin` from the browser; whatever the frame carried is ignored.
          toNative({ t: 'open', sid, origin: bridge.origin, url });
          break;
        }
        case 'msg': {
          const sid = bridge.sids.get(frame.sid);
          if (sid === undefined || typeof frame.data !== 'string') return;
          if (frame.data.length > PIECE) {
            // The bridge cuts messages into pieces; an oversized one would exceed the frame limit.
            closeLocal(bridge, frame.sid);
            bridge.post({ t: 'close', sid: frame.sid });
            return;
          }
          const data = wellFormed(frame.data);
          toNative(frame.more === true ? { t: 'msg', sid, data, more: true } : { t: 'msg', sid, data });
          break;
        }
        case 'close':
          closeLocal(bridge, frame.sid);
          break;
        case 'probe': {
          const session = connectNative();
          if (!session) bridge.post({ t: 'probe', ok: false });
          else if (session.relay) bridge.post({ t: 'probe', ok: true });
          else probeWaiters.push(bridge);
          break;
        }
      }
    }

    runtime.onConnect.addListener((port) => {
      if (port.name !== PORT_NAME) return;
      const bridge = {
        origin: senderOrigin(port.sender),
        sids: new Map(), // local sid → global sid
        connected: true,
        post(frame) {
          if (!bridge.connected) return;
          try {
            port.postMessage(frame);
          } catch {
            // The frame is gone; its onDisconnect cleans up.
          }
        },
      };
      // Frames of one tab share its socket cap; a port without a tab is a tab of its own.
      const tabId = port.sender?.tab?.id;
      if (tabId === undefined) {
        bridge.tab = new Set([bridge]);
      } else {
        if (!tabs.has(tabId)) tabs.set(tabId, new Set());
        bridge.tab = tabs.get(tabId);
        bridge.tab.add(bridge);
      }
      port.onMessage.addListener((frame) => fromBridge(bridge, frame));
      port.onDisconnect.addListener(() => {
        void runtime.lastError; // read, so it is not reported as unchecked
        bridge.connected = false;
        for (const sid of [...bridge.sids.keys()]) closeLocal(bridge, sid);
        probeWaiters = probeWaiters.filter((waiter) => waiter !== bridge);
        bridge.tab.delete(bridge);
        if (tabId !== undefined && bridge.tab.size === 0) tabs.delete(tabId);
      });
    });

    // --- Shim registration (Chromium) -----------------------------------------------------
    const scripting = chrome.scripting;
    if (scripting && typeof scripting.registerContentScripts === 'function') {
      const registerShim = async () => {
        const found = await scripting.getRegisteredContentScripts({ ids: [SHIM_SCRIPT.id] });
        if (found.length === 0) await scripting.registerContentScripts([SHIM_SCRIPT]);
        else await scripting.updateContentScripts([SHIM_SCRIPT]);
      };
      const register = () => {
        registerShim().catch((error) => console.error('OpenNCALayer: cannot register the page shim:', error));
      };
      runtime.onInstalled.addListener(register);
      runtime.onStartup.addListener(register);
    }
  }

  if (typeof module === 'object' && module !== null) module.exports = createBackground;
  else createBackground(chrome, HOST_NAME);
})();
