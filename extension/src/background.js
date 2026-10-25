// OpenNCALayer background (Chromium MV3 service worker, Firefox MV2 background page).
//
// Owns one native messaging port to the relay (`nmhost`), opened on first need and shared by
// every bridge. Maps each bridge's local sids to global sids (1, 2, …, never reused) and stamps
// `open` with the origin the browser reports for the bridge's frame; the page never chooses it.
// When the relay or the daemon is unavailable, sockets the daemon has not accepted yet get
// `fallback` (the page's own WebSocket takes over) and accepted ones get `close`.
if (typeof importScripts === 'function') importScripts('host.js');

(function () {
  'use strict';

  const PORT_NAME = 'oncl';
  // How long a failed connection to the relay/daemon answers `fallback` without retrying.
  const FAILURE_MEMORY_MS = 2000;
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
  const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

  const isSid = (value) => Number.isSafeInteger(value) && value > 0;

  /** The bridges cut well-formed text; a lone surrogate would cost the daemon connection. */
  function wellFormed(text) {
    return typeof text.toWellFormed === 'function' ? text.toWellFormed() : text.replace(LONE_SURROGATE, '\uFFFD');
  }

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
    let native = null; // { port, relay, hello } of the live native port
    let failedAt = -Infinity;
    let nextSid = 1;
    const sockets = new Map(); // global sid → { bridge, sid (local), accepted }
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
      const session = { port, relay: false, hello: false };
      native = session;
      port.onMessage.addListener((frame) => fromNative(session, frame));
      port.onDisconnect.addListener(() => {
        const error = runtime.lastError ?? port.error;
        if (native === session) console.warn('OpenNCALayer: native host disconnected:', error?.message ?? error);
        endNative(session);
      });
      return session;
    }

    function toNative(frame) {
      if (!native) return;
      try {
        native.port.postMessage(frame);
      } catch {
        endNative(native);
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

    function fromBridge(bridge, frame) {
      if (frame === null || typeof frame !== 'object') return;
      switch (frame.t) {
        case 'open': {
          if (!isSid(frame.sid) || typeof frame.url !== 'string') return;
          closeLocal(bridge, frame.sid);
          const session = connectNative();
          if (!session) {
            bridge.post({ t: 'fallback', sid: frame.sid });
            return;
          }
          const sid = nextSid++;
          bridge.sids.set(frame.sid, sid);
          sockets.set(sid, { bridge, sid: frame.sid, accepted: false });
          // `origin` from the browser; whatever the frame carried is ignored.
          toNative({ t: 'open', sid, origin: bridge.origin, url: frame.url });
          break;
        }
        case 'msg': {
          const sid = bridge.sids.get(frame.sid);
          if (sid === undefined || typeof frame.data !== 'string') return;
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
      port.onMessage.addListener((frame) => fromBridge(bridge, frame));
      port.onDisconnect.addListener(() => {
        void runtime.lastError; // read, so it is not reported as unchecked
        bridge.connected = false;
        for (const sid of [...bridge.sids.keys()]) closeLocal(bridge, sid);
        probeWaiters = probeWaiters.filter((waiter) => waiter !== bridge);
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
