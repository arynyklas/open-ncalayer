// OpenNCALayer page shim (document_start, every frame).
//
// `new WebSocket()` to NCALayer's loopback ports becomes a virtual socket carried by the
// extension: shim → bridge content script → background → native messaging host → daemon.
// When the extension cannot reach the daemon, the background answers `fallback` and the
// socket quietly becomes the browser's own `WebSocket` to the same URL (the original
// NCALayer, if any). Everything else is untouched. When the bridge stops answering (the
// extension was disabled, removed or updated), the browser's own `WebSocket` and `fetch`
// take over for good.
//
// The shim reaches the page in one of two ways:
// - in the page's own world (Chromium; Firefox 128+ with `world: "MAIN"`): it replaces the
//   page's globals directly and talks to the bridge with `CustomEvent`s on `document`
//   carrying JSON strings;
// - as an ordinary Firefox content script next to the bridge (Firefox before 128 ignores
//   `world`): it replaces them through Xray vision (`window.wrappedJSObject`,
//   `exportFunction`, `cloneInto`) and calls the bridge directly, with no page events. When
//   the extension goes away, Firefox destroys this script with what it gave the page: the
//   page's `WebSocket` and `fetch` throw until it reloads.
(function () {
  'use strict';

  const TO_EXT = '__oncl_to_ext';
  const TO_PAGE = '__oncl_to_page';
  // The property of the content-script global where the shim and the bridge meet (Xray).
  const LINK = '__oncl_link';
  const CONNECTING = 0;
  const OPEN = 1;
  const CLOSING = 2;
  const CLOSED = 3;
  const STATES = { CONNECTING, OPEN, CLOSING, CLOSED };
  // RFC 6455 §5.5: a close frame body is at most 125 bytes, 2 of them the code.
  const MAX_CLOSE_REASON = 123;

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

  /** Byte-ish values `send` encodes as UTF-8 text, by kind; `null` for everything else. */
  function binaryKind(data) {
    if (data === null || typeof data !== 'object') return null;
    if (ArrayBuffer.isView(data)) return 'bytes';
    // Tags rather than `instanceof`: buffers and blobs may come from another frame.
    const tag = Object.prototype.toString.call(data);
    if (tag === '[object ArrayBuffer]') return 'bytes';
    if (tag === '[object Blob]' || tag === '[object File]') return 'blob';
    return null;
  }

  /**
   * How the shim handles page objects. In the page's own world they are its own. From a
   * Firefox content script (`sandbox`, its global, has `exportFunction` and `cloneInto`):
   * - `page`: the page's `window` with Xray vision waived, so page objects behave as for page
   *   code (and whatever the shim creates through it is created in the page);
   * - `expose(fn)`: `fn` as a function the page may call; its `this` and arguments arrive
   *   with Xray vision waived too;
   * - `dict(object)`: a copy of a plain object of primitives in the page, for page APIs.
   */
  function pageAccess(win, sandbox) {
    if (!sandbox) return { page: win, expose: (fn) => fn, dict: (object) => object };
    /** `value` as the page sees it: page objects reach a content script behind Xrays. */
    const waive = (value) => {
      if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return value;
      const waived = value.wrappedJSObject;
      return waived === undefined ? value : waived;
    };
    const expose = (fn) => {
      const exported = waive(
        sandbox.exportFunction(function () {
          const args = Array.prototype.map.call(arguments, waive);
          return new.target === undefined ? Reflect.apply(fn, waive(this), args) : Reflect.construct(fn, args);
        }, win),
      );
      // Like the function itself rather than the wrapper above.
      Object.defineProperty(exported, 'name', { value: fn.name, configurable: true });
      Object.defineProperty(exported, 'length', { value: fn.length, configurable: true });
      return exported;
    };
    const dict = (object) => waive(sandbox.cloneInto(object, win));
    return { page: waive(win), expose, dict };
  }

  /**
   * The link to the bridge through `CustomEvent`s on the page's `document`: JSON strings
   * both ways. Calls `onFrame` with each frame from the bridge; returns the sender.
   */
  function eventLink(win, onFrame) {
    const doc = win.document;
    doc.addEventListener(TO_PAGE, (event) => {
      if (typeof event.detail !== 'string') return;
      let frame;
      try {
        frame = JSON.parse(event.detail);
      } catch {
        return;
      }
      onFrame(frame);
    });
    return (frame) => doc.dispatchEvent(new win.CustomEvent(TO_EXT, { detail: JSON.stringify(frame) }));
  }

  /**
   * The link to the bridge in the same content-script global `sandbox`: plain calls both ways,
   * out of the page's reach. Calls `onFrame` with each frame from the bridge; returns the sender.
   */
  function directLink(sandbox, onFrame) {
    if (!Object.prototype.hasOwnProperty.call(sandbox, LINK)) {
      Object.defineProperty(sandbox, LINK, { value: { toExt: null, toPage: null } });
    }
    const channel = sandbox[LINK];
    channel.toPage = onFrame;
    return (frame) => {
      if (channel.toExt) channel.toExt(frame);
    };
  }

  /**
   * Replaces `WebSocket` and `fetch` of the page `win`. `sandbox`: the global of the Firefox
   * content script the shim runs in; absent in the page's own world.
   */
  function installShim(win, sandbox) {
    const { page, expose, dict } = pageAccess(win, sandbox);
    const NativeWebSocket = page.WebSocket;
    const nativeFetch = page.fetch;
    const { CloseEvent, DOMException, Event, EventTarget, MessageEvent, Request, Response, URL } = page;
    const decoder = new page.TextDecoder();
    const encoder = new page.TextEncoder();

    // --- Link to the bridge ---------------------------------------------------------------
    let bridgeReady = false;
    // The bridge said `ready` once and no longer answers: the extension was removed, disabled
    // or updated. From then on the page's own `WebSocket` and `fetch` serve everything.
    let bridgeGone = false;
    let heard = false; // a `ready` arrived (while checking the bridge)
    const unsent = [];
    const sockets = new Map(); // sid → frame handler of a virtual socket
    const probes = []; // resolvers of pending probes, answered in order
    let nextSid = 1;

    function fromBridge(frame) {
      if (frame === null || typeof frame !== 'object') return;
      if (frame.t === 'ready') {
        heard = true;
        if (bridgeReady) return;
        bridgeReady = true;
        for (const queued of unsent.splice(0)) emit(queued);
      } else if (frame.t === 'probe') {
        const resolve = probes.shift();
        if (resolve) resolve(frame.ok === true);
      } else {
        const onFrame = isSid(frame.sid) ? sockets.get(frame.sid) : undefined;
        if (onFrame) onFrame(frame);
      }
    }

    const emit = sandbox ? directLink(sandbox, fromBridge) : eventLink(win, fromBridge);

    /** Sends `frame` to the bridge, holding it until the bridge has said `ready`. */
    function post(frame) {
      if (bridgeReady) emit(frame);
      else unsent.push(frame);
    }

    // The bridge may have started first and missed nothing but this: ask it to say `ready`.
    emit({ t: 'ready' });

    /**
     * Whether the bridge is still there. Both links deliver at once and the bridge answers
     * `ready` at once, so no answer means it is gone (Firefox 128+ keeps this page-world shim
     * when the extension goes away, but not the bridge). Then the extension's sockets are
     * handed to the browser's own `WebSocket` (not yet accepted) or reset (accepted), and
     * pending probes are refused. Until the bridge first answers, it is taken as coming.
     */
    function bridgeAlive() {
      if (bridgeGone) return false;
      if (!bridgeReady) return true;
      heard = false;
      emit({ t: 'ready' });
      if (heard) return true;
      bridgeGone = true;
      for (const onFrame of [...sockets.values()]) onFrame({ t: 'gone' });
      for (const resolve of probes.splice(0)) resolve(false);
      return false;
    }

    /** Whether the daemon is reachable through the extension. */
    function probe() {
      return new Promise((resolve) => {
        probes.push(resolve);
        post({ t: 'probe' });
      });
    }

    // --- Virtual socket -------------------------------------------------------------------
    // The page holds a plain page `EventTarget` (the face) whose prototype carries the
    // `WebSocket` members; they find the socket behind a face here.
    const faces = new WeakMap(); // face → VirtualWebSocket

    class VirtualWebSocket {
      #sid = nextSid++;
      #face;
      #url;
      #origin;
      #nativeArgs; // arguments for the native socket on `fallback`
      #state = CONNECTING;
      #binaryType = 'blob';
      #native = null; // the browser's own socket after `fallback`
      #outbox = []; // frames, or promises of frames (Blob reads), kept in send order
      #pumping = false;
      #handlers = { open: {}, message: {}, error: {}, close: {} };

      constructor(face, url, nativeArgs) {
        this.#face = face;
        this.#url = url.href;
        this.#origin = url.origin;
        this.#nativeArgs = nativeArgs;
        faces.set(face, this);
        sockets.set(this.#sid, (frame) => this.#onFrame(frame));
        post({ t: 'open', sid: this.#sid, url: this.#url });
      }

      get url() {
        return this.#native ? this.#native.url : this.#url;
      }
      get readyState() {
        return this.#native ? this.#native.readyState : this.#state;
      }
      get bufferedAmount() {
        return this.#native ? this.#native.bufferedAmount : 0;
      }
      get extensions() {
        return this.#native ? this.#native.extensions : '';
      }
      get protocol() {
        return this.#native ? this.#native.protocol : '';
      }
      get binaryType() {
        return this.#binaryType;
      }
      set binaryType(value) {
        // An enum attribute: unknown values are ignored.
        if (value !== 'blob' && value !== 'arraybuffer') return;
        this.#binaryType = value;
        if (this.#native) this.#native.binaryType = value;
      }

      send(data) {
        if (this.#native) return this.#native.send(data);
        if (this.#state === CONNECTING) {
          throw new DOMException("Failed to execute 'send' on 'WebSocket': Still in CONNECTING state.", 'InvalidStateError');
        }
        // Like the browser: data sent after `close()` is silently dropped.
        if (this.#state !== OPEN) return;
        const sid = this.#sid;
        switch (binaryKind(data)) {
          case 'bytes':
            this.#queue({ t: 'msg', sid, data: decoder.decode(data) });
            break;
          case 'blob': {
            const text = data.text();
            // An unreadable Blob is skipped rather than stalling the messages behind it (also
            // when the page's `Blob.prototype.text` does not return a promise).
            this.#queue(
              new Promise((resolve) => {
                try {
                  text.then(
                    expose((value) => resolve({ t: 'msg', sid, data: value })),
                    expose(() => resolve(null)),
                  );
                } catch {
                  resolve(null);
                }
              }),
            );
            break;
          }
          default:
            this.#queue({ t: 'msg', sid, data: String(data) });
        }
      }

      /** `close(...args)` of the page. */
      close(args) {
        if (this.#native) return this.#native.close(...args);
        let [code, reason] = args;
        if (code !== undefined) {
          // WebIDL `[Clamp] unsigned short`.
          code = Math.min(Math.max(Math.round(Number(code)) || 0, 0), 0xffff);
          if (code !== 1000 && !(code >= 3000 && code <= 4999)) {
            throw new DOMException(
              `Failed to execute 'close' on 'WebSocket': The close code must be either 1000, or between 3000 and 4999. ${code} is neither.`,
              'InvalidAccessError',
            );
          }
        }
        reason = reason === undefined ? '' : String(reason);
        if (encoder.encode(reason).length > MAX_CLOSE_REASON) {
          throw new DOMException(
            `Failed to execute 'close' on 'WebSocket': The close reason must not be greater than ${MAX_CLOSE_REASON} UTF-8 bytes.`,
            'SyntaxError',
          );
        }
        if (this.#state === CLOSING || this.#state === CLOSED) return;
        const accepted = this.#state === OPEN;
        this.#state = CLOSING;
        sockets.delete(this.#sid);
        this.#queue({ t: 'close', sid: this.#sid });
        page.setTimeout(
          expose(() => {
            this.#state = CLOSED;
            if (accepted) {
              this.#fire(new CloseEvent('close', dict({ code: code ?? 1000, reason, wasClean: true })));
            } else {
              // Closing a socket that never opened fails the connection, as in the browser.
              this.#fire(new Event('error'));
              this.#fire(new CloseEvent('close', dict({ code: 1006, reason: '', wasClean: false })));
            }
          }),
          0,
        );
      }

      /** The `on<type>` event handler attribute. */
      handler(type) {
        return this.#handlers[type].value ?? null;
      }

      setHandler(type, value) {
        const slot = this.#handlers[type];
        slot.value = typeof value === 'function' ? value : null;
        // Like an event handler attribute: one listener, added when first set.
        if (slot.value && !slot.listener) {
          slot.listener = expose((event) => {
            if (slot.value) Reflect.apply(slot.value, this.#face, [event]);
          });
          this.#face.addEventListener(type, slot.listener);
        } else if (!slot.value && slot.listener) {
          this.#face.removeEventListener(type, slot.listener);
          slot.listener = undefined;
        }
      }

      #onFrame(frame) {
        switch (frame.t) {
          case 'open':
            if (this.#state !== CONNECTING) return;
            this.#state = OPEN;
            this.#fire(new Event('open'));
            break;
          case 'msg':
            if (this.#state !== OPEN || typeof frame.data !== 'string') return;
            this.#fire(new MessageEvent('message', dict({ data: frame.data, origin: this.#origin })));
            break;
          case 'close':
            this.#reset();
            break;
          case 'fallback':
            if (this.#state === CONNECTING) this.#fallback();
            break;
          case 'gone':
            if (this.#state === CONNECTING) this.#fallback();
            else this.#reset();
            break;
        }
      }

      /** The daemon or the extension dropped the socket: error, then close 1006. */
      #reset() {
        sockets.delete(this.#sid);
        if (this.#state === CLOSED) return;
        this.#state = CLOSED;
        this.#outbox.length = 0;
        this.#fire(new Event('error'));
        this.#fire(new CloseEvent('close', dict({ code: 1006, reason: '', wasClean: false })));
      }

      /** The extension cannot serve this socket: hand it to the browser's own WebSocket. */
      #fallback() {
        sockets.delete(this.#sid);
        let native;
        try {
          native = new NativeWebSocket(...this.#nativeArgs);
        } catch {
          // E.g. invalid `protocols`, which the native constructor would have thrown on.
          this.#reset();
          return;
        }
        this.#native = native;
        native.binaryType = this.#binaryType;
        native.addEventListener('open', expose(() => this.#fire(new Event('open'))));
        native.addEventListener(
          'message',
          expose((e) => {
            const init = dict({ origin: e.origin, lastEventId: e.lastEventId });
            // The data as is (text, Blob or ArrayBuffer); defined, so no page setter runs.
            Object.defineProperty(init, 'data', { value: e.data, writable: true, enumerable: true, configurable: true });
            this.#fire(new MessageEvent('message', init));
          }),
        );
        native.addEventListener('error', expose(() => this.#fire(new Event('error'))));
        native.addEventListener(
          'close',
          expose((e) => {
            this.#fire(new CloseEvent('close', dict({ code: e.code, reason: e.reason, wasClean: e.wasClean })));
          }),
        );
      }

      #queue(item) {
        this.#outbox.push(item);
        if (!this.#pumping) this.#pump();
      }

      /** Posts queued frames in order; strings go out at once, Blob reads are awaited. */
      async #pump() {
        this.#pumping = true;
        while (this.#outbox.length > 0) {
          let frame = this.#outbox.shift();
          if (typeof frame.then === 'function') frame = await frame;
          if (frame) post(frame);
        }
        this.#pumping = false;
      }

      #fire(event) {
        this.#face.dispatchEvent(event);
      }
    }

    // --- Replacement constructor ----------------------------------------------------------
    /** Parses a `WebSocket`/`fetch` URL argument; `null` if it is not a valid URL. */
    function parse(url) {
      try {
        return new URL(String(url), page.location.href);
      } catch {
        return null;
      }
    }

    /** The virtual socket behind `face`, the `this` of a page call. */
    function socketOf(face) {
      const socket = faces.get(face);
      if (!socket) throw new page.TypeError("'WebSocket' member called on an object that is not a WebSocket.");
      return socket;
    }

    // The prototype of virtual sockets: every `WebSocket` member, over the native prototype.
    const virtualPrototype = page.Object.create(NativeWebSocket.prototype);
    const member = (name, descriptor) => {
      Object.defineProperty(virtualPrototype, name, { ...descriptor, enumerable: true, configurable: true });
    };
    for (const name of ['url', 'readyState', 'bufferedAmount', 'extensions', 'protocol']) {
      member(name, {
        get: expose(function () {
          return socketOf(this)[name];
        }),
      });
    }
    member('binaryType', {
      get: expose(function () {
        return socketOf(this).binaryType;
      }),
      set: expose(function (value) {
        socketOf(this).binaryType = value;
      }),
    });
    for (const type of ['open', 'message', 'error', 'close']) {
      member(`on${type}`, {
        get: expose(function () {
          return socketOf(this).handler(type);
        }),
        set: expose(function (value) {
          socketOf(this).setHandler(type, value);
        }),
      });
    }
    member('send', {
      writable: true,
      value: expose(function send(data) {
        return socketOf(this).send(data);
      }),
    });
    member('close', {
      writable: true,
      value: expose(function close() {
        return socketOf(this).close(Array.prototype.slice.call(arguments));
      }),
    });

    function WebSocket(url) {
      if (new.target === undefined) {
        throw new page.TypeError(
          "Failed to construct 'WebSocket': Please use the 'new' operator, this DOM object constructor cannot be called as a function.",
        );
      }
      const args = Array.prototype.slice.call(arguments, 0, 2);
      const parsed = args.length > 0 ? parse(url) : null;
      if (parsed === null || socketUrl(parsed.href) === null || !bridgeAlive()) {
        // A subclass of the page keeps its prototype.
        return Reflect.construct(NativeWebSocket, args, new.target === WebSocket ? NativeWebSocket : new.target);
      }
      const face = new EventTarget();
      Object.setPrototypeOf(face, virtualPrototype);
      new VirtualWebSocket(face, parsed, args);
      return face;
    }
    const PageWebSocket = expose(WebSocket);
    // Both kinds of socket are `instanceof WebSocket`: virtual ones inherit the native
    // prototype (overriding every member), native ones are made with it.
    Object.defineProperty(PageWebSocket, 'prototype', {
      value: NativeWebSocket.prototype,
      writable: true,
      enumerable: false,
      configurable: false,
    });
    Object.setPrototypeOf(PageWebSocket, Object.getPrototypeOf(NativeWebSocket));
    for (const [name, value] of Object.entries(STATES)) {
      Object.defineProperty(PageWebSocket, name, { value, enumerable: true });
    }
    Object.defineProperty(NativeWebSocket.prototype, 'constructor', {
      value: PageWebSocket,
      writable: true,
      configurable: true,
    });
    Object.defineProperty(page, 'WebSocket', { value: PageWebSocket, writable: true, configurable: true });

    // --- fetch ----------------------------------------------------------------------------
    // Sites check for NCALayer with `fetch("https://127.0.0.1:13579/")`: answer it with an
    // empty 200 when the extension reaches the daemon, else let the request go out.
    function fetch(input) {
      const init = arguments[1];
      const isRequest = input instanceof Request;
      const url = parse(isRequest ? input.url : input);
      if (url === null || !isNcaLayer(url, ['http:', 'https:']) || !bridgeAlive()) {
        return Reflect.apply(nativeFetch, this, arguments);
      }
      const thisArg = this;
      const args = Array.prototype.slice.call(arguments);
      const signal = init != null && init.signal != null ? init.signal : isRequest ? input.signal : null;
      return new page.Promise(
        expose((resolve, reject) => {
          const abortError = () => signal.reason ?? new DOMException('The operation was aborted.', 'AbortError');
          if (signal && signal.aborted) {
            reject(abortError());
            return;
          }
          const onAbort = expose(() => reject(abortError()));
          if (signal) signal.addEventListener('abort', onAbort, dict({ once: true }));
          probe().then((ok) => {
            if (signal) {
              signal.removeEventListener('abort', onAbort);
              if (signal.aborted) return;
            }
            if (ok) resolve(new Response('', dict({ status: 200 })));
            else resolve(Reflect.apply(nativeFetch, thisArg, args));
          });
        }),
      );
    }
    Object.defineProperty(page, 'fetch', { value: expose(fetch), writable: true, enumerable: true, configurable: true });
  }

  if (typeof module === 'object' && module !== null) module.exports = installShim;
  // `exportFunction` exists only in a Firefox content script, never in the page's own world.
  else installShim(window, typeof exportFunction === 'function' ? globalThis : undefined);
})();
