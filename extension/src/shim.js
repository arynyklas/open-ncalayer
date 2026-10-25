// OpenNCALayer page shim (MAIN world, document_start).
//
// `new WebSocket()` to NCALayer's loopback ports becomes a virtual socket carried by the
// extension: shim → bridge content script (`CustomEvent`s on `document` with JSON strings) →
// background → native messaging host → daemon. When the extension cannot reach the daemon,
// the background answers `fallback` and the socket quietly becomes the browser's own
// `WebSocket` to the same URL (the original NCALayer, if any). Everything else is untouched.
(function () {
  'use strict';

  const TO_EXT = '__oncl_to_ext';
  const TO_PAGE = '__oncl_to_page';
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
    if (ArrayBuffer.isView(data)) return 'view';
    // Tags rather than `instanceof`: buffers and blobs may come from another frame.
    const tag = Object.prototype.toString.call(data);
    if (tag === '[object ArrayBuffer]') return 'buffer';
    if (tag === '[object Blob]' || tag === '[object File]') return 'blob';
    return null;
  }

  function installShim(win) {
    const NativeWebSocket = win.WebSocket;
    const nativeFetch = win.fetch;
    const doc = win.document;
    const { CloseEvent, CustomEvent, DOMException, Event, MessageEvent, Request, Response, URL } = win;
    const decoder = new win.TextDecoder();
    const encoder = new win.TextEncoder();

    // --- Link to the bridge ---------------------------------------------------------------
    let bridgeReady = false;
    const unsent = [];
    const sockets = new Map(); // sid → frame handler of a virtual socket
    const probes = []; // resolvers of pending probes, answered in order
    let nextSid = 1;

    function emit(frame) {
      doc.dispatchEvent(new CustomEvent(TO_EXT, { detail: JSON.stringify(frame) }));
    }

    /** Sends `frame` to the bridge, holding it until the bridge has said `ready`. */
    function post(frame) {
      if (bridgeReady) emit(frame);
      else unsent.push(frame);
    }

    doc.addEventListener(TO_PAGE, (event) => {
      if (typeof event.detail !== 'string') return;
      let frame;
      try {
        frame = JSON.parse(event.detail);
      } catch {
        return;
      }
      if (frame === null || typeof frame !== 'object') return;
      if (frame.t === 'ready') {
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
    });
    // The bridge may have started first and missed nothing but this: ask it to say `ready`.
    emit({ t: 'ready' });

    /** Whether the daemon is reachable through the extension. */
    function probe() {
      return new Promise((resolve) => {
        probes.push(resolve);
        post({ t: 'probe' });
      });
    }

    // --- Virtual socket -------------------------------------------------------------------
    class VirtualWebSocket extends win.EventTarget {
      #sid = nextSid++;
      #url;
      #origin;
      #nativeArgs; // arguments for the native socket on `fallback`
      #state = CONNECTING;
      #binaryType = 'blob';
      #native = null; // the browser's own socket after `fallback`
      #outbox = []; // frames, or promises of frames (Blob reads), kept in send order
      #pumping = false;
      #handlers = { open: {}, message: {}, error: {}, close: {} };

      constructor(url, nativeArgs) {
        super();
        this.#url = url.href;
        this.#origin = url.origin;
        this.#nativeArgs = nativeArgs;
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

      get onopen() {
        return this.#handler('open');
      }
      set onopen(value) {
        this.#setHandler('open', value);
      }
      get onmessage() {
        return this.#handler('message');
      }
      set onmessage(value) {
        this.#setHandler('message', value);
      }
      get onerror() {
        return this.#handler('error');
      }
      set onerror(value) {
        this.#setHandler('error', value);
      }
      get onclose() {
        return this.#handler('close');
      }
      set onclose(value) {
        this.#setHandler('close', value);
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
          case 'view':
            this.#queue({ t: 'msg', sid, data: decoder.decode(data) });
            break;
          case 'buffer':
            this.#queue({ t: 'msg', sid, data: decoder.decode(new Uint8Array(data)) });
            break;
          case 'blob':
            // An unreadable Blob is skipped rather than stalling the messages behind it.
            this.#queue(data.text().then((text) => ({ t: 'msg', sid, data: text }), () => null));
            break;
          default:
            this.#queue({ t: 'msg', sid, data: String(data) });
        }
      }

      close(code, reason) {
        if (this.#native) {
          const args = [code, reason].slice(0, arguments.length);
          return this.#native.close(...args);
        }
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
        win.setTimeout(() => {
          this.#state = CLOSED;
          if (accepted) {
            this.#fire(new CloseEvent('close', { code: code ?? 1000, reason, wasClean: true }));
          } else {
            // Closing a socket that never opened fails the connection, as in the browser.
            this.#fire(new Event('error'));
            this.#fire(new CloseEvent('close', { code: 1006, reason: '', wasClean: false }));
          }
        }, 0);
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
            this.#fire(new MessageEvent('message', { data: frame.data, origin: this.#origin }));
            break;
          case 'close':
            this.#reset();
            break;
          case 'fallback':
            if (this.#state === CONNECTING) this.#fallback();
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
        this.#fire(new CloseEvent('close', { code: 1006, reason: '', wasClean: false }));
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
        native.addEventListener('open', () => this.#fire(new Event('open')));
        native.addEventListener('message', (e) => {
          this.#fire(new MessageEvent('message', { data: e.data, origin: e.origin, lastEventId: e.lastEventId }));
        });
        native.addEventListener('error', () => this.#fire(new Event('error')));
        native.addEventListener('close', (e) => {
          this.#fire(new CloseEvent('close', { code: e.code, reason: e.reason, wasClean: e.wasClean }));
        });
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
        this.dispatchEvent(event);
      }

      #handler(type) {
        return this.#handlers[type].value ?? null;
      }

      #setHandler(type, value) {
        const slot = this.#handlers[type];
        slot.value = typeof value === 'function' ? value : null;
        // Like an event handler attribute: one listener, added when first set.
        if (slot.value && !slot.listener) {
          slot.listener = (event) => slot.value?.call(this, event);
          this.addEventListener(type, slot.listener);
        } else if (!slot.value && slot.listener) {
          this.removeEventListener(type, slot.listener);
          slot.listener = undefined;
        }
      }
    }

    // --- Replacement constructor ----------------------------------------------------------
    /** Parses a `WebSocket`/`fetch` URL argument; `null` if it is not a valid URL. */
    function parse(url) {
      try {
        return new URL(String(url), win.location.href);
      } catch {
        return null;
      }
    }

    function WebSocket(url) {
      if (new.target === undefined) {
        throw new TypeError(
          "Failed to construct 'WebSocket': Please use the 'new' operator, this DOM object constructor cannot be called as a function.",
        );
      }
      const args = Array.prototype.slice.call(arguments, 0, 2);
      const parsed = args.length > 0 ? parse(url) : null;
      if (parsed === null || socketUrl(parsed.href) === null) {
        return Reflect.construct(NativeWebSocket, args, new.target);
      }
      return new VirtualWebSocket(parsed, args);
    }
    // Both kinds of socket are `instanceof WebSocket`: virtual ones inherit the native
    // prototype (overriding every member), native ones are made with it.
    WebSocket.prototype = NativeWebSocket.prototype;
    Object.setPrototypeOf(VirtualWebSocket.prototype, NativeWebSocket.prototype);
    Object.setPrototypeOf(WebSocket, Object.getPrototypeOf(NativeWebSocket));
    for (const [name, value] of Object.entries(STATES)) {
      const constant = { value, enumerable: true };
      Object.defineProperty(WebSocket, name, constant);
      Object.defineProperty(VirtualWebSocket.prototype, name, constant);
    }
    for (const proto of [NativeWebSocket.prototype, VirtualWebSocket.prototype]) {
      Object.defineProperty(proto, 'constructor', { value: WebSocket, writable: true, configurable: true });
    }
    Object.defineProperty(win, 'WebSocket', { value: WebSocket, writable: true, configurable: true });

    // --- fetch ----------------------------------------------------------------------------
    // Sites check for NCALayer with `fetch("https://127.0.0.1:13579/")`: answer it with an
    // empty 200 when the extension reaches the daemon, else let the request go out.
    function fetch(input) {
      const init = arguments[1];
      const isRequest = input instanceof Request;
      const url = parse(isRequest ? input.url : input);
      if (url === null || !isNcaLayer(url, ['http:', 'https:'])) {
        return Reflect.apply(nativeFetch, this, arguments);
      }
      const thisArg = this;
      const args = Array.prototype.slice.call(arguments);
      const signal = init != null && init.signal != null ? init.signal : isRequest ? input.signal : null;
      return new Promise((resolve, reject) => {
        const abortError = () => signal.reason ?? new DOMException('The operation was aborted.', 'AbortError');
        if (signal && signal.aborted) {
          reject(abortError());
          return;
        }
        const onAbort = () => reject(abortError());
        if (signal) signal.addEventListener('abort', onAbort, { once: true });
        probe().then((ok) => {
          if (signal) {
            signal.removeEventListener('abort', onAbort);
            if (signal.aborted) return;
          }
          if (ok) resolve(new Response('', { status: 200 }));
          else resolve(Reflect.apply(nativeFetch, thisArg, args));
        });
      });
    }
    Object.defineProperty(win, 'fetch', { value: fetch, writable: true, enumerable: true, configurable: true });
  }

  if (typeof module === 'object' && module !== null) module.exports = installShim;
  else installShim(window);
})();
