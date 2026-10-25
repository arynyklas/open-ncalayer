// Fake browser environment for the extension unit tests. The scripts under `src/` are classic
// scripts; `loadScript` runs one with `node:vm` and returns the factory it exports through
// `module.exports`. The fakes stand in for the page (`window`, `document`, the browser's own
// `WebSocket`/`fetch`) and for `chrome.runtime`/`chrome.scripting`.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

export const HOST_NAME = 'io.github.arynyklas.openncalayer';
const TO_EXT = '__oncl_to_ext';
const TO_PAGE = '__oncl_to_page';

/** Runs `extension/src/<name>` as a classic script and returns its `module.exports`. */
export function loadScript(name) {
  const url = new URL(`../src/${name}`, import.meta.url);
  const source = readFileSync(url, 'utf8');
  const module = { exports: {} };
  // The wrapper keeps the script on its own line numbers.
  vm.runInThisContext(`(function (module) {${source}\n})`, { filename: fileURLToPath(url) })(module);
  return module.exports;
}

/** Lets pending timers, promise jobs and `Blob` reads run. */
export const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

/** Waits (real time, at most ~2 s) until `predicate()` holds. */
export async function until(predicate) {
  for (let i = 0; i < 200; i++) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('condition not reached');
}

/** Runs `fn` without `String.prototype.toWellFormed`, as in Chrome 109–110. */
export function withoutToWellFormed(fn) {
  const descriptor = Object.getOwnPropertyDescriptor(String.prototype, 'toWellFormed');
  delete String.prototype.toWellFormed;
  try {
    return fn();
  } finally {
    if (descriptor) Object.defineProperty(String.prototype, 'toWellFormed', descriptor);
  }
}

// Node 22 has no global `CloseEvent`.
export const CloseEvent =
  globalThis.CloseEvent ??
  class CloseEvent extends Event {
    constructor(type, init = {}) {
      super(type, init);
      this.code = init.code ?? 0;
      this.reason = init.reason ?? '';
      this.wasClean = init.wasClean ?? false;
    }
  };

/** One end of the `CustomEvent` channel between the page and the bridge on `document`. */
function eventEnd(document, inbound, outbound) {
  const frames = [];
  document.addEventListener(inbound, (event) => frames.push(JSON.parse(event.detail)));
  return {
    frames,
    send(frame) {
      document.dispatchEvent(new CustomEvent(outbound, { detail: JSON.stringify(frame) }));
    },
  };
}

/** The bridge as the shim sees it: frames from the page and a way to answer. */
export const bridgeEnd = (document) => eventEnd(document, TO_EXT, TO_PAGE);

/** The page (shim) as the bridge sees it. */
export const pageEnd = (document) => eventEnd(document, TO_PAGE, TO_EXT);

/** A page `window` whose own `WebSocket` and `fetch` are recording fakes. */
export function pageWindow({ href = 'https://site.example/app/', document = new EventTarget() } = {}) {
  const nativeSockets = [];
  const fetchCalls = [];

  class NativeWebSocket extends EventTarget {
    constructor(url, protocols) {
      super();
      if (arguments.length === 0) throw new TypeError('1 argument required');
      this.args = [...arguments];
      this.url = String(url);
      this.readyState = 0;
      this.protocol = '';
      this.extensions = '';
      this.bufferedAmount = 0;
      this.binaryType = 'blob';
      this.sent = [];
      this.closeCalls = [];
      void protocols;
      nativeSockets.push(this);
    }
    send(data) {
      if (this.readyState === 0) throw new DOMException('Still in CONNECTING state.', 'InvalidStateError');
      this.sent.push(data);
    }
    close(...args) {
      this.closeCalls.push(args);
    }
    // Test side: what the network would do.
    serverOpen() {
      this.readyState = 1;
      this.dispatchEvent(new Event('open'));
    }
    serverMessage(data) {
      this.dispatchEvent(new MessageEvent('message', { data, origin: new URL(this.url).origin }));
    }
    serverClose(code, reason, wasClean) {
      this.readyState = 3;
      this.dispatchEvent(new CloseEvent('close', { code, reason, wasClean }));
    }
  }
  ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach((name, value) => {
    Object.defineProperty(NativeWebSocket, name, { value, enumerable: true });
    Object.defineProperty(NativeWebSocket.prototype, name, { value, enumerable: true });
  });

  function fetch(...args) {
    fetchCalls.push(args);
    return Promise.resolve('native fetch response');
  }

  const window = {
    document,
    location: { href },
    WebSocket: NativeWebSocket,
    fetch,
    Blob,
    CloseEvent,
    CustomEvent,
    DOMException,
    Event,
    EventTarget,
    MessageEvent,
    Request,
    Response,
    TextDecoder,
    TextEncoder,
    URL,
    setTimeout,
  };
  return { window, document, NativeWebSocket, nativeSockets, fetchCalls };
}

/** A `chrome.events.Event` stand-in. */
export class ChromeEvent {
  #listeners = [];
  addListener(listener) {
    this.#listeners.push(listener);
  }
  removeListener(listener) {
    this.#listeners = this.#listeners.filter((l) => l !== listener);
  }
  hasListener(listener) {
    return this.#listeners.includes(listener);
  }
  fire(...args) {
    for (const listener of [...this.#listeners]) listener(...args);
  }
}

/** A `runtime.Port` stand-in. The test drives the far end with `deliver` and `drop`. */
export class FakePort {
  constructor(name, sender) {
    this.name = name;
    this.sender = sender;
    this.onMessage = new ChromeEvent();
    this.onDisconnect = new ChromeEvent();
    this.posted = [];
    this.connected = true;
    this.disconnectedByOwner = false;
    // Set to make `postMessage` throw, as for a message over the browser's size limit.
    this.failPost = false;
  }
  postMessage(message) {
    if (!this.connected) throw new Error('Attempting to use a disconnected port object');
    if (this.failPost) throw new Error('Message exceeds maximum allowed size of 64MB.');
    this.posted.push(structuredClone(message));
  }
  disconnect() {
    this.connected = false;
    this.disconnectedByOwner = true;
  }
  /** The far end sends `message`. */
  deliver(message) {
    this.onMessage.fire(structuredClone(message), this);
  }
  /** The far end goes away (`runtime.lastError` set to `error` during the event, if any). */
  drop(runtime, error) {
    this.connected = false;
    if (runtime && error) runtime.lastError = { message: error };
    try {
      this.onDisconnect.fire(this);
    } finally {
      if (runtime) runtime.lastError = undefined;
    }
  }
}

/** The content script side: `window`/`document` and a `chrome.runtime` with `connect`. */
export function contentWindow({ document = new EventTarget() } = {}) {
  const ports = [];
  const runtime = {
    lastError: undefined,
    failConnect: false,
    connect(info) {
      if (runtime.failConnect) throw new Error('Extension context invalidated.');
      const port = new FakePort(info.name);
      ports.push(port);
      return port;
    },
  };
  const window = { document, CustomEvent };
  return { window, document, runtime, ports };
}

/** The background side: `chrome` with `runtime.connectNative` and `scripting`. */
export function backgroundChrome() {
  const natives = [];
  const registered = new Map();
  const scriptingCalls = [];
  const runtime = {
    lastError: undefined,
    onConnect: new ChromeEvent(),
    onInstalled: new ChromeEvent(),
    onStartup: new ChromeEvent(),
    connectNative(name) {
      const port = new FakePort(name);
      natives.push(port);
      return port;
    },
  };
  const scripting = {
    async getRegisteredContentScripts(filter) {
      scriptingCalls.push(['get', structuredClone(filter)]);
      return [...registered.values()].filter((s) => !filter?.ids || filter.ids.includes(s.id));
    },
    async registerContentScripts(scripts) {
      scriptingCalls.push(['register', structuredClone(scripts)]);
      for (const s of scripts) {
        if (registered.has(s.id)) throw new Error(`Duplicate script ID '${s.id}'`);
        registered.set(s.id, structuredClone(s));
      }
    },
    async updateContentScripts(scripts) {
      scriptingCalls.push(['update', structuredClone(scripts)]);
      for (const s of scripts) registered.set(s.id, structuredClone(s));
    },
  };
  const chrome = { runtime, scripting };
  return {
    chrome,
    runtime,
    natives,
    registered,
    scriptingCalls,
    /** A bridge content script connects with this `MessageSender`. */
    connectBridge(sender) {
      const port = new FakePort('oncl', sender);
      runtime.onConnect.fire(port);
      return port;
    },
  };
}
