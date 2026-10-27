// Fake browser environment for the extension unit tests. The scripts under `src/` are classic
// scripts; `loadScript` runs one with `node:vm` and returns the factory it exports through
// `module.exports`. The fakes stand in for the page (`window`, `document`, the browser's own
// `WebSocket`/`fetch`), for a Firefox content-script global (`exportFunction`, `cloneInto`)
// and for `chrome.runtime`/`chrome.scripting`.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

export const HOST_NAME = 'io.github.arynyklas.openncalayer';
const TO_EXT = '__oncl_to_ext';
const TO_PAGE = '__oncl_to_page';
const LINK = '__oncl_link';

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

/**
 * A test end of a link: the frames it received and `send`. With `answerReady` set, it answers
 * `ready` at once, as the real bridge does (the shim checks the bridge is still there that way).
 */
function linkEnd(deliver) {
  const end = {
    frames: [],
    answerReady: false,
    send: deliver,
    receive(frame) {
      end.frames.push(frame);
      if (end.answerReady && frame.t === 'ready') deliver({ t: 'ready' });
    },
  };
  return end;
}

/** One end of the `CustomEvent` channel between the page and the bridge on `document`. */
function eventEnd(document, inbound, outbound) {
  const end = linkEnd((frame) => {
    document.dispatchEvent(new CustomEvent(outbound, { detail: JSON.stringify(frame) }));
  });
  document.addEventListener(inbound, (event) => end.receive(JSON.parse(event.detail)));
  return end;
}

/** The bridge as the shim sees it: frames from the page and a way to answer. */
export const bridgeEnd = (document) => eventEnd(document, TO_EXT, TO_PAGE);

/** The page (shim) as the bridge sees it. */
export const pageEnd = (document) => eventEnd(document, TO_PAGE, TO_EXT);

/** Where shim and bridge meet in a content-script global, as both scripts set it up. */
function linkChannel(sandbox) {
  if (!Object.hasOwn(sandbox, LINK)) Object.defineProperty(sandbox, LINK, { value: { toExt: null, toPage: null } });
  return sandbox[LINK];
}

/** One end of the direct link between a shim and a bridge sharing the content-script global. */
function directEnd(sandbox, inbound, outbound) {
  const channel = linkChannel(sandbox);
  const end = linkEnd((frame) => {
    if (channel[outbound]) channel[outbound](structuredClone(frame));
  });
  channel[inbound] = (frame) => end.receive(structuredClone(frame));
  return end;
}

/** The bridge as a shim in the same content-script global sees it. */
export const bridgeLink = (sandbox) => directEnd(sandbox, 'toExt', 'toPage');

/** A shim in the same content-script global as the bridge sees it. */
export const pageLink = (sandbox) => directEnd(sandbox, 'toPage', 'toExt');

/**
 * A Firefox content-script global for `window`: `exportFunction` and `cloneInto`, recording
 * what they made in `exported` and `cloned`. `window.wrappedJSObject` is `window` itself:
 * the fakes have no Xray wrappers to waive.
 */
export function contentSandbox(window) {
  const exported = new WeakSet();
  const cloned = new WeakSet();
  window.wrappedJSObject = window;
  return {
    exported,
    cloned,
    exportFunction(fn, scope) {
      if (scope !== window) throw new Error('exportFunction into another scope');
      // A forwarder: callable and constructible, `new.target` is not passed on.
      const forwarder = function (...args) {
        return new.target === undefined ? Reflect.apply(fn, this, args) : Reflect.construct(fn, args);
      };
      exported.add(forwarder);
      return forwarder;
    },
    cloneInto(value, scope) {
      if (scope !== window) throw new Error('cloneInto another scope');
      const copy = structuredClone(value);
      cloned.add(copy);
      return copy;
    },
  };
}

/**
 * A page `window` whose own `WebSocket` and `fetch` are recording fakes. With `xray`, also
 * a content-script global (`sandbox`, see `contentSandbox`) for the shim, and page APIs that
 * insist on what Xray vision demands: callbacks the page calls are exported functions, and
 * dictionaries page constructors read were cloned into the page.
 */
export function pageWindow({ href = 'https://site.example/app/', document = new EventTarget(), xray = false } = {}) {
  const nativeSockets = [];
  const fetchCalls = [];
  const socketListeners = []; // [type, listener] of every listener added to a virtual socket
  let checkCallback = () => {};
  let checkDict = () => {};

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
      // Only the shim listens to a native socket (virtual ones share the prototype, and the
      // tests listen to those).
      this.addEventListener = (type, listener, options) => {
        checkCallback(listener, `native socket ${type} listener`);
        EventTarget.prototype.addEventListener.call(this, type, listener, options);
      };
    }
    addEventListener(type, listener, options) {
      socketListeners.push([type, listener]);
      super.addEventListener(type, listener, options);
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

  class PageBlob extends Blob {
    /** A page promise of the text: the page calls its callbacks. */
    text() {
      const text = super.text();
      return {
        then(onText, onError) {
          checkCallback(onText, 'Blob text callback');
          checkCallback(onError, 'Blob error callback');
          return text.then(onText, onError);
        },
      };
    }
  }
  // Page constructors that read a dictionary.
  const withDict = (Base) =>
    class extends Base {
      constructor(type, init) {
        checkDict(init, Base.name);
        super(type, init);
      }
    };
  class PagePromise extends Promise {
    // `then` and friends make plain promises.
    static get [Symbol.species]() {
      return Promise;
    }
    constructor(executor) {
      checkCallback(executor, 'Promise executor');
      super(executor);
    }
  }

  const window = {
    document,
    location: { href },
    WebSocket: NativeWebSocket,
    fetch,
    Blob: PageBlob,
    CloseEvent: withDict(CloseEvent),
    CustomEvent,
    DOMException,
    Event,
    EventTarget,
    MessageEvent: withDict(MessageEvent),
    Object,
    Promise: PagePromise,
    Request,
    Response: withDict(Response),
    TextDecoder,
    TextEncoder,
    TypeError,
    URL,
    setTimeout(callback, ms) {
      checkCallback(callback, 'setTimeout callback');
      return setTimeout(callback, ms);
    },
  };
  const env = { window, document, NativeWebSocket, nativeSockets, fetchCalls, socketListeners };
  if (!xray) return env;
  const sandbox = contentSandbox(window);
  checkCallback = (fn, what) => {
    if (!sandbox.exported.has(fn)) throw new Error(`${what} is not an exported function`);
  };
  checkDict = (init, what) => {
    if (init !== undefined && !sandbox.cloned.has(init)) throw new Error(`${what} dictionary is not cloned into the page`);
  };
  return { ...env, sandbox };
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
