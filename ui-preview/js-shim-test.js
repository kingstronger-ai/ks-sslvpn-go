// 用最小 DOM shim 完整执行 app.js 的启动流程，抓运行时（引用/类型）错误
const fs = require("fs");
const vm = require("vm");

const code = fs.readFileSync(__dirname + "/../backend/webfs/dist/app.js", "utf8");

const storage = {};
const els = {};
function makeEl(id) {
  return {
    id,
    innerHTML: "",
    textContent: "",
    style: {},
    _handlers: {},
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    dataset: {},
    addEventListener(ev, fn) { (this._handlers[ev] ||= []).push(fn); },
    onclick: null,
    setAttribute() {},
    getAttribute() { return null; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    insertAdjacentHTML() {},
    appendChild() { return makeEl("x"); },
    remove() {},
    href: "",
  };
}
const documentMock = {
  title: "",
  body: makeEl("body"),
  getElementById(id) { return (els[id] ||= makeEl(id)); },
  querySelector() { return null; },
  querySelectorAll() { return []; },
  createElement(t) { return makeEl(t); },
};
const sandbox = {
  console,
  document: documentMock,
  localStorage: {
    getItem: k => storage[k] ?? null,
    setItem: (k, v) => { storage[k] = String(v); },
    removeItem: k => { delete storage[k]; },
  },
  location: { pathname: "/", host: "test" },
  fetch: async () => ({ json: async () => ({ code: 1, data: {} }), ok: true }),
  setTimeout, clearTimeout, Date, Math, JSON, String, Number, Boolean, Array, Object,
  Promise, Error, RegExp, encodeURIComponent, decodeURIComponent, isNaN, parseInt, parseFloat,
  navigator: { userAgent: "shim" },
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;

process.on("unhandledRejection", e => {
  console.log("UNHANDLED REJECTION:", e && e.stack || e);
  process.exit(2);
});

(async () => {
  try {
    const script = new vm.Script(code, { filename: "app.js" });
    const ctx = vm.createContext(sandbox);
    script.runInContext(ctx);
    // 等 boot() 的异步链跑完
    await new Promise(r => setTimeout(r, 1200));
    const app = sandbox.document.getElementById("app");
    console.log("BOOT DONE. #app innerHTML length =", app.innerHTML.length);
    console.log("document.title =", JSON.stringify(documentMock.title));
    if (app.innerHTML.length === 0) { console.log("WHITE SCREEN REPRODUCED: #app 为空"); process.exit(3); }
    console.log("首屏片段:", app.innerHTML.slice(0, 120).replace(/\s+/g, " "));
    process.exit(0);
  } catch (e) {
    console.log("BOOT THREW:", e && e.stack || e);
    process.exit(1);
  }
})();
