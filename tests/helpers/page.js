// レポートのページ（HTML の <script> 群）を、DOM なしの vm で動かす。innerHTML に入った文字列を返す。
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");

function runPage(htmlFile, dir) {
  const app = { innerHTML: "" };
  const win = {};
  const sandbox = { window: win, document: { getElementById: () => app } };
  const ctx = vm.createContext(sandbox);
  const html = fs.readFileSync(path.join(dir, htmlFile), "utf8");
  const srcs = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
  for (const f of srcs) {
    const p = path.join(dir, f);
    if (fs.existsSync(p)) vm.runInContext(fs.readFileSync(p, "utf8"), ctx); // 無いファイルは、ブラウザの読み込み失敗と同じ（飛ばす）
  }
  const inline = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  vm.runInContext(inline[inline.length - 1], ctx);
  return { html: app.innerHTML, sandbox, ctx };
}

module.exports = { runPage };
