import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import vm from "node:vm";
import { createRequire } from "node:module";
const { runPage } = createRequire(import.meta.url)("./helpers/page.js");

const ROOT = resolve(import.meta.dir, "..");
const MAC = join(ROOT, "security-checkup/checks/mac");
const SHIMS = join(ROOT, "tests/mac-shims");
const IDS = ["antivirus", "disk_encryption", "os_update", "os_support", "firewall", "screen_lock", "local_admin", "remote_access", "vpn_client", "cloud_sync", "browser"];
const FIXTURE = join(ROOT, "tests/fixtures/diagnosis-company.json");

// tmp is the output root (<docs>/セキュリティ診断): the runner only writes inside it (SC_DOCS_ROOT = docs)
let docs, tmp, apps, home;
beforeAll(() => {
  docs = mkdtempSync(join(tmpdir(), "sc-mac-test-"));
  tmp = join(docs, "セキュリティ診断");
  apps = join(tmp, "Applications");
  home = join(tmp, "home 太郎");
  mkdirSync(apps, { recursive: true });
  mkdirSync(home, { recursive: true });
});
afterAll(() => rmSync(docs, { recursive: true, force: true }));

function env(extra = {}) {
  return {
    ...process.env,
    PATH: SHIMS + ":" + process.env.PATH,
    SC_APPS_DIR: apps,
    SC_HOME: home,
    SC_SOCKETFILTERFW: join(SHIMS, "socketfilterfw"),
    SC_SAFARI_APP: join(tmp, "no-safari.app"),
    SC_XPROTECT_INFO: join(tmp, "no-xprotect-info.plist"),
    SC_DOCS_ROOT: docs,
    ...extra,
  };
}
function run(script, args = [], extra = {}) {
  const r = spawnSync("bash", [script, ...args], { encoding: "utf8", env: env(extra) });
  return { code: r.status, out: r.stdout || "", err: r.stderr || "" };
}
function part(id, extra = {}) {
  const r = run(join(MAC, "parts", id + ".sh"), [], extra);
  expect(r.code).toBe(0);
  expect(r.out.trim().split("\n").length).toBe(1);
  return JSON.parse(r.out.trim());
}
function makeApp(dir, name, version) {
  const app = join(dir, name + ".app");
  mkdirSync(join(app, "Contents"), { recursive: true });
  if (version) writeFileSync(join(app, "Contents", "Info.plist"), `{\n  CFBundleShortVersionString = "${version}";\n}\n`);
  return app;
}

describe("mac parts: shape", () => {
  for (const id of IDS) {
    test("part " + id + " prints one JSON line with facts and unavailable", () => {
      const j = part(id);
      expect(j).toHaveProperty("facts");
      expect(j).toHaveProperty("unavailable");
      expect([null, "needs_admin", "not_supported", "error"]).toContain(j.unavailable);
    });
  }
});

describe("mac parts: facts", () => {
  test("disk_encryption", () => {
    expect(part("disk_encryption")).toEqual({ facts: { encrypted: true }, unavailable: null });
    expect(part("disk_encryption", { SHIM_FDESETUP: "off" }).facts.encrypted).toBe(false);
    expect(part("disk_encryption", { SHIM_FDESETUP: "progress" }).facts.encrypted).toBe(false); // "On." + "Encryption in progress"
    expect(part("disk_encryption", { SHIM_FDESETUP: "offrestart" }).facts.encrypted).toBe(false);
    expect(part("disk_encryption", { SHIM_FDESETUP: "weird" }).unavailable).toBe("not_supported");
    expect(part("disk_encryption", { SHIM_FDESETUP: "fail" }).unavailable).toBe("needs_admin");
  });

  test("firewall", () => {
    expect(part("firewall").facts).toEqual({ enabled: true });
    expect(part("firewall", { SHIM_FW: "0" }).facts).toEqual({ enabled: false });
    expect(part("firewall", { SHIM_FW: "2" }).facts).toEqual({ enabled: true });
    expect(part("firewall", { SHIM_FW: "weird" }).unavailable).toBe("error");
  });

  test("local_admin", () => {
    expect(part("local_admin").facts).toEqual({ isAdmin: true });
    expect(part("local_admin", { SHIM_ID_GN: "staff everyone localaccounts" }).facts).toEqual({ isAdmin: false });
    expect(part("local_admin", { SHIM_ID_GN: "staff administrators" }).facts).toEqual({ isAdmin: false });
  });

  test("os_support", () => {
    expect(part("os_support").facts).toEqual({ name: "macOS", version: "15.6.1", build: "24G90" });
    expect(part("os_support", { SHIM_SW_VERS: "13.6.1", SHIM_SW_BUILD: "22G313" }).facts.version).toBe("13.6.1");
  });

  test("os_update uses only macOS / Security Update entries", () => {
    expect(part("os_update").facts).toEqual({ lastInstalledAt: "2026-10-10", pendingCount: null });
    expect(part("os_update", { SHIM_SYSPROF: "fail" }).unavailable).toBe("error");
  });

  test("remote_access", () => {
    expect(part("remote_access").facts).toEqual({ rdpEnabled: null, sshEnabled: false, screenSharingEnabled: false });
    expect(part("remote_access", { SHIM_LAUNCHCTL: "ssh" }).facts.sshEnabled).toBe(true);
    expect(part("remote_access", { SHIM_LAUNCHCTL: "screen" }).facts.screenSharingEnabled).toBe(true);
    const old = part("remote_access", { SHIM_LAUNCHCTL: "old" }).facts;
    expect(old.sshEnabled).toBe(true);
    expect(old.screenSharingEnabled).toBe(false);
    expect(part("remote_access", { SHIM_LAUNCHCTL: "denied" }).unavailable).toBe("needs_admin");
  });

  test("screen_lock", () => {
    // 10 minutes of display sleep, screen saver at 600 s, password after 300 s -> 10 + 5
    expect(part("screen_lock").facts).toEqual({ timeoutMinutes: 15, requiresPassword: true });
    expect(part("screen_lock", { SHIM_SYSADMINCTL: "immediate" }).facts).toEqual({ timeoutMinutes: 10, requiresPassword: true });
    expect(part("screen_lock", { SHIM_SYSADMINCTL: "delay60", SHIM_SS_IDLE: "120", SHIM_DISPLAYSLEEP: "0" }).facts).toEqual({ timeoutMinutes: 3, requiresPassword: true });
    // no way to start the lock -> no lock
    expect(part("screen_lock", { SHIM_SYSADMINCTL: "immediate", SHIM_SS_IDLE: "none", SHIM_DISPLAYSLEEP: "0" }).facts).toEqual({ timeoutMinutes: null, requiresPassword: false });
    // lock turned off: never 0, never ok
    expect(part("screen_lock", { SHIM_SYSADMINCTL: "off" })).toEqual({ facts: { timeoutMinutes: null, requiresPassword: false }, unavailable: null });
    expect(part("screen_lock", { SHIM_SYSADMINCTL: "weird" }).unavailable).toBe("error");
  });

  test("screen_lock: sysadminctl permission error -> needs_admin (exit status 1 or 0)", () => {
    for (const mode of ["denied", "denied0"]) {
      const j = part("screen_lock", { SHIM_SYSADMINCTL: mode });
      expect(j).toEqual({ facts: {}, unavailable: "needs_admin" });
    }
  });

  test("antivirus: XProtect only", () => {
    const j = part("antivirus");
    expect(j.unavailable).toBe(null);
    expect(j.facts.products).toEqual([{ name: "XProtect", enabled: true, upToDate: null }]);
    expect(j.facts.definitionsUpdatedAt).toBe("2026-10-20");
    expect(j.facts.lastScanAt).toBe(null);
  });

  test("antivirus: XProtect.bundle date is used when newer than the install history (macOS 15+)", () => {
    const info = join(tmp, "XProtect-Info.plist");
    writeFileSync(info, "{}");
    // newer bundle date wins
    expect(part("antivirus", { SC_XPROTECT_INFO: info, SHIM_STAT_DAY: "2026-10-23" }).facts.definitionsUpdatedAt).toBe("2026-10-23");
    // older bundle date: the history date (2026-10-20) wins
    expect(part("antivirus", { SC_XPROTECT_INFO: info, SHIM_STAT_DAY: "2026-09-01" }).facts.definitionsUpdatedAt).toBe("2026-10-20");
    // history empty / failing: the bundle date alone is used
    const empty = join(tmp, "empty-history.json");
    writeFileSync(empty, '{ "SPInstallHistoryDataType" : [ ] }');
    expect(part("antivirus", { SC_XPROTECT_INFO: info, SHIM_STAT_DAY: "2026-10-22", SHIM_SYSPROF_FILE: empty }).facts.definitionsUpdatedAt).toBe("2026-10-22");
    expect(part("antivirus", { SC_XPROTECT_INFO: info, SHIM_STAT_DAY: "2026-10-22", SHIM_SYSPROF: "fail" }).facts.definitionsUpdatedAt).toBe("2026-10-22");
    // missing file, failing stat, or garbage output: ignored
    expect(part("antivirus", { SHIM_STAT_DAY: "2026-10-23" }).facts.definitionsUpdatedAt).toBe("2026-10-20");
    expect(part("antivirus", { SC_XPROTECT_INFO: info }).facts.definitionsUpdatedAt).toBe("2026-10-20");
    expect(part("antivirus", { SC_XPROTECT_INFO: info, SHIM_STAT_DAY: "garbage" }).facts.definitionsUpdatedAt).toBe("2026-10-20");
    // GNU/Linux stat (stat -f means filesystem status there) fails cleanly
    const linux = part("antivirus", { SC_XPROTECT_INFO: info, SHIM_STAT: "real" });
    expect(linux.unavailable).toBe(null);
    expect(linux.facts.definitionsUpdatedAt).toBe("2026-10-20");
  });

  test("antivirus: history unreadable keeps the product list", () => {
    const j = part("antivirus", { SHIM_SYSPROF: "fail" });
    expect(j.unavailable).toBe(null);
    expect(j.facts.definitionsUpdatedAt).toBe(null);
  });

  test("antivirus: third-party product -> XProtect dates not reported", () => {
    makeApp(apps, "ESET Endpoint Security", "9.1");
    try {
      const j = part("antivirus");
      expect(j.facts.products.map((p) => p.name)).toEqual(["XProtect", "ESET Endpoint Security"]);
      expect(j.facts.definitionsUpdatedAt).toBe(null);
      expect(j.facts.lastScanAt).toBe(null);
    } finally {
      rmSync(join(apps, "ESET Endpoint Security.app"), { recursive: true, force: true });
    }
  });

  test("vpn_client / browser read Info.plist, paths with spaces and Japanese", () => {
    const a = join(tmp, "アプリ 一覧");
    mkdirSync(a, { recursive: true });
    makeApp(a, "Tunnelblick", "8.0");
    makeApp(a, "Cisco Secure Client", "5.1.2");
    makeApp(a, "Google Chrome", "157.0.7000.1");
    makeApp(a, "Firefox", "158.0.1");
    makeApp(a, "Safari", "27.0");
    makeApp(a, "Microsoft Edge");
    makeApp(a, "Pages", "14.0");
    const vpn = part("vpn_client", { SC_APPS_DIR: a }).facts.products;
    expect(vpn).toEqual([
      { name: "Cisco Secure Client", version: "5.1.2" },
      { name: "Tunnelblick", version: "8.0" },
    ]);
    const br = part("browser", { SC_APPS_DIR: a }).facts.browsers;
    expect(br).toEqual([
      { name: "Google Chrome", version: "157.0.7000.1" },
      { name: "Mozilla Firefox", version: "158.0.1" },
      { name: "Safari", version: "27.0" },
    ]);
    expect(part("vpn_client").facts.products).toEqual([]);
  });

  test("cloud_sync: only signed-in services, exact names", () => {
    expect(part("cloud_sync").facts.products).toEqual([]);
    // installed apps alone do not count
    makeApp(apps, "OneDrive", "25.1");
    makeApp(apps, "Dropbox", "200.0");
    expect(part("cloud_sync").facts.products).toEqual([]);
    const cs = join(home, "Library", "CloudStorage");
    mkdirSync(join(cs, "GoogleDrive-someone"), { recursive: true });
    mkdirSync(join(cs, "OneDrive-会社 名"), { recursive: true });
    mkdirSync(join(cs, "Box-Box"), { recursive: true });
    mkdirSync(join(home, "Library", "Mobile Documents", "com~apple~CloudDocs"), { recursive: true });
    mkdirSync(join(home, ".dropbox"), { recursive: true });
    writeFileSync(join(home, ".dropbox", "info.json"), "{}");
    expect(part("cloud_sync").facts.products).toEqual(["Google Drive", "OneDrive", "Dropbox", "Box", "iCloud Drive"]);
    rmSync(join(home, "Library"), { recursive: true, force: true });
    rmSync(join(home, ".dropbox"), { recursive: true, force: true });
  });

  test("no personal information in part output", () => {
    const user = process.env.USER || "";
    for (const id of IDS) {
      const r = run(join(MAC, "parts", id + ".sh"));
      if (user.length > 2) expect(r.out.toLowerCase()).not.toContain(user.toLowerCase());
      expect(r.out).not.toContain(home);
    }
  });
});

// Evaluates the written data.js / questions.js in a sandbox with an empty window; returns that window.
function loadJs(...files) {
  const w = {};
  const ctx = vm.createContext({ window: w });
  for (const f of files) vm.runInContext(readFileSync(f, "utf8"), ctx);
  return w;
}

describe("mac run.sh", () => {
  test("check writes a PcResult to a Japanese path with spaces", () => {
    const out = join(tmp, "診断 テスト", "結果.json");
    const r = run(join(MAC, "run.sh"), ["check", "--label", "テスト 太郎", "--checks", IDS.join(","), "--out", out]);
    expect(r.code).toBe(0);
    expect(existsSync(out)).toBe(true);
    const buf = readFileSync(out);
    expect(buf[0]).not.toBe(0xef);
    const j = JSON.parse(buf.toString("utf8"));
    expect(j.version).toBe(1);
    expect(j.label).toBe("テスト 太郎");
    expect(j.os).toBe("mac");
    expect(j.checkedAt).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(j.osVersion).toBe("15.6.1");
    expect(Object.keys(j.checks).sort()).toEqual([...IDS].sort());
    for (const id of IDS) {
      expect(j.checks[id]).toHaveProperty("facts");
      expect(j.checks[id]).toHaveProperty("unavailable");
    }
    expect(j.checks.disk_encryption.facts.encrypted).toBe(true);
  });

  test("check without --checks runs all 11; label with quotes and backslash stays valid JSON", () => {
    const out = join(tmp, "all.json");
    const r = run(join(MAC, "run.sh"), ["check", "--label", 'a"b\\c', "--out", out]);
    expect(r.code).toBe(0);
    const j = JSON.parse(readFileSync(out, "utf8"));
    expect(j.label).toBe('a"b\\c');
    expect(Object.keys(j.checks).length).toBe(11);
  });

  test("unknown or invalid ids -> not_supported", () => {
    const out = join(tmp, "unknown.json");
    const r = run(join(MAC, "run.sh"), ["check", "--label", "x", "--checks", "nope,../etc,Bad", "--out", out]);
    expect(r.code).toBe(0);
    const j = JSON.parse(readFileSync(out, "utf8"));
    for (const id of ["nope", "../etc", "Bad"]) expect(j.checks[id]).toEqual({ facts: {}, unavailable: "not_supported" });
  });

  test("a crashing part and a part printing invalid JSON -> error", () => {
    const parts = join(tmp, "bad parts");
    mkdirSync(parts, { recursive: true });
    writeFileSync(join(parts, "crash.sh"), "#!/bin/bash\necho '{\"facts\":{},\"unavailable\":null}'\nexit 3\n");
    writeFileSync(join(parts, "garbage.sh"), "#!/bin/bash\necho 'hello'\n");
    writeFileSync(join(parts, "unbalanced.sh"), "#!/bin/bash\necho '{\"facts\":{\"a\":[1},\"unavailable\":null}'\n");
    writeFileSync(join(parts, "multi.sh"), "#!/bin/bash\nprintf '{\"facts\":{},\\n\"unavailable\":null}\\n'\n");
    writeFileSync(join(parts, "good.sh"), "#!/bin/bash\necho '{\"facts\":{\"s\":\"a}\\\\\\\"b\"},\"unavailable\":null}'\n");
    const out = join(tmp, "bad.json");
    const r = run(join(MAC, "run.sh"), ["check", "--label", "x", "--checks", "crash,garbage,unbalanced,multi,good", "--out", out], { SC_PARTS_DIR: parts });
    expect(r.code).toBe(0);
    const j = JSON.parse(readFileSync(out, "utf8"));
    for (const id of ["crash", "garbage", "unbalanced", "multi"]) expect(j.checks[id]).toEqual({ facts: {}, unavailable: "error" });
    expect(j.checks.good.unavailable).toBe(null);
  });

  test("check requires --label and --out", () => {
    expect(run(join(MAC, "run.sh"), ["check", "--out", join(tmp, "z.json")]).code).not.toBe(0);
    expect(run(join(MAC, "run.sh"), ["check", "--label", "x"]).code).not.toBe(0);
  });

  test("report copies 9 files (HTML 3 + baseline/engine/scenes + questions/data/pcs .js) into a Japanese path with spaces", () => {
    const outDir = join(tmp, "診断 レポート");
    const log = join(tmp, "open.log");
    const r = run(join(MAC, "run.sh"), ["report", "--data", FIXTURE, "--outdir", outDir, "--no-open"], { SHIM_OPEN_LOG: log });
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out.trim()).report).toBe(join(outDir, "report.html"));
    expect(readdirSync(outDir).sort()).toEqual(["asklist.html", "baseline.js", "data.js", "engine.js", "pcs.html", "pcs.js", "questions.js", "report.html", "scenes.js"]);
    const w = loadJs(join(outDir, "data.js"), join(outDir, "questions.js"));
    expect(readFileSync(join(outDir, "data.js"), "utf8").startsWith("window.SC_DATA = JSON.parse(\"")).toBe(true);
    expect(w.SC_DATA.mode).toBe("company");
    expect(w.SC_DATA).toEqual(JSON.parse(readFileSync(FIXTURE, "utf8")));
    expect(w.SC_QUESTIONS).toEqual(JSON.parse(readFileSync(join(ROOT, "security-checkup/questions/company.json"), "utf8")));
    expect(readFileSync(join(outDir, "engine.js"), "utf8")).toContain("SC_ENGINE");
    expect(existsSync(log)).toBe(false);
    // without --no-open it opens report.html
    const r2 = run(join(MAC, "run.sh"), ["report", "--data", FIXTURE, "--outdir", outDir], { SHIM_OPEN_LOG: log });
    expect(r2.code).toBe(0);
    expect(readFileSync(log, "utf8").trim()).toBe(join(outDir, "report.html"));
  });

  test("report: data is only data (no code runs, whatever the JSON text contains)", () => {
    const evil = '{"a":"x\\"});globalThis.pwned=1;//","b":"</script><script>globalThis.pwned=2</script>","c":"line\\u2028sep\\u2029\\ttab \\\\ back","d":"raw \u2028 \u2029 chars"}';
    const f = join(tmp, "evil data.json");
    writeFileSync(f, evil);
    const outDir = join(tmp, "evil out");
    expect(run(join(MAC, "run.sh"), ["report", "--data", f, "--outdir", outDir, "--no-open"]).code).toBe(0);
    const js = readFileSync(join(outDir, "data.js"), "utf8");
    expect(js).not.toContain("<");
    expect(js).not.toContain("\u2028");
    expect(js).not.toContain("\u2029");
    const sandbox = { window: {}, globalThis: null };
    const ctx = vm.createContext(sandbox);
    vm.runInContext(js, ctx);
    expect(sandbox.window.SC_DATA).toEqual(JSON.parse(evil));
    expect(sandbox.pwned).toBeUndefined();
    expect(vm.runInContext("typeof pwned", ctx)).toBe("undefined");
  });

  test("report rejects data that is a JS expression, not JSON (nothing is written)", () => {
    for (const [i, bad] of ["1;globalThis.pwned=1", '"x"});alert(1)//', '{"a":1});globalThis.pwned=1;//', "{}\n;globalThis.pwned=1"].entries()) {
      const f = join(tmp, "expr" + i + ".json");
      writeFileSync(f, bad);
      const outDir = join(tmp, "expr-out" + i);
      expect(run(join(MAC, "run.sh"), ["report", "--data", f, "--outdir", outDir, "--no-open"]).code).not.toBe(0);
      expect(existsSync(join(outDir, "data.js"))).toBe(false);
    }
  });

  test("check: duplicate ids run once; glob characters in ids are not expanded", () => {
    const out = join(tmp, "dup.json");
    const r = run(join(MAC, "run.sh"), ["check", "--label", "x", "--checks", "firewall,firewall,*,local_admin", "--out", out]);
    expect(r.code).toBe(0);
    const j = JSON.parse(readFileSync(out, "utf8"));
    expect(Object.keys(j.checks)).toEqual(["firewall", "*", "local_admin"]);
    expect(j.checks["*"]).toEqual({ facts: {}, unavailable: "not_supported" });
  });

  test("report --pcs-dir: one literal per *.json (bad JSON and hostile text included), nothing runs, stale results are cleared", () => {
    const dir = join(tmp, "社員 PC結果");
    mkdirSync(dir, { recursive: true });
    const good = JSON.parse(readFileSync(join(ROOT, "tests/fixtures/pc-windows-ok.json"), "utf8"));
    writeFileSync(join(dir, "good.json"), JSON.stringify(good));
    writeFileSync(join(dir, "html label.json"), JSON.stringify({ ...good, label: "<img src=x onerror=alert(1)>" }));
    writeFileSync(join(dir, "bad.json"), '{ not json </script><script>globalThis.pwned=1</script>');
    writeFileSync(join(dir, "sep.json"), '{"label":"a\u2028b","checks":{}}'.replace("\\u2028", "\u2028"));
    writeFileSync(join(dir, "notes.txt"), "not a json file");
    const outDir = join(tmp, "pcs out");
    expect(run(join(MAC, "run.sh"), ["report", "--data", FIXTURE, "--outdir", outDir, "--pcs-dir", dir, "--no-open"]).code).toBe(0);
    const js = readFileSync(join(outDir, "pcs.js"), "utf8");
    expect(js).not.toContain("<");
    expect(js).not.toContain("\u2028");
    expect(js.startsWith("window.SC_PCS = [")).toBe(true);
    const sandbox = { window: {}, globalThis: null };
    vm.runInContext(js, vm.createContext(sandbox));
    expect(sandbox.window.SC_PCS.length).toBe(4);
    expect(sandbox.window.SC_PCS.every((x) => typeof x === "string")).toBe(true);
    expect(sandbox.window.SC_PCS).toContain(readFileSync(join(dir, "bad.json"), "utf8"));
    expect(sandbox.window.SC_PCS.map((x) => { try { return JSON.parse(x).label; } catch (e) { return null; } })).toContain("<img src=x onerror=alert(1)>");
    // the page: each file is parsed on its own; the broken one is counted, the rest still show, and the label is escaped
    for (const f of ["report.html", "pcs.html"]) {
      const page = runPage(f, outDir);
      expect(page.sandbox.pwned, f).toBeUndefined();
      expect(page.html, f).not.toContain("レポートを表示できませんでした");
      expect(page.html, f).not.toMatch(/<img|<script/);
      expect(page.html, f).toContain("読めなかった社員の結果ファイルが 1 件");
    }
    expect(runPage("pcs.html", outDir).html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    // without --pcs-dir a re-run clears the old results
    expect(run(join(MAC, "run.sh"), ["report", "--data", FIXTURE, "--outdir", outDir, "--no-open"]).code).toBe(0);
    expect(readFileSync(join(outDir, "pcs.js"), "utf8").replace(/\s/g, "")).toBe("window.SC_PCS=[];");
    // a missing folder is an error
    expect(run(join(MAC, "run.sh"), ["report", "--data", FIXTURE, "--outdir", join(tmp, "x"), "--pcs-dir", join(tmp, "nope"), "--no-open"]).code).not.toBe(0);
  });

  test("report rejects invalid data", () => {
    const bad = join(tmp, "bad-data.json");
    writeFileSync(bad, '{"mode": [}');
    expect(run(join(MAC, "run.sh"), ["report", "--data", bad, "--outdir", join(tmp, "o"), "--no-open"]).code).not.toBe(0);
  });

  test("paths prints JSON and creates the folders", () => {
    const docs = join(tmp, "ドキュメント 仮");
    const r = run(join(MAC, "run.sh"), ["paths"], { SC_DOCS_ROOT: docs });
    expect(r.code).toBe(0);
    const j = JSON.parse(r.out.trim());
    expect(j.outputRoot).toBe(join(docs, "セキュリティ診断"));
    expect(j.employeeResults).toBe(join(docs, "セキュリティ診断", "社員PC結果"));
    expect(existsSync(j.employeeResults)).toBe(true);
  });
});

describe("bash 3.2 compatibility", () => {
  test("no bash 4+ syntax in the scripts", () => {
    const r = spawnSync("grep", ["-rnE", "declare -A|mapfile|readarray|\\$\\{[a-zA-Z_]+(,,|\\^\\^)\\}|\\[\\[ -v|\\|&", join(MAC, "run.sh"), join(MAC, "parts")], { encoding: "utf8" });
    expect(r.stdout).toBe("");
  });
  test("no sudo and no network tools", () => {
    const r = spawnSync("grep", ["-rnwE", "sudo|curl|wget|softwareupdate|nc", join(MAC, "run.sh"), join(MAC, "parts")], { encoding: "utf8" });
    // comments may mention them; code lines must not
    const code = r.stdout.split("\n").filter((l) => l && !/^[^:]+:\d+:\s*#/.test(l) && !/#.*(sudo|softwareupdate)/.test(l));
    expect(code).toEqual([]);
  });
});

describe("run.sh writes only inside the output root", () => {
  test("--out / --outdir outside the root, with .., relative, or not .json are refused and nothing is written", () => {
    const outside = join(docs, "outside.json");
    const bad = [
      ["check", "--label", "x", "--checks", "firewall", "--out", outside],
      ["check", "--label", "x", "--checks", "firewall", "--out", join(tmp, "..", "escape.json")],
      ["check", "--label", "x", "--checks", "firewall", "--out", "rel.json"],
      ["check", "--label", "x", "--checks", "firewall", "--out", join(tmp, "a.txt")],
      ["check", "--label", "x", "--checks", "firewall", "--out", tmp],
      ["report", "--data", FIXTURE, "--outdir", join(docs, "elsewhere"), "--no-open"],
      ["report", "--data", FIXTURE, "--outdir", join(tmp, "sub", "..", "..", "up"), "--no-open"],
    ];
    for (const args of bad) expect(run(join(MAC, "run.sh"), args).code, args.join(" ")).not.toBe(0);
    expect(existsSync(outside)).toBe(false);
    expect(existsSync(join(docs, "escape.json"))).toBe(false);
    expect(existsSync(join(tmp, "a.txt"))).toBe(false);
    expect(existsSync(join(docs, "elsewhere"))).toBe(false);
    expect(existsSync(join(docs, "up"))).toBe(false);
    expect(run(join(MAC, "run.sh"), ["check", "--label", "x", "--checks", "firewall", "--out", join(tmp, "社員PC結果", "ok.json")]).code).toBe(0);
  });
});
