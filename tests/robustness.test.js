const { test, expect, describe, beforeAll, afterAll } = require("bun:test");
const fs = require("fs");
const os = require("os");
const path = require("path");
const E = require("../security-checkup/report/engine.js");
const B = require("../security-checkup/report/baseline.js");
const S = require("../security-checkup/report/scenes.js");
const { questions: Q } = require("../security-checkup/questions/company.json");
const { runPage } = require("./helpers/page.js");

const ROOT = path.join(__dirname, "..");
const REPORT = path.join(ROOT, "security-checkup", "report");
const TODAY = "2026-10-24";
const fx = (n) => JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", n), "utf8"));
const byId = Object.fromEntries(S.map((s) => [s.id, s]));
const skill = fs.readFileSync(path.join(ROOT, "security-checkup", "SKILL.md"), "utf8");

// 手元の見本の PC を「全部良い」状態にしたもの（Windows 11 25H2・新しいブラウザ）
function goodPc(label) {
  const pc = fx("pc-windows-ok.json");
  pc.label = label || "営業 1";
  pc.checkedAt = "2026-10-22";
  pc.osVersion = "10.0.26200";
  pc.checks.os_support.facts.build = "26200";
  pc.checks.browser.facts.browsers = [{ name: "Chrome", version: "157.0.1" }];
  return pc;
}
// SKILL.md の「常に実行する 10 個」の行から ID を読む（SKILL.md と食い違わないようにするため）
function alwaysRunIds() {
  const line = skill.split("\n").find((l) => /^常に実行する \d+ 個の部品:/.test(l));
  expect(line, "SKILL.md に「常に実行する N 個の部品:」の行がある").toBeTruthy();
  return [...line.matchAll(/`([a-z_]+)`/g)].map((m) => m[1]);
}
const GOOD_ANSWERS = {
  backup_exists: "yes", backup_location: "separate", backup_generations: "multiple", backup_restore_tested: "yes",
  departed_accounts_count: "zero", departed_accounts_process: "yes", departed_accounts_days: "within_week", shared_accounts: "none", saas_list: "yes",
  mfa_enabled: "yes", mfa_coverage: "all", saas_admin_known: "yes", email_misdelivery: "yes",
  telework: "no", wifi_guest_separated: "separated", wifi_password_changed: "yes", nas_exists: "no",
  mail_service: "microsoft", cloud_extra: "no",
  incident_contact: "yes", security_owner: "yes", incident_vendor: "yes", incident_procedure: "yes", training: "yes", rules_documented: "yes",
};
const company = (answers, pcs, pcCount, role) => ({ version: 1, createdAt: TODAY, mode: "company", role: role || "admin", literacy: 2, company: { name: "見本", pcCount: pcCount === undefined ? (pcs || []).length : pcCount }, answers, pcs: pcs || [] });
const build = (d) => E.buildReport(d, S, B, TODAY, Q);
const run = (id, d) => byId[id].evaluate(d, { baseline: B, today: TODAY, answers: d.answers || {}, pcs: E.latestPcs(d.pcs) }, E);

describe("C1: SKILL.md の常に実行する部品だけで健全な PC が「わからない」にならない", () => {
  test("常に実行する部品は 10 個で、browser と cloud_sync を含み、vpn_client を含まない", () => {
    const ids = alwaysRunIds();
    expect(ids.length).toBe(10);
    expect(ids).toContain("browser");
    expect(ids).toContain("cloud_sync");
    expect(ids).not.toContain("vpn_client");
    expect([...ids, "vpn_client"].sort()).toEqual([...E.CHECK_IDS].sort());
  });
  test("場面が使う部品はすべて、常に実行する 10 個か vpn_client", () => {
    const src = fs.readFileSync(path.join(REPORT, "scenes.js"), "utf8");
    const used = new Set([...src.matchAll(/pcSig\(ctx, engine, "\w+", "(\w+)"/g)].map((m) => m[1]));
    expect(used.size).toBeGreaterThan(5);
    const allowed = [...alwaysRunIds(), "vpn_client"];
    for (const id of used) expect(allowed, id).toContain(id);
  });
  function onlyAlwaysRun(pc) {
    const ids = alwaysRunIds();
    pc.checks = Object.fromEntries(Object.entries(pc.checks).filter(([k]) => ids.indexOf(k) >= 0));
    expect(Object.keys(pc.checks).length).toBe(10);
    return pc;
  }
  test("会社診断：PC の場面はすべて守れている、回答が良ければレベル A、「確認できません」の文はない", () => {
    for (const role of ["admin", "manager"]) {
      const d = company(GOOD_ANSWERS, [onlyAlwaysRun(goodPc())], 1, role);
      const r = build(d);
      expect(r.level, role).toBe("A");
      for (const s of r.scenes) {
        expect(s.status, role + ":" + s.id).toBe("ok");
        expect(s.text + s.next, s.id).not.toMatch(/確認できませんでした|確認できていません/);
      }
    }
  });
  test("自分の PC の診断：3 つの場面がすべて守れている（レベル A）", () => {
    const d = { version: 1, createdAt: TODAY, mode: "pc", role: "employee", literacy: 2, company: { name: "", pcCount: 1 }, answers: {}, pcs: [onlyAlwaysRun(goodPc())] };
    const r = build(d);
    expect(r.scenes.map((s) => s.status)).toEqual(["ok", "ok", "ok"]);
    expect(r.level).toBe("A");
    const html = E.renderReport(r, "employee", { mode: "pc", date: TODAY });
    expect(html).not.toContain("わからない");
  });
});

describe("I2: 確認できた PC が会社の台数より少ないと、PC の場面は守れているにならない", () => {
  const ids = ["pc_loss", "antivirus", "os_update"];
  test("38 台中 1 台だけ確認：3 つとも わからない、未確認の台数が文と行動に出る", () => {
    const r = build(company(GOOD_ANSWERS, [goodPc()], 38));
    for (const id of ids) {
      const s = r.scenes.find((x) => x.id === id);
      expect(s.status, id).toBe("unknown");
      expect(s.text, id).toContain("37 台");
      expect(s.text, id).toContain("判断できません");
      expect(s.next, id).toContain("37 台");
    }
    expect(r.level).not.toBe("A");
    expect(r.pcSummary.unchecked).toBe(37);
  });
  test("全台確認と PC モードでは下げない。台数が不明（未指定）なら下げる", () => {
    expect(build(company(GOOD_ANSWERS, [goodPc("a"), goodPc("b")], 2)).scenes.filter((s) => ids.indexOf(s.id) >= 0).map((s) => s.status)).toEqual(["ok", "ok", "ok"]);
    const d = company(GOOD_ANSWERS, [goodPc()], 1);
    delete d.company.pcCount;
    expect(build(d).scenes.find((s) => s.id === "pc_loss").status).toBe("unknown");
    const pcMode = { ...company({}, [goodPc()], 38), mode: "pc", role: "employee" };
    expect(build(pcMode).scenes.map((s) => s.status)).toEqual(["ok", "ok", "ok"]);
  });
  test("危ない・一部危ないは、台数が足りなくてもそのまま出る", () => {
    const pc = goodPc();
    pc.checks.disk_encryption.facts.encrypted = false;
    const s = build(company(GOOD_ANSWERS, [pc], 38)).scenes.find((x) => x.id === "pc_loss");
    expect(s.status).toBe("bad");
  });
});

describe("I3: 決め手の深掘りが聞かれていない重大な場面は、はい だけでは守れているにならない", () => {
  const pcs = () => [goodPc()];
  const status = (id, answers, role) => {
    const d = company(answers, pcs(), 1, role || "manager");
    return build(d).scenes.find((s) => s.id === id);
  };
  const cases = [
    ["ransomware", { backup_exists: "yes" }, { backup_exists: "yes", backup_location: "separate" }, "confirm_backup"],
    ["departed_accounts", { departed_accounts_process: "yes" }, { departed_accounts_process: "yes", departed_accounts_count: "zero" }, "confirm_departed"],
    ["email_takeover", { mfa_enabled: "yes" }, { mfa_enabled: "yes", mfa_coverage: "all" }, "confirm_mfa"],
    ["remote_intrusion", { telework: "yes" }, { telework: "yes", vpn_used: "no", remote_desktop: "no" }, "confirm_remote"],
  ];
  for (const [id, unasked, asked, key] of cases) {
    test(id + "：聞いていなければ わからない、担当者に確かめる行動を出す。聞いて良ければ守れている", () => {
      const s = status(id, unasked);
      expect(s.status).toBe("unknown");
      expect(s.next).toContain("担当者");
      expect(s.text).toContain("まだ");
      const d = company(unasked, pcs(), 1, "manager");
      expect(run(id, d).facts.signals.map((x) => x.key)).toContain(key);
      const a = status(id, asked, "admin");
      expect(a.status).toBe("ok");
    });
  }
  test("悪い答えは わからない に薄めない（bad・warn はそのまま）", () => {
    expect(status("ransomware", { backup_exists: "no" }).status).toBe("bad");
    expect(status("remote_intrusion", { telework: "yes", vpn_used: "yes", vpn_updated: "no" }).status).toBe("bad");
  });
  test("テレワークなし・MFA なしの答えなど、深掘りが要らない場合は下げない", () => {
    expect(status("remote_intrusion", { telework: "no" }).status).toBe("ok");
    expect(status("email_takeover", { mfa_enabled: "no" }).status).toBe("bad");
  });
  test("経営者だけの回答では office_network がクラウドの方針を「決める」と促さない", () => {
    const pc = goodPc();
    pc.checks.cloud_sync.facts.products = ["Dropbox"];
    const d = company({}, [pc], 1, "manager");
    expect(run("office_network", d).facts.signals.some((x) => x.key === "cloud_sync")).toBe(false);
    const row = build(d).scenes.find((s) => s.id === "office_network");
    expect(row.text + row.next).not.toMatch(/決める|認めた/);
    // 聞いたうえで「わからない」なら、方針なしとして従来どおり出す
    const asked = company({ mail_service: "unknown" }, [pc], 1, "admin");
    expect(run("office_network", asked).facts.signals.some((x) => x.key === "cloud_sync")).toBe(true);
  });
});

describe("M1・M2・M4・M5: 文言", () => {
  test("PC モードの文に「ため」の後の読点がある", () => {
    const pc = goodPc();
    pc.checks.disk_encryption = { facts: {}, unavailable: "error" };
    pc.checks.os_update = { facts: {}, unavailable: "needs_admin" };
    const d = { version: 1, createdAt: TODAY, mode: "pc", role: "employee", company: { name: "", pcCount: 1 }, answers: {}, pcs: [pc] };
    const r = build(d);
    const all = r.scenes.map((s) => s.text).join("");
    expect(all).toContain("読み取りに失敗したため、ディスクの暗号化を");
    expect(all).toContain("管理者権限が必要なため、OS の更新を");
    expect(all).not.toMatch(/ため(?!、)[^、]*を確認できませんでした/);
  });
  test("PC モード（本人向け）の行動に、担当者向けの「もう一度診断を動かしてもらう」を出さない", () => {
    const pc = goodPc();
    pc.checks.disk_encryption = { facts: {}, unavailable: "error" };
    pc.checks.screen_lock = { facts: {}, unavailable: "needs_admin" };
    for (const role of ["employee", "admin", "manager"]) {
      const d = { version: 1, createdAt: TODAY, mode: "pc", role, company: { name: "", pcCount: 1 }, answers: {}, pcs: [pc] };
      const html = E.renderReport(build(d), role, { mode: "pc" });
      expect(html, role).not.toContain("動かしてもらう");
      expect(html, role).not.toContain("見てもらう");
      expect(html, role).toContain("担当者に伝える");
      expect(html, role).not.toContain("経営者への質問だけで");
    }
    // 会社診断（1 台だけ確認した場合）では従来どおり
    const c = company({}, [pc], 1);
    expect(build(c).scenes.find((s) => s.id === "pc_loss").next).toMatch(/診断を動かしてもらう|見てもらう/);
  });
  test("レベルの注意書きは重複せず、レベルの文字が A〜E で色分けされる", () => {
    const html = E.renderReport(build(company(GOOD_ANSWERS, [goodPc()], 1)), "admin");
    expect(html).toContain("レベルは A〜E の目安で、安全を保証するものではありません。");
    expect(html).not.toContain("目安です。目安で");
    for (const lv of ["A", "B", "C", "D", "E"]) {
      const h = E.renderReport({ level: lv, scenes: [], asklist: [], pcSummary: {}, baselineAsOf: "x" }, "admin");
      expect(h).toContain('class="grade g-' + lv + '"');
    }
    for (const f of ["report.html", "asklist.html", "pcs.html"]) {
      const css = fs.readFileSync(path.join(REPORT, f), "utf8");
      for (const lv of ["A", "B", "C", "D", "E"]) expect(css, f + lv).toContain(".grade.g-" + lv);
      expect(css, f).not.toMatch(/\.level \.grade \{[^}]*var\(--warn\)/);
    }
  });
  test("日付を二重にエスケープしない（読めない日付に & があっても &amp;amp; にならない）", () => {
    const html = E.renderReport(build(company({}, [], 0)), "admin", { date: "a&b", mode: "company" });
    expect(html).toContain("a&amp;b 診断");
    expect(html).not.toContain("&amp;amp;");
    const d = company({}, [{ ...goodPc(), checkedAt: "x&y" }], 1);
    const p = E.renderPcs(d, { baseline: B, today: TODAY });
    expect(p).toContain("x&amp;y 確認");
    expect(p).not.toContain("&amp;amp;");
  });
  test("reason が constructor のような名前でも、文言の表に引っかからない", () => {
    const pc = goodPc();
    pc.checks.firewall = { facts: {}, unavailable: "constructor" };
    const html = E.renderPcs(company({}, [pc], 1), { baseline: B, today: TODAY });
    expect(html).not.toContain("native code");
  });
});

describe("I4: 形の崩れた結果でも例外を出さない", () => {
  const ctx = { baseline: B, today: TODAY, answers: {}, allowedCloud: [] };
  test("evaluateCheck は products・browsers・facts の形が違っても わからない / 判定を返す", () => {
    const bad = ["x", {}, 5, null, [1, "a", null], true];
    for (const v of bad) {
      for (const [id, key] of [["antivirus", "products"], ["vpn_client", "products"], ["cloud_sync", "products"], ["browser", "browsers"]]) {
        const r = E.evaluateCheck(id, { facts: { [key]: v }, unavailable: null }, ctx);
        expect(["ok", "warn", "bad", "unknown"], id + JSON.stringify(v)).toContain(r.status);
      }
      expect(["ok", "warn", "bad", "unknown"]).toContain(E.evaluateCheck("os_update", { facts: v, unavailable: null }, ctx).status);
      expect(E.evaluateCheck("firewall", v, ctx).status).toBeDefined();
    }
    expect(E.evaluateCheck("antivirus", { facts: { products: "x" }, unavailable: null }, ctx).status).toBe("bad");
    expect(E.evaluateCheck("vpn_client", { facts: { products: {} }, unavailable: null }, ctx).status).toBe("unknown");
    expect(E.evaluateCheck("firewall", "x", ctx)).toEqual({ status: "unknown", reason: "error" });
    expect(E.evaluateCheck("firewall", { facts: {}, unavailable: { a: 1 } }, ctx)).toEqual({ status: "unknown", reason: "error" });
    expect(E.evaluateCheck("toString", { facts: {}, unavailable: null }, ctx).reason).toBe("unknown_check");
  });
  const MALFORMED_PCS = [
    "x", null, 5, [1, 2], { label: "チェックなし" }, { label: "checks が文字列", checks: "x" },
    { label: "壊れた中身", checkedAt: "2026-10-22", os: "windows", checks: {
      antivirus: { facts: { products: "x" } }, browser: { facts: { browsers: {} } }, vpn_client: { facts: { products: {} } },
      cloud_sync: "str", disk_encryption: 7, firewall: { facts: { enabled: "yes" }, unavailable: "constructor" }, screen_lock: null,
    } },
  ];
  test("buildReport と 3 つの描画は、崩れた PC・答え・会社情報でも例外を出さない", () => {
    const d = company(GOOD_ANSWERS, MALFORMED_PCS, 8);
    const r = build(d);
    expect(r.pcSummary.checked).toBe(1);
    expect(r.pcSummary.unreadable).toBe(6);
    const html = E.renderReport(r, "admin", { name: "見本", date: TODAY, mode: "company" });
    expect(html).toContain("読めなかった社員の結果ファイルが 6 件");
    expect(E.renderAsklist(r, {})).toContain("聞くことリスト");
    const p = E.renderPcs(d, { baseline: B, today: TODAY });
    expect(p).toContain("壊れた中身");
    expect(p).toContain("読めなかった社員の結果ファイルが 6 件");
    for (const bad of [undefined, null, "x", 5, [], {}, { pcs: "x", answers: "y", company: 5, mode: "company" }, { pcs: {}, answers: [] }]) {
      expect(() => E.renderReport(E.buildReport(bad, S, B, TODAY, Q), "admin", {})).not.toThrow();
      expect(() => E.renderPcs(bad, { baseline: B, today: TODAY })).not.toThrow();
    }
    expect(() => E.renderReport({}, "admin")).not.toThrow();
    expect(() => E.renderAsklist({}, undefined)).not.toThrow();
  });
  test("評価で例外を出す場面があっても、その場面だけ わからない になる", () => {
    const boom = { id: "boom", title: "壊れた場面", critical: false, pcScene: false, evaluate() { throw new Error("x"); }, text: {}, next: {} };
    const r = E.buildReport(company({}, [], 0), [boom, byId.pc_loss], B, TODAY, Q);
    expect(r.scenes[0].status).toBe("unknown");
    expect(r.scenes.length).toBe(2);
  });
  test("mergePcs は 1 件ずつ読み、読めないものを数える", () => {
    const d = { pcs: [] };
    const bad = E.mergePcs(d, [JSON.stringify(goodPc()), "{not json", JSON.stringify({ a: 1 }), JSON.stringify([1]), "null", JSON.stringify("x"), { label: "obj", checks: {} }]);
    expect(bad).toBe(5);
    expect(d.pcs.length).toBe(2);
    expect(d.unreadablePcFiles).toBe(5);
    expect(E.mergePcs({ pcs: "x" }, undefined)).toBe(0);
    expect(E.mergePcs({}, "notarray")).toBe(1);
    expect(E.mergePcs(null, [])).toBe(0);
  });
});

describe("ページ：データがない・壊れている・社員の結果ファイルが壊れていても白紙にならない", () => {
  let dir;
  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sc-page-"));
    for (const f of ["baseline.js", "engine.js", "scenes.js", "report.html", "asklist.html", "pcs.html"]) fs.copyFileSync(path.join(REPORT, f), path.join(dir, f));
    fs.writeFileSync(path.join(dir, "questions.js"), "window.SC_QUESTIONS = " + JSON.stringify({ questions: Q }) + ";");
  });
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));
  const put = (name, text) => (text === null ? fs.rmSync(path.join(dir, name), { force: true }) : fs.writeFileSync(path.join(dir, name), text));
  const PAGES = ["report.html", "asklist.html", "pcs.html"];

  test("data.js がない・中身が壊れている：どのページも、固定の案内文を出す", () => {
    put("pcs.js", null);
    put("data.js", null);
    for (const f of PAGES) expect(runPage(f, dir).html, f).toContain("レポートを表示できませんでした");
    put("data.js", "window.SC_DATA = 5;");
    for (const f of PAGES) expect(runPage(f, dir).html, f).toContain("レポートを表示できませんでした");
    put("data.js", "window.SC_DATA = { mode: 'company', pcs: 'x', answers: 5, company: 7 };");
    for (const f of PAGES) expect(runPage(f, dir).html, f).not.toBe("");
  });
  test("pcs.js がなくても表示できる（任意）。あれば足される", () => {
    const d = company(GOOD_ANSWERS, [], 2);
    put("data.js", "window.SC_DATA = " + JSON.stringify(d) + ";");
    put("pcs.js", null);
    expect(runPage("report.html", dir).html).toContain("PC 2 台中 0 台を確認");
    put("pcs.js", "window.SC_PCS = " + JSON.stringify([JSON.stringify(goodPc("a")), JSON.stringify(goodPc("b"))]) + ";");
    expect(runPage("report.html", dir).html).toContain("PC 2 台中 2 台を確認");
    expect(runPage("pcs.html", dir).html).toContain("確認できた PC 2 台");
  });
  test("敵対的な社員ファイル：実行されず、ページは壊れず、エスケープされ、読めない件数が出る", () => {
    const evil = { ...goodPc("<img src=x onerror=alert(1)>"), os: "windows" };
    evil.checks.firewall = { facts: { enabled: true }, unavailable: null };
    const files = [
      JSON.stringify(goodPc("普通")),
      JSON.stringify(evil),
      "{ this is not json </script><script>globalThis.pwned=1</script>",
      '{"label":"line\\u2028sep","checks":{}}'.replace("\\u2028", " "),
      JSON.stringify({ a: 1 }),
      "[1,2,3]",
      "<script>globalThis.pwned=2</script>",
    ];
    // runner と同じ形式（JS の文字列にして、< と U+2028 を escape）で書く
    const lit = (t) => JSON.stringify(t).replace(/</g, "\\u003c").replace(new RegExp("\\u2028", "g"), "\\\\u2028").replace(new RegExp("\\u2029", "g"), "\\\\u2029");
    put("pcs.js", "window.SC_PCS = [\n" + files.map(lit).join(",\n") + "\n];\n");
    put("data.js", "window.SC_DATA = " + JSON.stringify(company(GOOD_ANSWERS, [], 4)) + ";");
    expect(fs.readFileSync(path.join(dir, "pcs.js"), "utf8")).not.toContain("</script");
    for (const f of PAGES) {
      const out = runPage(f, dir);
      expect(out.sandbox.pwned, f).toBeUndefined();
      expect(out.html, f).not.toContain("レポートを表示できませんでした");
      expect(out.html, f).not.toMatch(/<img|<script/);
    }
    const rep = runPage("report.html", dir).html;
    expect(rep).toContain("読めなかった社員の結果ファイルが 4 件");
    expect(rep).toContain("PC 4 台中 3 台を確認");
    const pcs = runPage("pcs.html", dir).html;
    expect(pcs).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(pcs).toContain("読めなかった社員の結果ファイルが 4 件");
    expect(pcs).toContain("普通");
  });
});
