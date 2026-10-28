const { test, expect, describe } = require("bun:test");
const E = require("../security-checkup/report/engine.js");
const B = require("../security-checkup/report/baseline.js");
const fs = require("fs");
const path = require("path");

const TODAY = "2026-10-24";
const ctx = { baseline: B, today: TODAY, answers: {} };
const fx = (n) => JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", n), "utf8"));
const res = (facts, unavailable = null) => ({ facts, unavailable });

describe("evaluateCheck antivirus", () => {
  test("Defender disabled but third-party enabled with fresh definitions -> ok", () => {
    const r = E.evaluateCheck("antivirus", res({
      products: [{ name: "Windows Defender", enabled: false, upToDate: false }, { name: "ESET", enabled: true, upToDate: true }],
      definitionsUpdatedAt: "2026-10-21", lastScanAt: "2026-10-20",
    }), ctx);
    expect(r.status).toBe("ok");
  });
  test("no enabled product -> bad", () => {
    const r = E.evaluateCheck("antivirus", res({ products: [{ name: "Windows Defender", enabled: false, upToDate: false }], definitionsUpdatedAt: "2026-10-21", lastScanAt: null }), ctx);
    expect(r).toEqual({ status: "bad", reason: "no_product" });
    expect(E.evaluateCheck("antivirus", res({ products: [] }), ctx).status).toBe("bad");
  });
  test("definitions 20 days old -> warn; 40 days -> bad; boundaries 7 ok / 30 warn", () => {
    const mk = (d) => res({ products: [{ name: "X", enabled: true, upToDate: true }], definitionsUpdatedAt: d, lastScanAt: null });
    expect(E.evaluateCheck("antivirus", mk("2026-10-04"), ctx).status).toBe("warn");
    expect(E.evaluateCheck("antivirus", mk("2026-09-14"), ctx).status).toBe("bad");
    expect(E.evaluateCheck("antivirus", mk("2026-10-17"), ctx).status).toBe("ok");
    expect(E.evaluateCheck("antivirus", mk("2026-09-24"), ctx).status).toBe("warn");
  });
  test("last scan older than 30 days lowers ok to warn", () => {
    const r = E.evaluateCheck("antivirus", res({ products: [{ name: "X", enabled: true, upToDate: true }], definitionsUpdatedAt: "2026-10-23", lastScanAt: "2026-09-01" }), ctx);
    expect(r.status).toBe("warn");
    expect(r.reason).toBe("scan_stale");
  });
});

describe("evaluateCheck others", () => {
  test("unavailable -> unknown with reason", () => {
    expect(E.evaluateCheck("disk_encryption", { facts: {}, unavailable: "needs_admin" }, ctx)).toEqual({ status: "unknown", reason: "needs_admin" });
  });
  test("missing result / unknown check id do not throw", () => {
    expect(E.evaluateCheck("firewall", undefined, ctx).status).toBe("unknown");
    expect(E.evaluateCheck("nope", res({}), ctx).status).toBe("unknown");
  });
  test("disk_encryption", () => {
    expect(E.evaluateCheck("disk_encryption", res({ encrypted: true }), ctx).status).toBe("ok");
    expect(E.evaluateCheck("disk_encryption", res({ encrypted: false }), ctx).status).toBe("bad");
    expect(E.evaluateCheck("disk_encryption", res({ encrypted: null }), ctx).status).toBe("unknown");
  });
  test("os_update thresholds", () => {
    const f = (d) => E.evaluateCheck("os_update", res({ lastInstalledAt: d, pendingCount: 0 }), ctx).status;
    expect(f("2026-10-01")).toBe("ok");
    expect(f("2026-09-10")).toBe("warn");
    expect(f("2026-07-01")).toBe("bad");
    expect(f(null)).toBe("unknown");
  });
  test("os_support windows build / mac major / unmatched / future end", () => {
    const w = (build, today) => E.evaluateCheck("os_support", res({ name: "Windows", version: "x", build }), { ...ctx, os: "windows", today });
    expect(w("19045", TODAY)).toEqual({ status: "bad", reason: "past_end_of_support" });
    expect(w("10.0.26100.9711", "2026-10-01").status).toBe("warn");
    expect(w("26100", "2026-10-13").status).toBe("bad");
    expect(w("26200", TODAY).status).toBe("ok");
    expect(w("99999", TODAY).status).toBe("unknown");
    const m = (version) => E.evaluateCheck("os_support", res({ name: "macOS", version, build: null }), { ...ctx, os: "mac" });
    expect(m("26.7.1").status).toBe("ok");
    expect(m("13.6").status).toBe("bad");
    expect(m("1.0").status).toBe("unknown");
  });
  test("firewall, local_admin, remote_access", () => {
    expect(E.evaluateCheck("firewall", res({ enabled: true }), ctx).status).toBe("ok");
    expect(E.evaluateCheck("firewall", res({ enabled: false }), ctx).status).toBe("warn");
    expect(E.evaluateCheck("local_admin", res({ isAdmin: false }), ctx).status).toBe("ok");
    expect(E.evaluateCheck("local_admin", res({ isAdmin: true }), ctx).status).toBe("warn");
    expect(E.evaluateCheck("remote_access", res({ rdpEnabled: false, sshEnabled: false, screenSharingEnabled: null }), ctx).status).toBe("ok");
    expect(E.evaluateCheck("remote_access", res({ rdpEnabled: true, sshEnabled: false, screenSharingEnabled: null }), ctx).status).toBe("warn");
  });
  test("screen_lock", () => {
    const f = (t, p) => E.evaluateCheck("screen_lock", res({ timeoutMinutes: t, requiresPassword: p }), ctx).status;
    expect(f(5, true)).toBe("ok");
    expect(f(10, true)).toBe("ok");
    expect(f(20, true)).toBe("warn");
    expect(f(60, true)).toBe("bad");
    expect(f(5, false)).toBe("bad");
    expect(f(null, true)).toBe("unknown");
  });
  test("vpn_client: none unknown, no baseline ok, below min warn", () => {
    expect(E.evaluateCheck("vpn_client", res({ products: [] }), ctx).status).toBe("unknown");
    expect(E.evaluateCheck("vpn_client", res({ products: [{ name: "FortiClient", version: "7.2.4" }] }), ctx)).toEqual({ status: "ok", reason: "no_baseline" });
    const b2 = { ...B, vpnMinVersion: { forticlient: "7.2.5" } };
    expect(E.evaluateCheck("vpn_client", res({ products: [{ name: "FortiClient", version: "7.2.4" }] }), { ...ctx, baseline: b2 }).status).toBe("warn");
    expect(E.evaluateCheck("vpn_client", res({ products: [{ name: "FortiClient", version: "7.10.0" }] }), { ...ctx, baseline: b2 }).status).toBe("ok");
  });
  test("cloud_sync: allowed list", () => {
    const f = (p, allowed) => E.evaluateCheck("cloud_sync", res({ products: p }), { ...ctx, allowedCloud: allowed }).status;
    expect(f(["OneDrive"], ["onedrive"])).toBe("ok");
    expect(f(["OneDrive", "Dropbox"], ["OneDrive"])).toBe("warn");
    expect(f([], ["OneDrive"])).toBe("ok");
    expect(f(["Dropbox"], undefined)).toBe("unknown");
  });
  test("browser", () => {
    const f = (b) => E.evaluateCheck("browser", res({ browsers: b }), ctx).status;
    expect(f([{ name: "Chrome", version: "157.0.1" }, { name: "Edge", version: "154.0" }])).toBe("ok");
    expect(f([{ name: "Chrome", version: "130.0.6723.70" }])).toBe("warn");
    expect(f([])).toBe("unknown");
  });
});

describe("latestPcs / aggregatePcs", () => {
  test("latestPcs keeps newest per label", () => {
    const a = { ...fx("pc-windows-ok.json"), checkedAt: "2026-10-01" };
    const b = { ...fx("pc-windows-ok.json"), checkedAt: "2026-10-24" };
    const c = { ...fx("pc-windows-ok.json"), label: "佐藤", checkedAt: "2026-10-02" };
    const r = E.latestPcs([b, a, c]);
    expect(r.length).toBe(2);
    expect(r.find((p) => p.label === "山田").checkedAt).toBe("2026-10-24");
    expect(E.latestPcs([a, b]).length).toBe(1);
    expect(E.latestPcs(undefined)).toEqual([]);
  });
  test("empty -> unknown, checked 0", () => {
    expect(E.aggregatePcs([], "antivirus", ctx)).toEqual({ status: "unknown", counts: { ok: 0, warn: 0, bad: 0, unknown: 0 }, checked: 0 });
  });
  const pcWith = (i, enc) => ({ version: 1, label: "p" + i, checkedAt: TODAY, os: "windows", osVersion: "10.0.26100", checks: { disk_encryption: res({ encrypted: enc }) } });
  test("6 of 31 bad -> warn; half bad -> bad; all ok -> ok", () => {
    const pcs = Array.from({ length: 31 }, (_, i) => pcWith(i, i >= 6));
    const r = E.aggregatePcs(pcs, "disk_encryption", ctx);
    expect(r.status).toBe("warn");
    expect(r.counts).toEqual({ ok: 25, warn: 0, bad: 6, unknown: 0 });
    expect(r.checked).toBe(31);
    expect(E.aggregatePcs([pcWith(1, false), pcWith(2, true)], "disk_encryption", ctx).status).toBe("bad");
    expect(E.aggregatePcs([pcWith(1, true), pcWith(2, true)], "disk_encryption", ctx).status).toBe("ok");
  });
  test("unknown present without bad/warn -> unknown", () => {
    expect(E.aggregatePcs([pcWith(1, true), pcWith(2, null)], "disk_encryption", ctx).status).toBe("unknown");
  });
  test("old-format PcResult (missing id) counts as unknown; one with no checks object at all is unreadable and not counted", () => {
    const noChecks = { version: 1, label: "古い", checkedAt: TODAY, os: "windows" };
    const missing = { version: 1, label: "欠け", checkedAt: TODAY, os: "windows", checks: {} };
    const r = E.aggregatePcs([missing], "antivirus", ctx);
    expect(r.counts.unknown).toBe(1);
    expect(r.status).toBe("unknown");
    expect(E.latestPcs([noChecks, missing]).length).toBe(1);
    // aggregatePcs given an unreadable entry directly still does not throw and counts it as unknown
    expect(E.aggregatePcs([noChecks, "x", null], "antivirus", ctx).counts.unknown).toBe(3);
  });
  test("fixture mixed pcs aggregate os_support per pc os", () => {
    const r = E.aggregatePcs([fx("pc-windows-ok.json"), fx("pc-mac-mixed.json")], "os_support", ctx);
    expect(r.checked).toBe(2);
  });
});

describe("answerStatus / combine", () => {
  const map = { yes: "ok", partial: "warn", no: "bad" };
  test("mapping, unknown/later, unanswered, arrays", () => {
    expect(E.answerStatus({ q: "yes" }, "q", map)).toBe("ok");
    expect(E.answerStatus({ q: "no" }, "q", map)).toBe("bad");
    expect(E.answerStatus({ q: "later" }, "q", map)).toBe("unknown");
    expect(E.answerStatus({ q: "unknown" }, "q", { ...map, unknown: "ok" })).toBe("unknown");
    expect(E.answerStatus({}, "q", map)).toBe("unknown");
    expect(E.answerStatus({ q: "zzz" }, "q", map)).toBe("unknown");
    expect(E.answerStatus({ q: ["yes", "partial"] }, "q", map)).toBe("warn");
    expect(E.answerStatus({ q: ["yes", "later"] }, "q", map)).toBe("unknown");
  });
  test("combine order", () => {
    expect(E.combine(["ok", "warn", "unknown", "bad"])).toBe("bad");
    expect(E.combine(["ok", "warn", "unknown"])).toBe("unknown");
    expect(E.combine(["ok", "warn"])).toBe("warn");
    expect(E.combine(["ok", "ok"])).toBe("ok");
    expect(E.combine([])).toBe("unknown");
  });
});

describe("computeLevel", () => {
  const s = (critical, status) => ({ critical, status });
  test("A all ok", () => expect(E.computeLevel([s(true, "ok"), s(false, "ok")])).toBe("A"));
  test("B no bad, <=2 warn/unknown", () => expect(E.computeLevel([s(true, "warn"), s(false, "unknown"), s(true, "ok")])).toBe("B"));
  test("C non-critical bad", () => expect(E.computeLevel([s(true, "ok"), s(false, "bad")])).toBe("C"));
  test("C two critical warn/unknown", () => expect(E.computeLevel([s(true, "warn"), s(true, "unknown")])).toBe("C"));
  test("C more than 2 non-critical warn", () => expect(E.computeLevel([s(false, "warn"), s(false, "warn"), s(false, "warn")])).toBe("C"));
  test("D one critical bad", () => expect(E.computeLevel([s(true, "bad"), s(true, "ok"), s(false, "bad")])).toBe("D"));
  test("E two critical bad", () => expect(E.computeLevel([s(true, "bad"), s(true, "bad")])).toBe("E"));
  test("empty -> A? no: unknown-safe", () => expect(["A", "B", "C", "D", "E"]).toContain(E.computeLevel([])));
});

describe("buildReport", () => {
  const stubScenes = [
    {
      id: "pc_loss", title: "PC紛失", critical: true, pcScene: true,
      evaluate: (d, c, eng) => {
        const a = eng.aggregatePcs(c.pcs, "disk_encryption", c);
        return { status: a.status, facts: { n: c.pcs.length } };
      },
      text: { admin: { ok: (f) => "OK " + f.n, warn: (f) => "W " + f.n, bad: () => "B", unknown: (f) => "U " + f.n }, manager: { ok: () => "m-ok", warn: () => "m-w", bad: () => "m-b", unknown: () => "m-u" } },
      next: { ok: () => "n-ok", warn: () => "n-w", bad: () => "n-b", unknown: (f) => "n-u " + f.n },
    },
    {
      id: "backup", title: "バックアップ", critical: true, pcScene: false,
      evaluate: (d, c, eng) => ({ status: eng.answerStatus(c.answers, "backup_exists", { yes: "ok", no: "bad" }), facts: {} }),
      text: { admin: { ok: () => "bk-ok", warn: () => "", bad: () => "bk-bad", unknown: () => "bk-u" } },
      next: { ok: () => "", warn: () => "", bad: () => "bk-next", unknown: () => "bk-nu" },
    },
  ];
  const questions = [
    { id: "backup_exists", text: "バックアップはありますか", howToAsk: "業者に聞く" },
    { id: "other", text: "別の質問", howToAsk: "担当に聞く" },
  ];
  const base = () => ({
    version: 1, createdAt: TODAY, mode: "company", role: "admin", literacy: 2,
    company: { name: "S", pcCount: 38 },
    answers: { backup_exists: "later", other: "unknown", ghost: "later", done: "yes" },
    pcs: [fx("pc-windows-ok.json"), { ...fx("pc-windows-ok.json"), checkedAt: "2026-09-01" }],
  });

  test("deterministic", () => {
    const a = E.buildReport(base(), stubScenes, B, TODAY, questions);
    const b = E.buildReport(base(), stubScenes, B, TODAY, questions);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
  test("pcSummary uses deduped pcs and unchecked = pcCount - checked", () => {
    const r = E.buildReport(base(), stubScenes, B, TODAY, questions);
    expect(r.pcSummary.total).toBe(38);
    expect(r.pcSummary.checked).toBe(1);
    expect(r.pcSummary.unchecked).toBe(37);
    // 見本の PC は Windows 11 24H2（期限切れ）と古いブラウザを含むので要対応
    expect(r.pcSummary.ok).toBe(0);
    expect(r.pcSummary.needsAction).toBe(1);
    // 全項目 ok の PC は ok に数える（VPN 製品なし・クラウド方針なしは不備扱いしない）
    const good = fx("pc-windows-ok.json");
    good.osVersion = "10.0.26200";
    good.checks.os_support.facts.build = "26200";
    good.checks.browser.facts.browsers = [{ name: "Chrome", version: "157.0.1" }];
    good.checks.vpn_client.facts.products = [];
    const r2 = E.buildReport({ ...base(), pcs: [good] }, stubScenes, B, TODAY, questions);
    expect(r2.pcSummary.ok).toBe(1);
    expect(r2.pcSummary.needsAction).toBe(0);
    expect(r.baselineAsOf).toBe(B.asOf);
  });
  test("scene text/next by role and status", () => {
    const all = { ...base(), company: { name: "S", pcCount: 1 } };
    const r = E.buildReport(all, stubScenes, B, TODAY, questions);
    const pc = r.scenes.find((s) => s.id === "pc_loss");
    expect(pc).toEqual({ id: "pc_loss", title: "PC紛失", status: "ok", text: "OK 1", next: "n-ok" });
    expect(r.scenes.find((s) => s.id === "backup").status).toBe("unknown");
    const m = E.buildReport({ ...all, role: "manager" }, stubScenes, B, TODAY, questions);
    expect(m.scenes[0].text).toBe("m-ok");
  });
  test("asklist from unknown/later answers, skipping ids with no question", () => {
    const r = E.buildReport(base(), stubScenes, B, TODAY, questions);
    expect(r.asklist).toEqual([
      { questionId: "backup_exists", text: "バックアップはありますか", howToAsk: "業者に聞く" },
      { questionId: "other", text: "別の質問", howToAsk: "担当に聞く" },
    ]);
    expect(E.buildReport(base(), stubScenes, B, TODAY).asklist).toEqual([]);
  });
  test("zero pcs: pc scene unknown, unchecked = pcCount", () => {
    const d = { ...base(), pcs: [] };
    const r = E.buildReport(d, stubScenes, B, TODAY, questions);
    expect(r.scenes[0].status).toBe("unknown");
    expect(r.pcSummary).toEqual({ total: 38, checked: 0, unchecked: 38, ok: 0, needsAction: 0, unreadable: 0 });
  });
  test("unknown PC count (missing, 0, fewer than checked): ok pc scene becomes unknown", () => {
    const all = { ...base(), company: { name: "S", pcCount: 1 } };
    expect(E.buildReport(all, stubScenes, B, TODAY, questions).scenes.find((s) => s.id === "pc_loss").status).toBe("ok");
    for (const company of [{ name: "S" }, { name: "S", pcCount: 0 }, { name: "S", pcCount: -1 }, { name: "S", pcCount: "x" }]) {
      const r = E.buildReport({ ...all, company }, stubScenes, B, TODAY, questions);
      expect(r.pcSummary.total).toBe(null);
      expect(r.pcSummary.unchecked).toBe(null);
      const pc = r.scenes.find((s) => s.id === "pc_loss");
      expect(pc.status).toBe("unknown");
      expect(pc.text).toContain("台数がわからない");
      const html = E.renderReport(r, "admin", { name: "S", date: TODAY });
      expect(html).toContain("PC 1 台を確認（全体の台数は不明）");
      expect(html).toContain("未確認の PC があるかどうか判断できません");
    }
    const two = E.buildReport({ ...all, company: { name: "S", pcCount: 1 }, pcs: [fx("pc-windows-ok.json"), { ...fx("pc-mac-mixed.json"), label: "別PC" }] }, stubScenes, B, TODAY, questions);
    expect(two.pcSummary.total).toBe(null);
  });
  test("pc mode returns only pcScene scenes", () => {
    const r = E.buildReport({ ...base(), mode: "pc", answers: {} }, stubScenes, B, TODAY, questions);
    expect(r.scenes.map((s) => s.id)).toEqual(["pc_loss"]);
  });
  test("level computed", () => {
    const d = { ...base(), answers: { backup_exists: "no" } };
    expect(E.buildReport(d, stubScenes, B, TODAY, questions).level).toBe("D");
  });
});
