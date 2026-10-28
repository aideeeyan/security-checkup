const { test, expect, describe } = require("bun:test");
const E = require("../security-checkup/report/engine.js");
const B = require("../security-checkup/report/baseline.js");
const S = require("../security-checkup/report/scenes.js");
const Q = require("../security-checkup/questions/company.json").questions;
const fs = require("fs");
const path = require("path");

const fx = (n) => JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", n), "utf8"));
const build = (d) => E.buildReport(d, S.SCENES || S, B, d.createdAt, Q);
const company = fx("diagnosis-company.json");
const pcDiag = fx("diagnosis-pc.json");
const labels = [...new Set(company.pcs.map((p) => p.label))];

describe("renderReport", () => {
  const rep = build(company);
  test("level, disclaimer, baseline date", () => {
    const html = E.renderReport(rep, "admin");
    expect(html).toContain(">" + rep.level + "<");
    expect(html).toContain("目安で、安全を保証するものではありません");
    expect(html).toContain("基準表：" + rep.baselineAsOf + " 時点");
  });
  test("one card per scene with status labels", () => {
    const html = E.renderReport(rep, "admin");
    expect((html.match(/class="scene /g) || []).length).toBe(rep.scenes.length);
    expect(rep.scenes.length).toBe(9);
    const L = { bad: "危ない", warn: "一部危ない", unknown: "わからない", ok: "守れている" };
    rep.scenes.forEach((s) => expect(html).toContain(">" + L[s.status] + "<"));
  });
  test("header shows company, date, PC count", () => {
    const html = E.renderReport(rep, "admin", { name: company.company.name, date: company.createdAt, mode: "company" });
    expect(html).toContain(company.company.name);
    expect(html).toContain("PC " + rep.pcSummary.total + " 台中 " + rep.pcSummary.checked + " 台を確認");
  });
  test("checked 0 -> unchecked note", () => {
    const r = build(Object.assign({}, company, { pcs: [] }));
    const html = E.renderReport(r, "admin");
    expect(html).toContain("未確認");
    expect(html).toContain("自分の PC の診断");
    expect(html).toContain("社員PC結果");
  });
  test("unchecked > 0 shows note, none when all checked", () => {
    const some = Object.assign({}, rep, { pcSummary: Object.assign({}, rep.pcSummary, { unchecked: 3 }) });
    expect(E.renderReport(some, "admin")).toContain("社員PC結果");
    const none = Object.assign({}, rep, { pcSummary: { total: 2, checked: 2, unchecked: 0, ok: 2, needsAction: 0 } });
    expect(E.renderReport(none, "admin")).not.toContain("社員PC結果");
  });
  test("never contains PC labels; manager gets detail note, admin not", () => {
    ["manager", "admin"].forEach((role) => {
      const html = E.renderReport(build(Object.assign({}, company, { role })), role);
      labels.forEach((l) => expect(html).not.toContain(l));
    });
    expect(E.renderReport(rep, "manager")).toContain("担当者");
    expect(E.renderReport(rep, "manager")).toContain("より詳しく");
    expect(E.renderReport(rep, "admin")).not.toContain("より詳しく");
  });
  test("pc mode: only pc scenes, title あなたの PC", () => {
    const r = build(pcDiag);
    expect(r.scenes.map((s) => s.id).sort()).toEqual(["antivirus", "os_update", "pc_loss"]);
    const html = E.renderReport(r, "employee", { mode: "pc", date: pcDiag.createdAt });
    expect(html).toContain("あなたの PC");
    expect((html.match(/class="scene /g) || []).length).toBe(3);
    expect(html).not.toContain("台中");
  });
  test("needs_admin shown in scene text", () => {
    const d = JSON.parse(JSON.stringify(pcDiag));
    d.pcs[0].checks.disk_encryption = { facts: {}, unavailable: "needs_admin" };
    expect(E.renderReport(build(d), "employee")).toContain("管理者権限が必要");
  });
  test("no external URL, escapes html", () => {
    expect(E.renderReport(rep, "admin")).not.toContain("http");
    const r = Object.assign({}, rep, { scenes: [{ id: "x", title: "<b>t</b>", status: "ok", text: "a<script>", next: "" }] });
    const html = E.renderReport(r, "admin");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });
});

describe("renderAsklist", () => {
  test("lists questions with howToAsk, escaped; empty message", () => {
    const rep = { asklist: [{ questionId: "a", text: "Q<1>", howToAsk: "聞き方&" }], baselineAsOf: "2026-10-01" };
    const html = E.renderAsklist(rep);
    expect(html).toContain("Q&lt;1&gt;");
    expect(html).toContain("聞き方&amp;");
    expect(html).not.toContain("http");
    expect(E.renderAsklist({ asklist: [], baselineAsOf: "x" })).toContain("ありません");
  });
  test("built from company fixture has no PC labels", () => {
    const html = E.renderAsklist(build(company));
    labels.forEach((l) => expect(html).not.toContain(l));
  });
});

describe("renderPcs", () => {
  const ctx = { baseline: B, today: company.createdAt, answers: company.answers };
  test("shows latest PC labels once, heading says 担当者向け, status labels", () => {
    const html = E.renderPcs(company, ctx);
    expect(html).toContain("担当者向け");
    labels.forEach((l) => expect(html).toContain(l));
    expect((html.match(/class="pc"/g) || []).length).toBe(labels.length);
    expect(html).toContain("危ない");
    expect(html).not.toContain("http");
  });
  test("needs_admin reason, escapes label", () => {
    const d = JSON.parse(JSON.stringify(company));
    d.pcs = [{ label: "<i>x", checkedAt: "2026-10-01", os: "windows", checks: { disk_encryption: { facts: {}, unavailable: "needs_admin" } } }];
    const html = E.renderPcs(d, ctx);
    expect(html).toContain("管理者権限が必要");
    expect(html).toContain("&lt;i&gt;x");
  });
  test("no PCs -> message", () => {
    expect(E.renderPcs(Object.assign({}, company, { pcs: [] }), ctx)).toContain("まだありません");
  });
});
