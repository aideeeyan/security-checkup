import { test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const dir = join(import.meta.dir, "fixtures");
const load = (name) => JSON.parse(readFileSync(join(dir, name), "utf8"));

const UNAVAILABLE = [null, "needs_admin", "not_supported", "error"];

function checkPc(pc) {
  expect(typeof pc.label).toBe("string");
  expect(pc.label.length).toBeGreaterThan(0);
  expect(pc.checkedAt).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  expect(["windows", "mac"]).toContain(pc.os);
  expect(typeof pc.checks).toBe("object");
  for (const [id, c] of Object.entries(pc.checks)) {
    expect(c, id).toHaveProperty("facts");
    expect(c, id).toHaveProperty("unavailable");
    expect(UNAVAILABLE).toContain(c.unavailable);
  }
}

for (const name of ["pc-windows-ok.json", "pc-mac-mixed.json"]) {
  test(`${name} は PcResult として読める`, () => {
    const pc = load(name);
    expect(pc.version).toBe(1);
    checkPc(pc);
  });
}

test("pc-mac-mixed は暗号化なしと管理者権限が必要な項目を含む", () => {
  const pc = load("pc-mac-mixed.json");
  expect(pc.checks.disk_encryption.facts.encrypted).toBe(false);
  expect(pc.checks.antivirus.unavailable).toBe("needs_admin");
});

for (const name of ["diagnosis-company.json", "diagnosis-pc.json"]) {
  test(`${name} は diagnosis として読める`, () => {
    const d = load(name);
    expect(d.version).toBe(1);
    expect(["company", "pc"]).toContain(d.mode);
    expect(["manager", "admin", "employee"]).toContain(d.role);
    expect([1, 2, 3]).toContain(d.literacy);
    expect(Array.isArray(d.pcs)).toBe(true);
    for (const pc of d.pcs) {
      expect(pc.version).toBe(1);
      checkPc(pc);
    }
  });
}

test("diagnosis-company は重複ラベルと 38 台の情報を含む", () => {
  const d = load("diagnosis-company.json");
  expect(d.role).toBe("admin");
  expect(d.company.pcCount).toBe(38);
  const labels = d.pcs.map((p) => p.label);
  expect(new Set(labels).size).toBeLessThan(labels.length);
});

test("diagnosis-pc は pc モード・社員・1 台", () => {
  const d = load("diagnosis-pc.json");
  expect(d.mode).toBe("pc");
  expect(d.role).toBe("employee");
  expect(d.pcs.length).toBe(1);
});
