const { test, expect } = require("bun:test");
const B = require("../security-checkup/report/baseline.js");

test("asOf is a YYYY-MM-DD date", () => {
  expect(B.asOf).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  expect(Number.isNaN(Date.parse(B.asOf))).toBe(false);
});

test("thresholds match the spec", () => {
  expect(B.thresholds).toEqual({
    avDefinitionsOkDays: 7,
    avDefinitionsWarnDays: 30,
    avLastScanWarnDays: 30,
    osUpdateOkDays: 30,
    osUpdateWarnDays: 60,
    osSupportWarnDays: 90,
    screenLockOkMinutes: 10,
    screenLockWarnMinutes: 30,
  });
});

test("osSupport entries have the required shape", () => {
  for (const e of B.osSupport) {
    expect(["windows", "mac"]).toContain(e.os);
    expect(typeof e.name).toBe("string");
    expect(e.endOfSupport === null || /^\d{4}-\d{2}-\d{2}$/.test(e.endOfSupport)).toBe(true);
    expect(["windowsBuild", "macMajor"]).toContain(e.match.kind);
    expect(e.match.min).toBeLessThanOrEqual(e.match.max);
  }
});

test("Windows 10 ended 2025-10-14 and covers build 19045", () => {
  const w10 = B.osSupport.find((e) => e.os === "windows" && e.match.min <= 19045 && 19045 <= e.match.max);
  expect(w10.endOfSupport).toBe("2025-10-14");
});

test("Windows 11 current builds are present", () => {
  for (const build of [22631, 26100, 26200, 26300]) {
    const e = B.osSupport.find((x) => x.os === "windows" && x.match.min <= build && build <= x.match.max);
    expect(e).toBeDefined();
    expect(e.name).toContain("Windows 11");
  }
  const h = (b) => B.osSupport.find((x) => x.os === "windows" && x.match.min <= b && b <= x.match.max);
  expect(h(26100).endOfSupport).toBe("2026-10-13");
  expect(h(26200).endOfSupport).toBe("2027-10-12");
});

test("macOS latest three majors are present and supported", () => {
  const majors = B.osSupport.filter((e) => e.os === "mac" && e.endOfSupport === null);
  expect(majors.map((e) => e.match.min).sort((a, b) => a - b)).toEqual([15, 26, 27]);
});

test("no two entries of the same OS overlap", () => {
  for (const os of ["windows", "mac"]) {
    const es = B.osSupport.filter((e) => e.os === os).sort((a, b) => a.match.min - b.match.min);
    for (let i = 1; i < es.length; i++) expect(es[i].match.min).toBeGreaterThan(es[i - 1].match.max);
  }
});

test("browser minimums are positive integers", () => {
  for (const k of ["chrome", "edge", "safari", "firefox"]) {
    expect(Number.isInteger(B.browserMinMajor[k])).toBe(true);
    expect(B.browserMinMajor[k]).toBeGreaterThan(0);
  }
  expect(typeof B.vpnMinVersion).toBe("object");
});
