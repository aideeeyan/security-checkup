const { test, expect, describe } = require("bun:test");
const fs = require("fs");
const path = require("path");

const REPORT = path.join(__dirname, "..", "security-checkup", "report");
const read = (f) => fs.readFileSync(path.join(REPORT, f), "utf8");
const BASE = "https://www.aideeyan.com/security-skill?utm_source=security-skill&utm_medium=skill&utm_campaign=";

describe("無料個別相談の案内", () => {
  for (const [file, campaign] of [["report.html", "report"], ["asklist.html", "asklist"]]) {
    const html = read(file);
    test(file + " には、印つきの申し込みのリンクが 1 つだけあり、新しいタブで開く", () => {
      const links = [...html.matchAll(/href="(https?:[^"]+)"/g)].map((m) => m[1].replace(/&amp;/g, "&"));
      expect(links).toEqual([BASE + campaign]);
      expect(html).toContain('target="_blank" rel="noopener"');
      expect(html).toContain(">無料個別相談を申し込む<");
      expect(html).toContain("申し込みページ（aideeyan.com）が開きます。診断の結果は送られません。");
    });
    test(file + " の案内は #app の外の固定の HTML で、表示に失敗しても残る", () => {
      const app = html.indexOf('<div id="app"></div>');
      const aside = html.indexOf('<aside class="consult"');
      expect(app).toBeGreaterThan(-1);
      expect(aside).toBeGreaterThan(app);
      expect(aside).toBeLessThan(html.indexOf("<script"));
      expect((html.match(/<script>/g) || []).length).toBe(1);
    });
    test(file + " の案内は印刷に出ない", () => {
      expect(html).toContain("@media print { .consult { display: none; } }");
    });
  }
  test("レポートの見出しと、聞くことリストの見出しは、それぞれの場面に合わせる", () => {
    expect(read("report.html")).toContain(">この結果をもとに、何から直すか一緒に決めませんか<");
    expect(read("asklist.html")).toContain(">聞ける業者や担当者がいない、聞いても判断がつかないときは<");
  });
  test("pcs.html（担当者向けの PC ごとの結果）には案内を置かない", () => {
    expect(read("pcs.html")).not.toContain("security-skill");
  });
});
