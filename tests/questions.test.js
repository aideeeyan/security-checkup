const { test, expect, describe } = require("bun:test");
const E = require("../security-checkup/report/engine.js");
const { questions } = require("../security-checkup/questions/company.json");

const ids = questions.map((q) => q.id);
const byId = Object.fromEntries(questions.map((q) => [q.id, q]));
const DOMAINS = ["account", "backup", "email", "saas", "remote", "network", "incident", "education"];

describe("company.json の質問", () => {
  test("id が重複しない", () => {
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("全問に unknown と later があり、選択肢は 2〜4 個で id が重複しない", () => {
    for (const q of questions) {
      const opt = q.options.map((o) => o.id);
      expect(opt.length, q.id).toBeGreaterThanOrEqual(2);
      expect(opt.length, q.id).toBeLessThanOrEqual(4);
      expect(new Set(opt).size, q.id).toBe(opt.length);
      expect(q.options.find((o) => o.id === "unknown"), q.id).toEqual({ id: "unknown", label: "わからない" });
      expect(q.options.find((o) => o.id === "later"), q.id).toEqual({ id: "later", label: "あとで確認" });
      for (const o of q.options) expect(o.label.trim().length, `${q.id}.${o.id}`).toBeGreaterThan(0);
      expect(q.options.some((o) => /その他/.test(o.label)), q.id).toBe(false);
    }
  });

  test("when と followupOf は実在する、前に出てくる質問を指す", () => {
    for (const q of questions) {
      const myIndex = ids.indexOf(q.id);
      if (q.when) {
        for (const [pid, vals] of Object.entries(q.when)) {
          expect(byId[pid], `${q.id} when ${pid}`).toBeDefined();
          expect(ids.indexOf(pid), q.id).toBeLessThan(myIndex);
          const parentOpts = byId[pid].options.map((o) => o.id);
          for (const v of vals) expect(parentOpts, `${q.id} when ${pid}=${v}`).toContain(v);
        }
      }
      if (q.followupOf) {
        expect(byId[q.followupOf], q.id).toBeDefined();
        expect(q.when && q.when[q.followupOf], `${q.id} は followupOf と同じ親の when を持つ`).toBeDefined();
      }
    }
  });

  test("selectsChecks の値は部品の表の id だけで、キーは選択肢の id", () => {
    for (const q of questions) {
      if (!q.selectsChecks) continue;
      const opt = q.options.map((o) => o.id);
      for (const [k, checks] of Object.entries(q.selectsChecks)) {
        expect(opt, q.id).toContain(k);
        for (const c of checks) expect(E.CHECK_IDS, q.id).toContain(c);
      }
    }
  });

  test("text・textEasy・howToAsk が空でなく、domain と roles が正しい", () => {
    for (const q of questions) {
      for (const k of ["text", "textEasy", "howToAsk"]) {
        expect(typeof q[k], `${q.id}.${k}`).toBe("string");
        expect(q[k].trim().length, `${q.id}.${k}`).toBeGreaterThan(0);
      }
      expect(DOMAINS, q.id).toContain(q.domain);
      expect(q.roles.length, q.id).toBeGreaterThan(0);
      for (const r of q.roles) expect(["manager", "admin"], q.id).toContain(r);
      expect(typeof q.multiSelect, q.id).toBe("boolean");
    }
  });

  test("設定を任せている人が答えるのは、経営者 13 問以下・担当者 24 問以下", () => {
    const asked = (role) => questions.filter((q) => q.roles.includes(role) && !q.setupOnly).length;
    expect(asked("manager")).toBeLessThanOrEqual(13);
    expect(asked("admin")).toBeLessThanOrEqual(24);
    expect(questions.filter((q) => q.roles.includes("admin")).length).toBeLessThanOrEqual(35);
  });

  test("最初の質問は振り分け（it_setup）で、「自分がしている」がある", () => {
    expect(questions[0].id).toBe("it_setup");
    expect(questions[0].roles.sort()).toEqual(["admin", "manager"]);
    expect(questions[0].options.map((o) => o.id)).toContain("self");
    expect(questions[0].setupOnly).toBeUndefined();
  });

  test("設定した人だけに聞く質問は、業者でないと答えにくい 8 問で、経営者にも担当者にも付く", () => {
    const only = questions.filter((q) => q.setupOnly === true).map((q) => q.id).sort();
    expect(only).toEqual([
      "backup_generations", "backup_location", "backup_restore_tested", "departed_accounts_count",
      "departed_accounts_days", "mfa_coverage", "nas_updated", "vpn_updated",
    ]);
    for (const id of only) expect(byId[id].roles.sort(), id).toEqual(["admin", "manager"]);
    for (const q of questions) if (q.setupOnly !== undefined) expect(q.setupOnly, q.id).toBe(true);
  });

  test("機器とシステムの更新（systems_updated）は全員に聞き、VPN を含めて聞く", () => {
    const q = byId.systems_updated;
    expect(q.roles.sort()).toEqual(["admin", "manager"]);
    expect(q.setupOnly).toBeUndefined();
    expect(q.when).toBeUndefined();
    expect(q.text).toContain("VPN");
  });

  test("言葉を知らなくても答えられるよう、2 段階認証と VPN の質問文に専門用語を使わない", () => {
    expect(byId.mfa_enabled.text).not.toMatch(/2 段階認証|二段階/);
    expect(byId.vpn_used.text).not.toMatch(/VPN/);
  });

  test("設計書 5 章の 8 領域がすべてある", () => {
    for (const d of DOMAINS) expect(questions.some((q) => q.domain === d), d).toBe(true);
  });

  test("深掘りの質問は親が「している」のときだけ聞く", () => {
    const followups = questions.filter((q) => q.followupOf);
    expect(followups.length).toBeGreaterThan(0);
    for (const q of followups) {
      for (const v of q.when[q.followupOf]) expect(["unknown", "later", "no"], q.id).not.toContain(v);
    }
  });

  test("退職者アカウントは件数で答え、名前を求めない", () => {
    const q = byId.departed_accounts_count;
    expect(q).toBeDefined();
    for (const o of q.options) expect(o.label).toMatch(/件|わからない|あとで確認/);
    expect(q.text + q.howToAsk).not.toMatch(/名前を(教えて|書いて)|氏名を/);
  });

  test("文面に em ダッシュの差し込みがない", () => {
    for (const q of questions) {
      for (const s of [q.text, q.textEasy, q.howToAsk, ...q.options.map((o) => o.label)]) {
        expect(s, q.id).not.toMatch(/[—―]/);
      }
    }
  });
});
