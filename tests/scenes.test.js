const { test, expect, describe } = require("bun:test");
const E = require("../security-checkup/report/engine.js");
const B = require("../security-checkup/report/baseline.js");
const SCENES = require("../security-checkup/report/scenes.js");
const { questions } = require("../security-checkup/questions/company.json");
const fs = require("fs");
const path = require("path");

const TODAY = "2026-10-24";
const STATUSES = ["ok", "warn", "bad", "unknown"];
const ROLES = ["manager", "admin", "employee"];
const fx = (n) => JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", n), "utf8"));
const byId = Object.fromEntries(SCENES.map((s) => [s.id, s]));
const ctxOf = (d) => ({ baseline: B, today: TODAY, answers: d.answers || {}, pcs: E.latestPcs(d.pcs) });
const run = (id, d) => byId[id].evaluate(d, ctxOf(d), E);

const okPc = () => fx("pc-windows-ok.json");
const company = (answers, pcs) => ({ version: 1, createdAt: TODAY, mode: "company", role: "admin", literacy: 2, company: { name: "見本", pcCount: 10 }, answers, pcs: pcs || [] });

describe("場面の定義", () => {
  test("9 場面がそろい、critical は 4 つ、pcScene は 3 つ", () => {
    expect(SCENES.map((s) => s.id).sort()).toEqual(
      ["antivirus", "departed_accounts", "email_takeover", "incident_response", "office_network", "os_update", "pc_loss", "ransomware", "remote_intrusion"].sort()
    );
    expect(SCENES.filter((s) => s.critical).map((s) => s.id).sort()).toEqual(["departed_accounts", "email_takeover", "ransomware", "remote_intrusion"]);
    expect(SCENES.filter((s) => s.pcScene).map((s) => s.id).sort()).toEqual(["antivirus", "os_update", "pc_loss"]);
    for (const s of SCENES) expect(typeof s.title).toBe("string");
  });

  test("全場面・全役割・全状態で text が空でない文字列を返す（facts が空でも）", () => {
    const d = fx("diagnosis-company.json");
    for (const s of SCENES) {
      const real = s.evaluate(d, ctxOf(d), E).facts;
      for (const role of ROLES) for (const st of STATUSES) for (const facts of [{}, real]) {
        const t = s.text[role][st](facts);
        expect(typeof t, `${s.id}.${role}.${st}`).toBe("string");
        expect(t.length, `${s.id}.${role}.${st}`).toBeGreaterThan(0);
      }
    }
  });

  test("bad・warn・unknown の next は文字列、ok は null", () => {
    for (const s of SCENES) {
      for (const st of ["bad", "warn", "unknown"]) {
        expect(typeof s.next[st]({}), `${s.id}.${st}`).toBe("string");
        expect(s.next[st]({}).length).toBeGreaterThan(0);
      }
      expect(s.next.ok({})).toBeNull();
    }
  });

  test("diagnosis-company で全場面の evaluate が 4 状態のどれかを返す", () => {
    const d = fx("diagnosis-company.json");
    for (const s of SCENES) {
      const out = s.evaluate(d, ctxOf(d), E);
      expect(STATUSES, s.id).toContain(out.status);
      expect(typeof out.facts, s.id).toBe("object");
    }
  });

  test("回答がすべて later なら、回答だけを見る場面は unknown", () => {
    const answers = Object.fromEntries(questions.map((q) => [q.id, "later"]));
    const d = company(answers, [okPc()]);
    for (const id of ["departed_accounts", "email_takeover", "incident_response"]) {
      expect(run(id, d).status, id).toBe("unknown");
    }
  });

  test("場面が読む回答の id はすべて company.json にある", () => {
    const qids = new Set(questions.map((q) => q.id));
    for (const id of SCENES.flatMap((s) => s.answerIds || [])) expect(qids.has(id), id).toBe(true);
  });
});

describe("場面の判定", () => {
  test("ransomware：バックアップが同じ場所だけなら bad、別の場所で戻せるなら PC 次第で ok", () => {
    const bad = run("ransomware", company({ backup_exists: "yes", backup_location: "same", backup_generations: "multiple", backup_restore_tested: "yes" }, [okPc()]));
    expect(bad.status).toBe("bad");
    const ok = run("ransomware", company({ backup_exists: "yes", backup_location: "separate", backup_generations: "multiple", backup_restore_tested: "yes" }, [okPc()]));
    expect(ok.status).toBe("ok");
  });

  test("ransomware：バックアップなしなら深掘りの回答がなくても bad", () => {
    expect(run("ransomware", company({ backup_exists: "no" }, [okPc()])).status).toBe("bad");
  });

  test("departed_accounts：残りが 1 件以上なら bad、0 件で決まりありなら ok", () => {
    expect(run("departed_accounts", company({ departed_accounts_process: "yes", departed_accounts_days: "within_week", departed_accounts_count: "some" })).status).toBe("bad");
    expect(run("departed_accounts", company({ departed_accounts_process: "yes", departed_accounts_days: "within_week", departed_accounts_count: "zero", shared_accounts: "none", saas_list: "yes" })).status).toBe("ok");
  });

  test("email_takeover：2 段階認証が一部だけなら warn、していないなら bad", () => {
    const base = { email_misdelivery: "yes", saas_admin_known: "yes" };
    expect(run("email_takeover", company({ ...base, mfa_enabled: "yes", mfa_coverage: "some" })).status).toBe("warn");
    expect(run("email_takeover", company({ ...base, mfa_enabled: "no" })).status).toBe("bad");
    expect(run("email_takeover", company({ ...base, mfa_enabled: "yes", mfa_coverage: "all" })).status).toBe("ok");
  });

  test("office_network：回答からクラウドの許可リストを作り、cloud_sync に渡す", () => {
    const pc = okPc();
    pc.checks.cloud_sync = { facts: { products: ["OneDrive"] }, unavailable: null };
    const base = { wifi_guest_separated: "separated", wifi_password_changed: "yes", nas_exists: "no" };
    const okD = company({ ...base, mail_service: "microsoft", cloud_extra: "no" }, [pc]);
    expect(run("office_network", okD).status).toBe("ok");
    const warnD = company({ ...base, mail_service: "google", cloud_extra: "no" }, [pc]);
    const w = run("office_network", warnD);
    expect(w.status).toBe("warn");
    expect(byId.office_network.text.admin.warn(w.facts)).toContain("OneDrive");
    const extra = company({ ...base, mail_service: "google", cloud_extra: "yes", cloud_extra_which: ["dropbox"] }, [{ ...pc, checks: { ...pc.checks, cloud_sync: { facts: { products: ["Dropbox", "Google Drive"] }, unavailable: null } } }]);
    expect(run("office_network", extra).status).toBe("ok");
    expect(run("office_network", company({ ...base, mail_service: "later", cloud_extra: "no" }, [pc])).status).toBe("unknown");
  });

  test("remote_intrusion：VPN の部品は VPN ソフトがある PC だけで数え、VPN なしなら使わない", () => {
    const withVpn = okPc();
    withVpn.label = "A";
    withVpn.checks.vpn_client = { facts: { products: [{ name: "FortiClient", version: "7.2.4" }] }, unavailable: null };
    const noVpn = okPc();
    noVpn.label = "B";
    noVpn.checks.vpn_client = { facts: { products: [] }, unavailable: null };
    const base = { telework: "yes", vpn_updated: "yes", remote_desktop: "no" };
    const r = run("remote_intrusion", company({ ...base, vpn_used: "yes" }, [withVpn, noVpn]));
    expect(r.status).toBe("ok");
    const vpnSig = r.facts.signals.find((s) => s.key === "vpn_client");
    expect(vpnSig.checked).toBe(1);
    const r2 = run("remote_intrusion", company({ telework: "yes", vpn_used: "no", remote_desktop: "no" }, [withVpn, noVpn]));
    expect(r2.facts.signals.some((s) => s.key === "vpn_client")).toBe(false);
    expect(r2.status).toBe("ok");
  });

  test("PC 系の文言は「N 台中 M 台」で書き、PC のラベルを出さない", () => {
    const enc = (label, encrypted) => ({ ...okPc(), label, checks: { ...okPc().checks, disk_encryption: { facts: { encrypted }, unavailable: null } } });
    const pcs = [enc("佐藤", false), enc("鈴木", true), enc("高橋", true), enc("田中", true)];
    const d = company({}, pcs);
    const out = run("pc_loss", d);
    expect(out.status).toBe("warn");
    for (const role of ROLES) {
      const t = byId.pc_loss.text[role].warn(out.facts) + byId.pc_loss.next.warn(out.facts);
      expect(t).toContain("4 台中 1 台");
      for (const p of pcs) expect(t).not.toContain(p.label);
    }
  });

  test("PC の結果がないと PC 系の場面は unknown で、結果がないことを伝える", () => {
    const d = company({}, []);
    for (const id of ["pc_loss", "antivirus", "os_update"]) {
      const out = run(id, d);
      expect(out.status, id).toBe("unknown");
      expect(byId[id].text.admin.unknown(out.facts), id).toMatch(/PC の結果がまだ/);
    }
  });

  test("管理者権限が必要な項目は、その理由を日本語で伝える", () => {
    const pc = okPc();
    pc.checks.disk_encryption = { facts: {}, unavailable: "needs_admin" };
    const out = run("pc_loss", company({}, [pc]));
    expect(out.status).toBe("unknown");
    expect(byId.pc_loss.text.admin.unknown(out.facts)).toContain("管理者権限が必要");
  });

  test("unknown の文言は責めない形（把握している人がいない／確認できない）", () => {
    const d = company({ departed_accounts_process: "unknown", mfa_enabled: "unknown", incident_contact: "unknown" });
    for (const id of ["departed_accounts", "email_takeover", "incident_response"]) {
      const out = run(id, d);
      expect(out.status).toBe("unknown");
      for (const role of ["manager", "admin"]) {
        expect(byId[id].text[role].unknown(out.facts), `${id}.${role}`).toMatch(/把握している人がいませんでした|確認できませんでした/);
      }
    }
  });

  // 10 台のうち一部だけ部品の結果を差し替える
  const fleet = (n, patch) => Array.from({ length: 10 }, (_, i) => {
    const pc = okPc();
    pc.label = "PC" + i;
    if (i < n) patch(pc);
    return pc;
  });

  test("os_support：10 台中 1 台がサポート終了なら、集計が warn でも「終わっています」と書く", () => {
    const pcs = fleet(1, (pc) => { pc.osVersion = "10.0.19045"; pc.checks.os_support = { facts: { name: "Windows 10", version: "22H2", build: "19045" }, unavailable: null }; });
    // ほかの 9 台は 25H2 にして、os_support の問題を 1 台だけにする
    pcs.slice(1).forEach((pc) => { pc.osVersion = "10.0.26200"; pc.checks.os_support = { facts: { name: "Windows 11", version: "25H2", build: "26200" }, unavailable: null }; });
    const out = run("os_update", company({}, pcs));
    const sig = out.facts.signals.find((s) => s.key === "os_support");
    expect(sig.status).toBe("warn");
    expect(out.status).toBe("warn");
    for (const role of ROLES) {
      const t = byId.os_update.text[role].warn(out.facts);
      expect(t, role).toContain("10 台中 1 台は、OS のサポートがもう終わっています");
      expect(t, role).not.toContain("3 か月以内");
    }
    expect(byId.os_update.next.warn(out.facts)).toBe("1 台の OS を新しい版へ上げる");
  });

  test("screen_lock：パスワードなしの PC は、パスワードなしで開けると書く（集計が warn でも）", () => {
    const pcs = fleet(3, (pc) => { pc.checks.screen_lock = { facts: { timeoutMinutes: null, requiresPassword: false }, unavailable: null }; });
    const out = run("pc_loss", company({}, pcs));
    expect(out.status).toBe("warn");
    for (const role of ROLES) {
      const t = byId.pc_loss.text[role].warn(out.facts);
      expect(t, role).toContain("10 台中 3 台は、パスワードなしで画面を開けるか");
      expect(t, role).not.toContain("長め");
    }
    expect(byId.pc_loss.next.warn(out.facts)).toContain("パスワードを求める");
  });

  test("screen_lock：パスワードなしと時間が長いが混ざると、理由ごとに台数を書く", () => {
    const pcs = fleet(3, (pc) => { pc.checks.screen_lock = { facts: { timeoutMinutes: null, requiresPassword: false }, unavailable: null }; });
    pcs[3].checks.screen_lock = { facts: { timeoutMinutes: 20, requiresPassword: true }, unavailable: null };
    const out = run("pc_loss", company({}, pcs));
    const t = byId.pc_loss.text.admin[out.status](out.facts);
    expect(t).toContain("10 台中 3 台は、パスワードなし");
    expect(t).toContain("1 台は、画面がロックされるまでの時間が 10 分より長く");
  });

  test("ok の文言は、聞いていない深掘りを事実として書かない", () => {
    const d = company({ backup_exists: "yes" }, [okPc()]);
    d.role = "manager";
    const out = run("ransomware", d);
    // 保存先を聞いていないので、場面は ok にならない（下の gate のテスト）。ok の文言だけを確かめる
    expect(out.status).toBe("unknown");
    for (const role of ["manager", "admin"]) {
      const t = byId.ransomware.text[role].ok(out.facts);
      expect(t, role).toContain("バックアップは取っています");
      expect(t, role).not.toMatch(/戻せることも|別の場所にあり|別の場所に置いて/);
    }
    const full = run("ransomware", company({ backup_exists: "yes", backup_location: "separate", backup_generations: "multiple", backup_restore_tested: "yes" }, [okPc()]));
    expect(byId.ransomware.text.manager.ok(full.facts)).toContain("戻せることも試してあります");
  });

  test("ok の文言：2 段階認証は全員オンと聞いたときだけ「全員」と書く", () => {
    const only = run("email_takeover", company({ mfa_enabled: "yes" }));
    expect(only.status).toBe("unknown");
    expect(byId.email_takeover.text.manager.ok(only.facts)).not.toMatch(/全員が 2 段階認証|全員がスマホ/);
    const all = run("email_takeover", company({ mfa_enabled: "yes", mfa_coverage: "all" }));
    expect(byId.email_takeover.text.admin.ok(all.facts)).toContain("全員が 2 段階認証");
  });

  test("ok の文言：退職者の件数を聞いていなければ「残っていません」と書かない", () => {
    const out = run("departed_accounts", company({ departed_accounts_process: "yes" }));
    expect(out.status).toBe("unknown");
    const t = byId.departed_accounts.text.manager.ok(out.facts);
    expect(t).not.toContain("残っていません");
    expect(t).toContain("担当者に数えてもらって");
  });

  test("ok の文言：テレワークありで VPN を聞いていなければ、つなぎ方を断定しない", () => {
    const out = run("remote_intrusion", company({ telework: "yes" }, [okPc()]));
    expect(out.status).toBe("unknown");
    const t = byId.remote_intrusion.text.manager.ok(out.facts);
    expect(t).not.toContain("つなぐ使い方はしていません");
    expect(t).toContain("担当者に確かめて");
    const none = run("remote_intrusion", company({ telework: "no" }, [okPc()]));
    expect(byId.remote_intrusion.text.manager.ok(none.facts)).toContain("つなぐ使い方はしていません");
  });

  test("ok の文言：VPN ありで更新の確認が未回答なら「VPN は使っていません」と書かない", () => {
    const out = run("remote_intrusion", company({ telework: "yes", vpn_used: "yes", remote_desktop: "no" }, [okPc()]));
    expect(out.status).toBe("ok");
    for (const role of ["manager", "admin"]) {
      const t = byId.remote_intrusion.text[role].ok(out.facts);
      expect(t, role).not.toContain("VPN は使っていません");
      expect(t, role).toContain("最新の状態かは、担当者に確かめて");
    }
    const noVpn = run("remote_intrusion", company({ telework: "yes", vpn_used: "no", remote_desktop: "no" }, [okPc()]));
    expect(byId.remote_intrusion.text.manager.ok(noVpn.facts)).toContain("VPN は使っていません");
  });

  test("ok の文言：戻せることを試してあるなら、戻せるかを担当者に聞かせない", () => {
    const out = run("ransomware", company({ backup_exists: "yes", backup_restore_tested: "yes" }, [okPc()]));
    expect(out.status).toBe("unknown");
    const t = byId.ransomware.text.admin.ok(out.facts);
    expect(t).toContain("戻せることも試してあります");
    expect(t).not.toContain("実際に戻せるか");
    expect(t).toContain("保存先");
  });

  test("systems_updated：社外から社内につなぐ会社で「していない」なら外からの侵入が bad、社内のネットワークでは数えない", () => {
    for (const a of [{ telework: "yes", vpn_used: "yes" }, { telework: "yes" }, { telework: "yes", vpn_used: "unknown" }]) {
      const d = company({ ...a, systems_updated: "no", remote_desktop: "no" }, [okPc()]);
      const out = run("remote_intrusion", d);
      expect(out.status, JSON.stringify(a)).toBe("bad");
      expect(byId.remote_intrusion.text.admin.bad(out.facts)).toContain("定期的に更新している人がいません");
      expect(byId.remote_intrusion.next.bad(out.facts)).toContain("業者と決める");
      expect(run("office_network", d).facts.signals.some((s) => s.key === "systems_updated")).toBe(false);
    }
  });

  test("systems_updated：社外からつながない・VPN を使わない会社では、社内のネットワークの warn", () => {
    for (const a of [{ telework: "no" }, { telework: "yes", vpn_used: "no", remote_desktop: "no" }, {}]) {
      const d = company({ ...a, systems_updated: "no", wifi_guest_separated: "separated", wifi_password_changed: "yes", nas_exists: "no" }, [okPc()]);
      const net = run("office_network", d);
      expect(net.status, JSON.stringify(a)).toBe("warn");
      expect(byId.office_network.text.admin.warn(net.facts)).toContain("定期的に更新している人がいません");
      expect(run("remote_intrusion", d).facts.signals.some((s) => s.key === "systems_updated")).toBe(false);
    }
  });

  test("systems_updated：「している」なら ok の文言に書く", () => {
    const out = run("remote_intrusion", company({ telework: "yes", vpn_used: "yes", vpn_updated: "yes", systems_updated: "yes", remote_desktop: "no" }, [okPc()]));
    expect(out.status).toBe("ok");
    expect(byId.remote_intrusion.text.manager.ok(out.facts)).toContain("更新も、定期的にしています");
  });

  test("振り分けで業者に回した深掘り（later）は、重大な場面を ok にせず聞くことリストに載る", () => {
    const answers = { it_setup: "others", backup_exists: "yes", backup_location: "later", backup_generations: "later", backup_restore_tested: "later", departed_accounts_process: "yes", departed_accounts_count: "later", departed_accounts_days: "later" };
    const d = company(answers, [okPc()]);
    expect(run("ransomware", d).status).toBe("unknown");
    expect(run("departed_accounts", d).status).toBe("unknown");
    const rep = E.buildReport(d, SCENES, B, TODAY, questions);
    const ids = rep.asklist.map((x) => x.questionId);
    for (const id of ["backup_location", "backup_generations", "backup_restore_tested", "departed_accounts_count", "departed_accounts_days"]) expect(ids, id).toContain(id);
    expect(ids).not.toContain("it_setup");
  });

  test("vpn_updated が「確かめていない」なら bad（裁定 9）", () => {
    const out = run("remote_intrusion", company({ telework: "yes", vpn_used: "yes", vpn_updated: "no", remote_desktop: "no" }, [okPc()]));
    expect(out.status).toBe("bad");
    expect(byId.remote_intrusion.text.admin.bad(out.facts)).toContain("確かめていません");
    expect(byId.remote_intrusion.next.bad(out.facts)).toContain("VPN の機器が最新か");
  });

  test("cloud_sync：「その他」の iCloud なども製品名にそろえて許可に入れる", () => {
    const pc = okPc();
    pc.checks.cloud_sync = { facts: { products: ["iCloud Drive", "Google Drive"] }, unavailable: null };
    const base = { wifi_guest_separated: "separated", wifi_password_changed: "yes", nas_exists: "no", mail_service: "google", cloud_extra: "yes" };
    expect(run("office_network", company({ ...base, cloud_extra_which: ["icloud"] }, [pc])).status).toBe("ok");
    expect(run("office_network", company({ ...base, cloud_extra_which: ["iCloud Drive"] }, [pc])).status).toBe("ok");
    expect(run("office_network", company({ ...base, cloud_extra_which: ["dropbox"] }, [pc])).status).toBe("warn");
  });

  test("PC が確認できないときは、設定の手順（BitLocker など）を出さない", () => {
    const pc = okPc();
    pc.checks.disk_encryption = { facts: {}, unavailable: "needs_admin" };
    const out = run("pc_loss", company({}, [pc]));
    expect(byId.pc_loss.text.admin.unknown(out.facts)).not.toContain("BitLocker");
  });

  test("buildReport に通すと全場面の行ができる", () => {
    const d = fx("diagnosis-company.json");
    const r = E.buildReport(d, SCENES, B, TODAY, questions);
    expect(r.scenes.length).toBe(9);
    for (const row of r.scenes) expect(row.text.length, row.id).toBeGreaterThan(0);
    const p = E.buildReport(fx("diagnosis-pc.json"), SCENES, B, TODAY, questions);
    expect(p.scenes.map((s) => s.id).sort()).toEqual(["antivirus", "os_update", "pc_loss"]);
  });
});
