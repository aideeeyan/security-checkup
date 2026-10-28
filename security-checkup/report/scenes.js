/**
 * 事故の場面の定義と文言。ブラウザ（クラシックスクリプト）と bun の両方で動く。
 *
 * 1 つの場面は、回答と PC の結果から「シグナル」を集めて状態を決める。
 *   シグナル  { key, status, kind: "answer" | "pc", ...PC のときは counts / checked / reasons / extra }
 *   facts     { signals: [シグナル...] }
 * 文言は facts から組み立てる。シグナルごとの文（say）、管理者向けの確かめ方（hint）、次にやること（next）を持つ。
 * 文言に PC のラベル（社員の名前）は入れない。台数は「31 台中 6 台」の形で書く。
 *
 * 回答の決まり
 *   - 回答がない質問（その立場には聞いていない）はシグナルにしない
 *   - 深掘りの質問は、親の回答が条件に合うときだけ読む
 *   - 「わからない」「あとで確認」は unknown（engine.answerStatus）
 */
const SC_SCENES = (function () {
  // 質問の選択肢 id（と「その他」に書かれやすい呼び名）→ PC の部品（cloud_sync）が返す製品名。
  // 製品名は部品の出力と完全に同じ表記にする: "Google Drive" / "OneDrive" / "Dropbox" / "Box" / "iCloud Drive"。
  // 部品（Windows・Mac）の出力名を変えるときは、ここも合わせて変える。会社として認めたクラウドの一覧を作るのに使う
  const CLOUD_PRODUCTS = {
    google: ["Google Drive"],
    microsoft: ["OneDrive"],
    dropbox: ["Dropbox"],
    box: ["Box"],
    icloud: ["iCloud Drive"],
  };
  // 「その他」の自由記述を製品名にそろえる（大文字小文字と空白は無視）。どれにも当たらなければそのまま
  function cloudNames(v) {
    if (CLOUD_PRODUCTS[v]) return CLOUD_PRODUCTS[v];
    const key = String(v).toLowerCase().replace(/\s+/g, "");
    for (const id of Object.keys(CLOUD_PRODUCTS)) {
      if (id === key) return CLOUD_PRODUCTS[id];
      for (const n of CLOUD_PRODUCTS[id]) if (n.toLowerCase().replace(/\s+/g, "") === key) return [n];
    }
    return [String(v)];
  }
  const RESERVED = ["unknown", "later"];

  // 部品の reason のうち、文言で理由として添えるもの
  const REASON_TEXT = {
    needs_admin: "管理者権限が必要なため",
    not_supported: "この OS では読めない項目のため",
    error: "読み取りに失敗したため",
  };

  const isReserved = (v) => RESERVED.indexOf(v) >= 0;
  const list = (v) => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);

  // ---- 回答と PC からシグナルを作る ----

  function answerSig(ctx, engine, key, map, when) {
    const answers = ctx.answers || {};
    if (when) {
      for (const pid of Object.keys(when)) {
        const pv = list(answers[pid]);
        if (!pv.some((x) => when[pid].indexOf(x) >= 0)) return null;
      }
    }
    if (answers[key] === undefined) return null;
    return { key, kind: "answer", status: engine.answerStatus(answers, key, map), value: answers[key] };
  }

  function pcSig(ctx, engine, key, checkId, extra, pcs) {
    const c = Object.assign({}, ctx, extra || {});
    const target = pcs || ctx.pcs || [];
    const agg = engine.aggregatePcs(target, checkId, c);
    const reasons = Object.create(null);
    target.forEach((pc) => {
      const ok = pc !== null && typeof pc === "object";
      const checks = ok && pc.checks !== null && typeof pc.checks === "object" ? pc.checks : null;
      const res = engine.evaluateCheck(checkId, checks ? checks[checkId] : undefined, Object.assign({}, c, { os: ok ? pc.os : undefined, osVersion: ok ? pc.osVersion : undefined }));
      if (res.status !== "ok" && res.reason) reasons[res.reason] = (reasons[res.reason] || 0) + 1;
    });
    return { key, kind: "pc", status: agg.status, counts: agg.counts, checked: agg.checked, reasons, pcMode: c.mode === "pc" };
  }

  // gates: 重大な場面で、決め手になる深掘りの質問が聞かれていないときの印 [{ key, miss }]。
  // 聞かれていない（経営者だけの回答など）のに、親の「はい」だけで「守れている」にしないため、ok のときだけ unknown に下げる
  function result(engine, signals, gates) {
    const sigs = signals.filter(Boolean);
    let status = sigs.length ? engine.combine(sigs.map((s) => s.status)) : "unknown";
    if (status === "ok") {
      const missing = (gates || []).filter((g) => g && g.miss);
      if (missing.length) {
        status = "unknown";
        missing.forEach((g) => sigs.push({ key: g.key, kind: "answer", status: "unknown", unasked: true }));
      }
    }
    return { status, facts: { signals: sigs } };
  }
  const asked = (answers, id) => (answers || {})[id] !== undefined;
  // 社外から社内につないでいる（または、つないでいないと言い切れない）会社。
  // 社外から使っていて、VPN を「使っていない」とはっきり答えたときだけ外す（クラウドだけで使っている会社）
  const connectsIn = (answers) => list((answers || {}).telework).indexOf("yes") >= 0 && list((answers || {}).vpn_used).indexOf("no") < 0;

  function allowedCloud(answers) {
    const a = answers || {};
    const mail = list(a.mail_service);
    const extra = list(a.cloud_extra);
    if (mail.length === 0 || mail.some(isReserved)) return undefined;
    if (extra.length === 0 || extra.some(isReserved)) return undefined;
    const out = [];
    const add = (v) => cloudNames(v).forEach((n) => { if (out.indexOf(n) < 0) out.push(n); });
    mail.forEach((v) => { if (CLOUD_PRODUCTS[v]) add(v); });
    if (extra.indexOf("yes") >= 0) {
      const which = list(a.cloud_extra_which);
      if (which.length === 0 || which.some(isReserved)) return undefined;
      which.forEach(add); // 「その他」に書かれた名前も、製品名にそろえて認めたものとして扱う
    }
    return out;
  }

  // 認めていない同期ソフトの名前（製品名だけで、PC のラベルは含めない）
  function unapprovedProducts(pcs, allowed) {
    if (!Array.isArray(allowed)) return [];
    const ok = allowed.map((x) => String(x).toLowerCase());
    const out = [];
    (pcs || []).forEach((pc) => {
      const r = pc && pc.checks && pc.checks.cloud_sync;
      if (!r || typeof r !== "object" || r.unavailable != null) return;
      (r.facts && Array.isArray(r.facts.products) ? r.facts.products : []).forEach((p) => {
        if (ok.indexOf(String(p).toLowerCase()) < 0 && out.indexOf(p) < 0) out.push(p);
      });
    });
    return out.sort();
  }

  // ---- 文言の部品 ----

  // 「31 台中 6 台」。1 台だけなら「この PC 」（助詞の前の空白まで含む）
  function of(s, n) {
    return s.checked === 1 ? "この PC " : s.checked + " 台中 " + n + " 台";
  }
  const problems = (s) => (s.counts ? s.counts.bad + s.counts.warn : 0);
  const reasonN = (s, r) => (s.reasons && s.reasons[r]) || 0;

  // PC ごとの理由の台数から文を作る。場面の状態（集計）ではなく、各 PC の理由に合わせるため。
  // parts: [[台数, 「は、」に続く文]...]。最初の文だけ「31 台中 3 台は、」、続きは「2 台は、」
  function reasonLines(s, parts, fallbackText) {
    const used = parts.filter((p) => p[0] > 0);
    if (used.length === 0) return of(s, problems(s)) + "は、" + fallbackText;
    if (s.checked === 1) return "この PC は、" + used[0][1];
    return used.map((p, i) => (i === 0 ? of(s, p[0]) : p[0] + " 台") + "は、" + p[1]).join("");
  }

  // ok の文言用。その回答や部品が判定に使われ、ok だったか
  const okSig = (f, key) => ((f && f.signals) || []).some((s) => s.key === key && s.status === "ok");
  const hasSig = (f, key) => ((f && f.signals) || []).some((s) => s.key === key);
  const pcChecked = (f) => {
    const s = ((f && f.signals) || []).find((x) => x.kind === "pc");
    return s ? s.checked : 0;
  };

  function pcUnknown(s, what) {
    if (!s.checked) return "社員の PC の結果がまだないため、" + what + "を確認できていません。";
    const n = s.counts.unknown;
    for (const r of Object.keys(REASON_TEXT)) {
      if (reasonN(s, r) === n) return of(s, n) + "は、" + REASON_TEXT[r] + "、" + what + "を確認できませんでした。";
    }
    return of(s, n) + "は、" + what + "を確認できませんでした。";
  }
  function pcNextUnknown(s) {
    if (!s.checked) return "社員に「自分の PC の診断」を回してもらう";
    // 自分の PC の診断（本人が見るページ）では、担当者向けの行動を出さない
    if (s.pcMode) return "担当者に伝える";
    if (reasonN(s, "needs_admin") > 0) return "管理者のアカウントで、確認できなかった PC を見てもらう";
    return "確認できなかった PC で、もう一度診断を動かしてもらう";
  }

  // say: { [key]: { bad?, warn?, unknown? }: (sig) => 文 }。hint は管理者向けの確かめ方。next は次にやること
  function makeScene(def) {
    const sigsOf = (facts, status) => ((facts && facts.signals) || []).filter((s) => s.status === status && def.say[s.key] && def.say[s.key][status]);
    const line = (s, status) => def.say[s.key][status](s);
    const top = (facts, status) => sigsOf(facts, status)[0];

    function compose(role, status, facts) {
      if (status === "ok") return def.ok[role](facts || {});
      let sigs = sigsOf(facts, status);
      if (role === "employee") sigs = sigs.filter((s) => s.kind === "pc");
      const max = role === "manager" ? 1 : 2;
      const lines = sigs.slice(0, max).map((s) => line(s, status));
      if (lines.length === 0) lines.push(def.fallback[status]);
      if (role === "manager") lines.push(def.impact[status]);
      else if (role === "admin") {
        const t = sigs[0];
        // PC が確認できなかったときは設定の手順ではなく、次にやること（next）で案内する
        const hint = t && !(t.kind === "pc" && status === "unknown") && def.hint[t.key];
        if (hint) lines.push(typeof hint === "function" ? hint(t) : hint);
      } else lines.push(def.employee[status]);
      return lines.join("");
    }

    const text = {};
    ["manager", "admin", "employee"].forEach((role) => {
      text[role] = {};
      ["ok", "warn", "bad", "unknown"].forEach((st) => { text[role][st] = (facts) => compose(role, st, facts); });
    });
    const next = { ok: () => null };
    ["warn", "bad", "unknown"].forEach((st) => {
      next[st] = (facts) => {
        const t = top(facts, st);
        const n = t && def.next[t.key] && def.next[t.key][st];
        if (n) return typeof n === "function" ? n(t) : n;
        return def.nextFallback[st];
      };
    });
    return { id: def.id, title: def.title, critical: def.critical, pcScene: def.pcScene, answerIds: def.answerIds, evaluate: def.evaluate, text, next };
  }

  const ASK = "業者や担当者に聞くことリストで確かめる";
  const CONFIRM = "担当者に、詳しい質問に答えてもらって確かめる";

  // ---- 場面 ----

  // 回答された分だけを書く。深掘り（保存先・戻せるか）を聞いていなければ、そうとは書かない
  function backupOk(f) {
    if (!hasSig(f, "backup_exists")) return "バックアップについては回答がないため、ここには含めていません。";
    const deep = ["backup_location", "backup_generations", "backup_restore_tested"];
    if (deep.every((k) => okSig(f, k))) return "バックアップは別の場所にあり、何日か前の分もさかのぼれます。戻せることも試してあります。";
    const said = [];
    if (okSig(f, "backup_location")) said.push("別の場所に置いてあります");
    if (okSig(f, "backup_generations")) said.push("何日か前の分も残っています");
    if (okSig(f, "backup_restore_tested")) said.push("戻せることも試してあります");
    const head = "バックアップは取っています" + (said.length ? "。" + said.join("。") : "") + "。";
    const ask = [];
    if (!okSig(f, "backup_location")) ask.push("保存先");
    if (!okSig(f, "backup_generations")) ask.push("何日前までさかのぼれるか");
    if (!okSig(f, "backup_restore_tested")) ask.push("実際に戻せるか");
    return head + ask.join("、") + "は、担当者に確かめてください。";
  }

  const ransomware = makeScene({
    id: "ransomware",
    title: "ランサムウェアに感染したら",
    critical: true,
    pcScene: false,
    answerIds: ["backup_exists", "backup_location", "backup_generations", "backup_restore_tested"],
    evaluate(d, ctx, engine) {
      const yes = { backup_exists: ["yes"] };
      return result(engine, [
        answerSig(ctx, engine, "backup_exists", { yes: "ok", no: "bad" }),
        answerSig(ctx, engine, "backup_location", { separate: "ok", same: "bad" }, yes),
        answerSig(ctx, engine, "backup_generations", { multiple: "ok", latest_only: "warn" }, yes),
        answerSig(ctx, engine, "backup_restore_tested", { yes: "ok", no: "warn" }, yes),
        pcSig(ctx, engine, "antivirus", "antivirus"),
        pcSig(ctx, engine, "os_update", "os_update"),
      ], [{ key: "confirm_backup", miss: list((ctx.answers || {}).backup_exists).indexOf("yes") >= 0 && !asked(ctx.answers, "backup_location") }]);
    },
    say: {
      confirm_backup: { unknown: () => "バックアップは取っているとのことですが、別の場所に置いているか、戻せるかは、まだ確かめていません。" },
      backup_exists: {
        bad: () => "大事なデータのバックアップを取っていません。",
        unknown: () => "バックアップを取っているか、把握している人がいませんでした。",
      },
      backup_location: {
        bad: () => "バックアップが元のデータと同じ機器や社内のネットワークの中にしかなく、感染すると一緒に暗号化されるおそれがあります。",
        unknown: () => "バックアップをどこに置いているか、把握している人がいませんでした。",
      },
      backup_generations: {
        warn: () => "バックアップを毎回上書きしているため、感染したあとのデータで上書きされると戻せません。",
        unknown: () => "バックアップを何日前までさかのぼれるか、把握している人がいませんでした。",
      },
      backup_restore_tested: {
        warn: () => "バックアップから戻せるか、試したことがありません。",
        unknown: () => "バックアップから戻せるか試したことがあるか、把握している人がいませんでした。",
      },
      antivirus: {
        bad: (s) => of(s, problems(s)) + "で、ウイルス対策が止まっているか、更新が古くなっています。",
        warn: (s) => of(s, problems(s)) + "で、ウイルス対策が止まっているか、更新が古くなっています。",
        unknown: (s) => pcUnknown(s, "ウイルス対策"),
      },
      os_update: {
        bad: (s) => of(s, problems(s)) + "は、OS の更新が 1 か月以上止まっています。",
        warn: (s) => of(s, problems(s)) + "は、OS の更新が 1 か月以上止まっています。",
        unknown: (s) => pcUnknown(s, "OS の更新"),
      },
    },
    hint: {
      confirm_backup: "バックアップの保存先と、戻せるかを担当者に確かめてもらってください。",
      backup_exists: "共有フォルダと会計データから始め、社外のクラウドか、ふだんはつないでいない機器に保存してください。",
      backup_location: "社外のクラウドか、ふだんはつないでいない機器にもう 1 つ写しを置けるか、業者に相談してください。",
      backup_generations: "数日分以上を残す設定にできるか、バックアップの設定画面か業者に確かめてください。",
      backup_restore_tested: "ファイルを 1 つ選び、別の場所に戻せるかを試してください。",
      antivirus: "PC ごとの結果の一覧で、該当する PC を確かめてください。",
      os_update: "PC ごとの結果の一覧で、該当する PC を確かめてください。",
    },
    next: {
      confirm_backup: { unknown: CONFIRM },
      backup_exists: { bad: "大事なデータのバックアップを取り始める", unknown: ASK },
      backup_location: { bad: "社外か別の場所にもう 1 つ保存する", unknown: ASK },
      backup_generations: { warn: "数日分さかのぼれる形で残す", unknown: ASK },
      backup_restore_tested: { warn: "バックアップから 1 つ戻してみる", unknown: ASK },
      antivirus: { bad: (s) => problems(s) + " 台のウイルス対策を動かす", warn: (s) => problems(s) + " 台のウイルス対策を動かす", unknown: pcNextUnknown },
      os_update: { bad: (s) => problems(s) + " 台の持ち主に更新をお願いする", warn: (s) => problems(s) + " 台の持ち主に更新をお願いする", unknown: pcNextUnknown },
    },
    impact: {
      bad: "感染すると共有データや会計データを戻せず、業務が数日から数週間止まるおそれがあります。",
      warn: "感染したとき、戻すまでに時間がかかったり、一部のデータを失ったりするおそれがあります。",
      unknown: "感染したときに業務をどこまで戻せるか、今はわかりません。",
    },
    employee: {
      bad: "担当者に相談してください。",
      warn: "担当者に相談してください。",
      unknown: "担当者が確認する項目です。",
    },
    ok: {
      manager: (f) => backupOk(f) + "確認した PC のウイルス対策と OS の更新も止まっていません。",
      admin: (f) => backupOk(f) + "確認した PC のウイルス対策と OS の更新も止まっていません。",
      employee: () => "この場面で、あなたの PC について直すことはありません。",
    },
    fallback: {
      bad: "感染したときにデータを戻せないおそれがあります。",
      warn: "感染したときの備えに、足りない所があります。",
      unknown: "感染したときの備えを、把握している人がいませんでした。",
    },
    nextFallback: { bad: "バックアップを別の場所にも取る", warn: "バックアップの残し方を見直す", unknown: ASK },
  });

  function departedOk(f) {
    const said = [];
    if (okSig(f, "departed_accounts_count")) said.push("辞めた人のアカウントは残っていません。");
    if (okSig(f, "departed_accounts_process")) said.push(okSig(f, "departed_accounts_days") ? "退職から 1 週間以内に止める手順が回っています。" : "アカウントを止める手順は決まっています。");
    if (okSig(f, "shared_accounts")) said.push("ID の使い回しもありません。");
    if (!said.length) return "回答の範囲では、問題は見つかりませんでした。";
    if (!hasSig(f, "departed_accounts_count")) said.push("止め忘れが残っていないかは、担当者に数えてもらってください。");
    return said.join("");
  }

  const departed = makeScene({
    id: "departed_accounts",
    title: "辞めた人のアカウント",
    critical: true,
    pcScene: false,
    answerIds: ["departed_accounts_process", "departed_accounts_days", "departed_accounts_count", "shared_accounts", "saas_list"],
    evaluate(d, ctx, engine) {
      return result(engine, [
        answerSig(ctx, engine, "departed_accounts_count", { zero: "ok", some: "bad" }),
        answerSig(ctx, engine, "departed_accounts_process", { yes: "ok", no: "bad" }),
        answerSig(ctx, engine, "departed_accounts_days", { within_week: "ok", after_week: "bad" }, { departed_accounts_process: ["yes"] }),
        answerSig(ctx, engine, "shared_accounts", { none: "ok", some: "warn" }),
        answerSig(ctx, engine, "saas_list", { yes: "ok", no: "warn" }),
      ], [{ key: "confirm_departed", miss: !asked(ctx.answers, "departed_accounts_count") }]);
    },
    say: {
      confirm_departed: { unknown: () => "辞めた人のアカウントが残っていないかは、まだ数えて確かめていません。" },
      departed_accounts_count: {
        bad: () => "辞めた人のアカウントで、止めていないものが残っています。",
        unknown: () => "辞めた人のアカウントが残っていないか、把握している人がいませんでした。",
      },
      departed_accounts_process: {
        bad: () => "辞めた人のアカウントを止める手順が決まっていません。",
        unknown: () => "辞めた人のアカウントを止める手順があるか、把握している人がいませんでした。",
      },
      departed_accounts_days: {
        bad: () => "最近辞めた人のアカウントは、止めるまでに 1 週間以上かかったか、まだ止まっていません。",
        unknown: () => "辞めた人のアカウントを退職後いつ止めたか、把握している人がいませんでした。",
      },
      shared_accounts: {
        warn: () => "何人かで使い回している ID があり、辞めた人もそのパスワードを知っているおそれがあります。",
        unknown: () => "ID を使い回しているシステムがあるか、把握している人がいませんでした。",
      },
      saas_list: {
        warn: () => "使っているクラウドのサービスの一覧がなく、退職のときに止め忘れが出やすい状態です。",
        unknown: () => "使っているクラウドのサービスの一覧があるか、把握している人がいませんでした。",
      },
    },
    hint: {
      confirm_departed: "メールやファイル共有の管理画面で、辞めた人のアカウントが残っていないか数えてもらってください。",
      departed_accounts_count: "メールやファイル共有の管理画面で、最後のログインが古いアカウントから見ていくと見つけやすいです。",
      departed_accounts_process: "退職の手続きの書類に「アカウントを止める」を入れ、誰が止めるかを決めてください。",
      departed_accounts_days: "退職の手続きの書類に「退職日にアカウントを止める」を入れてください。",
      shared_accounts: "使い回している ID のパスワードを変え、できれば 1 人 1 つの ID に分けてください。",
      saas_list: "サービス名と管理者を並べた表を 1 つ作り、退職のときはそれを見て止めてください。",
    },
    next: {
      confirm_departed: { unknown: CONFIRM },
      departed_accounts_count: { bad: "今日止める。退職日に止める手順を決める", unknown: "管理画面で、辞めた人のアカウントが残っていないか数える" },
      departed_accounts_process: { bad: "退職日に止める手順を決める", unknown: ASK },
      departed_accounts_days: { bad: "退職日に止める流れにする", unknown: ASK },
      shared_accounts: { warn: "使い回している ID のパスワードを変える", unknown: ASK },
      saas_list: { warn: "使っているサービスと管理者の一覧を作る", unknown: ASK },
    },
    impact: {
      bad: "辞めた人が社内のメールやファイルを見られる状態が続くと、情報の持ち出しやなりすましにつながります。",
      warn: "退職者が出たときに、止め忘れが起きやすい状態です。",
      unknown: "辞めた人が今も社内のデータを見られるかどうか、わかりません。",
    },
    employee: {
      bad: "担当者が確認する項目です。",
      warn: "担当者が確認する項目です。",
      unknown: "担当者が確認する項目です。",
    },
    ok: {
      manager: (f) => departedOk(f),
      admin: (f) => departedOk(f),
      employee: () => "この場面で、あなたの PC について直すことはありません。",
    },
    fallback: {
      bad: "辞めた人のアカウントが、止まっていないおそれがあります。",
      warn: "辞めた人のアカウントの止め方に、足りない所があります。",
      unknown: "辞めた人のアカウントの扱いを、把握している人がいませんでした。",
    },
    nextFallback: { bad: "退職日に止める手順を決める", warn: "使っているサービスと管理者の一覧を作る", unknown: ASK },
  });

  function emailOk(f) {
    const said = [];
    if (okSig(f, "mfa_coverage")) said.push("メールは全員が 2 段階認証（スマホでの確認）付きで入る設定です。");
    else if (okSig(f, "mfa_enabled")) said.push("メールの 2 段階認証（スマホでの確認）は使っています。全員がオンかは、担当者に確かめてください。");
    if (okSig(f, "saas_admin_known")) said.push("サービスごとの管理者も決まっています。");
    if (okSig(f, "email_misdelivery")) said.push("誤送信を防ぐ仕組みも入っています。");
    return said.length ? said.join("") : "回答の範囲では、問題は見つかりませんでした。";
  }

  const email = makeScene({
    id: "email_takeover",
    title: "メールが乗っ取られたら",
    critical: true,
    pcScene: false,
    answerIds: ["mfa_enabled", "mfa_coverage", "saas_admin_known", "email_misdelivery"],
    evaluate(d, ctx, engine) {
      return result(engine, [
        answerSig(ctx, engine, "mfa_enabled", { yes: "ok", no: "bad" }),
        answerSig(ctx, engine, "mfa_coverage", { all: "ok", some: "warn" }, { mfa_enabled: ["yes"] }),
        answerSig(ctx, engine, "saas_admin_known", { yes: "ok", no: "warn" }),
        answerSig(ctx, engine, "email_misdelivery", { yes: "ok", no: "warn" }),
      ], [{ key: "confirm_mfa", miss: list((ctx.answers || {}).mfa_enabled).indexOf("yes") >= 0 && !asked(ctx.answers, "mfa_coverage") }]);
    },
    say: {
      confirm_mfa: { unknown: () => "メールの 2 段階認証（スマホでの確認）は使っているとのことですが、全員がオンかは、まだ確かめていません。" },
      mfa_enabled: {
        bad: () => "メールにパスワードだけで入れるため、パスワードが漏れるとそのまま乗っ取られます。",
        unknown: () => "メールの 2 段階認証（スマホでの確認）を使っているか、把握している人がいませんでした。",
      },
      mfa_coverage: {
        warn: () => "2 段階認証（スマホでの確認）がオンになっていない人がいます。",
        unknown: () => "2 段階認証が全員オンかどうか、把握している人がいませんでした。",
      },
      saas_admin_known: {
        warn: () => "管理する人が決まっていないサービスがあり、乗っ取られたときにすぐ止められません。",
        unknown: () => "サービスごとに管理する人が決まっているか、把握している人がいませんでした。",
      },
      email_misdelivery: {
        warn: () => "社外へのメールを送る前に、宛先を確かめる仕組みがありません。",
        unknown: () => "メールの誤送信を防ぐ仕組みがあるか、把握している人がいませんでした。",
      },
    },
    hint: {
      confirm_mfa: "メールの管理画面で、2 段階認証がオンでないアカウントがないか確かめてもらってください。",
      mfa_enabled: "メールの管理画面で 2 段階認証を全員に求める設定にしてください。",
      mfa_coverage: "メールの管理画面で、2 段階認証がオンでないアカウントを一覧で確かめられます。",
      saas_admin_known: "サービスごとに管理者を 2 人ずつ決めておくと、1 人が不在でも止められます。",
      email_misdelivery: "社外あての送信に確認画面を出す設定や、送信の取り消しができる設定を入れられるか確かめてください。",
    },
    next: {
      confirm_mfa: { unknown: CONFIRM },
      mfa_enabled: { bad: "全員の 2 段階認証をオンにする", unknown: "管理画面で 2 段階認証の状態を確かめる" },
      mfa_coverage: { warn: "残りの人の 2 段階認証をオンにする", unknown: "管理画面で 2 段階認証の状態を確かめる" },
      saas_admin_known: { warn: "サービスごとに管理する人を決める", unknown: ASK },
      email_misdelivery: { warn: "社外あての送信に確認の仕組みを入れる", unknown: ASK },
    },
    impact: {
      bad: "乗っ取られたメールから取引先に偽の請求書が送られると、お金と信用の両方を失います。",
      warn: "乗っ取りや誤送信が起きたとき、取引先に迷惑が広がるおそれがあります。",
      unknown: "メールが乗っ取られにくい状態かどうか、今はわかりません。",
    },
    employee: {
      bad: "担当者が確認する項目です。",
      warn: "担当者が確認する項目です。",
      unknown: "担当者が確認する項目です。",
    },
    ok: {
      manager: (f) => emailOk(f),
      admin: (f) => emailOk(f),
      employee: () => "この場面で、あなたの PC について直すことはありません。",
    },
    fallback: {
      bad: "メールが乗っ取られやすい状態です。",
      warn: "メールの守りに、足りない所があります。",
      unknown: "メールの守りを、把握している人がいませんでした。",
    },
    nextFallback: { bad: "全員の 2 段階認証をオンにする", warn: "2 段階認証が全員オンか確かめる", unknown: ASK },
  });

  function remoteOk(f) {
    const val = (key) => {
      const s = ((f && f.signals) || []).find((x) => x.key === key);
      return s ? list(s.value) : [];
    };
    const said = [];
    if (!hasSig(f, "telework")) said.push("社外からの使い方は回答がないため、ここには含めていません。");
    else if (val("telework").indexOf("yes") < 0) said.push("社外から社内につなぐ使い方はしていません。");
    else if (!hasSig(f, "vpn_used")) said.push("社外から社内へのつなぎ方は、担当者に確かめてください。");
    else if (okSig(f, "vpn_updated")) said.push("社外からつなぐための機器（VPN）は、最新の状態か確かめてあります。");
    else if (val("vpn_used").indexOf("no") >= 0) said.push("社外からつなぐのに VPN は使っていません。");
    else said.push("社外からつなぐための機器（VPN）が最新の状態かは、担当者に確かめてください。");
    if (okSig(f, "systems_updated")) said.push("会社の機器やシステムの更新も、定期的にしています。");
    if (okSig(f, "remote_desktop")) said.push("社内の PC を外から直接操作する仕組みも使っていません。");
    said.push("確認した PC にも、外から入られる設定は見つかりませんでした。");
    return said.join("");
  }

  const remote = makeScene({
    id: "remote_intrusion",
    title: "外から社内に入られたら",
    critical: true,
    pcScene: false,
    answerIds: ["telework", "vpn_used", "vpn_updated", "systems_updated", "remote_desktop"],
    evaluate(d, ctx, engine) {
      const answers = ctx.answers || {};
      const tele = { telework: ["yes"] };
      const usesVpn = list(answers.vpn_used).indexOf("yes") >= 0 && list(answers.telework).indexOf("yes") >= 0;
      // VPN ソフトが入っている PC だけで数える（入っていない PC は対象外）
      const vpnPcs = (ctx.pcs || []).filter((pc) => {
        const r = pc && pc.checks && pc.checks.vpn_client;
        return r && r.unavailable == null && r.facts && Array.isArray(r.facts.products) && r.facts.products.length > 0;
      });
      return result(engine, [
        answerSig(ctx, engine, "telework", { yes: "ok", no: "ok" }),
        answerSig(ctx, engine, "vpn_used", { yes: "ok", no: "ok" }, tele),
        // VPN 機器は国内のランサムウェアの侵入口で最も多いため、確かめていなければ bad（裁定 9）
        answerSig(ctx, engine, "vpn_updated", { yes: "ok", no: "bad" }, { telework: ["yes"], vpn_used: ["yes"] }),
        // 社外から社内につなぐ会社では、機器やシステムの更新を誰もしていなければ bad（VPN 機器と同じ理由）。
        // それ以外の会社では、社内のネットワークの場面で warn として数える
        connectsIn(answers) ? answerSig(ctx, engine, "systems_updated", { yes: "ok", no: "bad" }) : null,
        answerSig(ctx, engine, "remote_desktop", { no: "ok", yes: "warn" }, tele),
        usesVpn && vpnPcs.length > 0 ? pcSig(ctx, engine, "vpn_client", "vpn_client", null, vpnPcs) : null,
        pcSig(ctx, engine, "remote_access", "remote_access"),
        pcSig(ctx, engine, "firewall", "firewall"),
      ], [{ key: "confirm_remote", miss: list(answers.telework).indexOf("yes") >= 0 && !asked(answers, "vpn_used") }]);
    },
    say: {
      confirm_remote: { unknown: () => "社外から社内のシステムを使っているとのことですが、つなぎ方（VPN など）が安全な状態かは、まだ確かめていません。" },
      telework: { unknown: () => "社外から社内のシステムを使っているか、把握している人がいませんでした。" },
      vpn_used: { unknown: () => "社外から社内につなぐのに VPN を使っているか、把握している人がいませんでした。" },
      vpn_updated: {
        bad: () => "社外からつなぐための機器（VPN）が最新の状態か、確かめていません。古いままの VPN 機器は、ランサムウェアの侵入口として最も多く狙われています。",
        unknown: () => "社外からつなぐための機器（VPN）が最新の状態か、把握している人がいませんでした。",
      },
      systems_updated: {
        bad: () => "社外から社内につないでいるのに、VPN などの機器やシステムを定期的に更新している人がいません。古いままの VPN 機器は、ランサムウェアの侵入口として最も多く狙われています。",
        unknown: () => "会社の機器やシステムを定期的に更新しているか、把握している人がいませんでした。",
      },
      remote_desktop: {
        warn: () => "社外から社内の PC の画面を直接操作する仕組みを使っていて、パスワードが破られると中に入られます。",
        unknown: () => "社外から社内の PC を操作する仕組みを使っているか、把握している人がいませんでした。",
      },
      vpn_client: {
        warn: (s) => "VPN のソフトが入っている " + of(s, problems(s)) + "は、ソフトが古いままです。",
        bad: (s) => "VPN のソフトが入っている " + of(s, problems(s)) + "は、ソフトが古いままです。",
        unknown: (s) => pcUnknown(s, "VPN のソフト"),
      },
      remote_access: {
        warn: (s) => of(s, problems(s)) + "は、外から画面を操作できる設定がオンになっています。",
        bad: (s) => of(s, problems(s)) + "は、外から画面を操作できる設定がオンになっています。",
        unknown: (s) => pcUnknown(s, "外から操作できる設定"),
      },
      firewall: {
        warn: (s) => of(s, problems(s)) + "は、外からの接続を止める機能（ファイアウォール）がオフです。",
        bad: (s) => of(s, problems(s)) + "は、外からの接続を止める機能（ファイアウォール）がオフです。",
        unknown: (s) => pcUnknown(s, "ファイアウォール"),
      },
    },
    hint: {
      confirm_remote: "社外からのつなぎ方（VPN の有無、外から PC を操作する仕組み）を担当者に確かめてもらってください。",
      vpn_updated: "機器のメーカー名と型番を控え、最新の更新が当たっているかを業者に確かめてください。",
      systems_updated: "社外からつなぐ機器（VPN）、ルーター、業務ソフトの順に、更新を誰が受け持つかを業者と決めてください。保守の契約があれば、その範囲に更新が入っているかを確かめてください。",
      remote_desktop: "VPN を通したときだけ使えるようにし、2 段階認証を付けられるか業者に相談してください。",
      vpn_client: "PC ごとの結果の一覧で、該当する PC を確かめてください。",
      remote_access: "PC ごとの結果の一覧で、該当する PC と、その設定が業務で必要かを確かめてください。",
      firewall: "PC ごとの結果の一覧で、該当する PC を確かめてください。",
    },
    next: {
      confirm_remote: { unknown: CONFIRM },
      telework: { unknown: ASK },
      vpn_used: { unknown: ASK },
      vpn_updated: { bad: "VPN の機器が最新か、今週中に業者に確かめる", unknown: "VPN の機器が最新か業者に確かめる" },
      systems_updated: { bad: "VPN などの機器の更新を誰がするか、業者と決める", unknown: ASK },
      remote_desktop: { warn: "VPN を通したときだけ使えるようにする", unknown: ASK },
      vpn_client: { warn: (s) => problems(s) + " 台の VPN のソフトを更新する", bad: (s) => problems(s) + " 台の VPN のソフトを更新する", unknown: pcNextUnknown },
      remote_access: { warn: (s) => problems(s) + " 台で、その設定が業務で要るか確かめる", bad: (s) => problems(s) + " 台で、その設定が業務で要るか確かめる", unknown: pcNextUnknown },
      firewall: { warn: (s) => problems(s) + " 台のファイアウォールをオンにする", bad: (s) => problems(s) + " 台のファイアウォールをオンにする", unknown: pcNextUnknown },
    },
    impact: {
      bad: "外から社内に入られると、全社のデータを暗号化されたり、持ち出されたりするおそれがあります。",
      warn: "外から社内に入られる入口が残っていて、ランサムウェアの被害につながるおそれがあります。",
      unknown: "外から社内に入られにくい状態かどうか、今はわかりません。",
    },
    employee: {
      bad: "担当者に相談してください。",
      warn: "担当者に相談してください。",
      unknown: "担当者が確認する項目です。",
    },
    ok: {
      manager: (f) => remoteOk(f),
      admin: (f) => remoteOk(f),
      employee: () => "この PC に、外から入られる設定は見つかりませんでした。",
    },
    fallback: {
      bad: "外から社内に入られる入口が残っています。",
      warn: "外から社内に入られる入口が残っています。",
      unknown: "外から社内に入る入口を、把握している人がいませんでした。",
    },
    nextFallback: { bad: "VPN の機器が最新か業者に確かめる", warn: "VPN の機器が最新か業者に確かめる", unknown: ASK },
  });

  const pcLoss = makeScene({
    id: "pc_loss",
    title: "PC をなくしたら",
    critical: false,
    pcScene: true,
    answerIds: [],
    evaluate(d, ctx, engine) {
      return result(engine, [pcSig(ctx, engine, "disk_encryption", "disk_encryption"), pcSig(ctx, engine, "screen_lock", "screen_lock")]);
    },
    say: {
      disk_encryption: {
        bad: (s) => of(s, problems(s)) + "はディスクが暗号化されておらず、拾った人が中身を読めます。",
        warn: (s) => of(s, problems(s)) + "はディスクが暗号化されておらず、拾った人が中身を読めます。",
        unknown: (s) => pcUnknown(s, "ディスクの暗号化"),
      },
      screen_lock: {
        bad: (s) => lockLine(s),
        warn: (s) => lockLine(s),
        unknown: (s) => pcUnknown(s, "画面ロック"),
      },
    },
    hint: {
      disk_encryption: "Windows は BitLocker、Mac は FileVault をオンにします。回復キーは本人以外も取り出せる場所に保管してください。",
      screen_lock: "10 分以内にロックがかかり、解除にパスワードが要る設定にしてください。",
    },
    next: {
      disk_encryption: { bad: (s) => (s.checked === 1 ? "この PC の" : problems(s) + " 台の") + "暗号化をオンにする", warn: (s) => (s.checked === 1 ? "この PC の" : problems(s) + " 台の") + "暗号化をオンにする", unknown: pcNextUnknown },
      screen_lock: { bad: lockNext, warn: lockNext, unknown: pcNextUnknown },
    },
    impact: {
      bad: "PC をなくすと、中の顧客情報が読まれ、取引先への報告やお詫びが必要になるおそれがあります。",
      warn: "なくした PC によっては、中の顧客情報が読まれるおそれがあります。",
      unknown: "PC をなくしたときに中身を守れるかどうか、今はわかりません。",
    },
    employee: {
      bad: "担当者に相談して、設定を変えてください。",
      warn: "担当者に相談して、設定を変えてください。",
      unknown: "担当者に伝えてください。",
    },
    ok: {
      manager: () => "確認した PC は、なくしても中身を読まれにくい状態です。",
      admin: (f) => {
        const s = ((f && f.signals) || [])[0];
        return s && s.checked > 1 ? "確認した " + s.checked + " 台すべてで、暗号化と画面ロックが設定されています。" : "暗号化と画面ロックが設定されています。";
      },
      employee: () => "この PC は、なくしても中身を読まれにくい状態です。",
    },
    fallback: {
      bad: "なくしたときに、中身を読まれるおそれがあります。",
      warn: "なくしたときに、中身を読まれるおそれのある PC があります。",
      unknown: "PC の暗号化と画面ロックを確認できませんでした。",
    },
    nextFallback: { bad: "暗号化をオンにする", warn: "暗号化をオンにする", unknown: "社員に「自分の PC の診断」を回してもらう" },
  });

  function lockLine(s) {
    return reasonLines(s, [
      [reasonN(s, "no_password"), "パスワードなしで画面を開けるか、画面ロックがかかりません。"],
      [reasonN(s, "timeout_long"), "画面がロックされるまでの時間が 10 分より長くなっています。"],
    ], "画面ロックの設定に見直す所があります。");
  }
  function lockNext(s) {
    return reasonN(s, "no_password") ? "画面ロックの解除にパスワードを求める設定にする" : "10 分以内に画面がロックされるようにする";
  }

  function avLine(s) {
    if (s.checked === 1) {
      return reasonN(s, "no_product") ? "この PC はウイルス対策が動いていません。" : "この PC はウイルス対策の更新が古くなっています。";
    }
    const off = reasonN(s, "no_product");
    const stale = problems(s) - off;
    const parts = [];
    if (off) parts.push(s.checked + " 台中 " + off + " 台はウイルス対策が動いていません。");
    if (stale > 0) parts.push((off ? "" : s.checked + " 台中 ") + stale + " 台はウイルス対策の更新や検査が古くなっています。");
    return parts.join("");
  }

  const antivirus = makeScene({
    id: "antivirus",
    title: "ウイルス対策",
    critical: false,
    pcScene: true,
    answerIds: [],
    evaluate(d, ctx, engine) {
      return result(engine, [pcSig(ctx, engine, "antivirus", "antivirus")]);
    },
    say: {
      antivirus: { bad: avLine, warn: avLine, unknown: (s) => pcUnknown(s, "ウイルス対策") },
    },
    hint: {
      antivirus: "PC ごとの結果の一覧で、該当する PC を確かめてください。ほかの会社のウイルス対策ソフトを入れている場合も、動いていれば問題ありません。",
    },
    next: {
      antivirus: {
        bad: (s) => (s.checked === 1 ? "ウイルス対策を動かし、更新する" : problems(s) + " 台のウイルス対策を動かし、更新する"),
        warn: (s) => (s.checked === 1 ? "ウイルス対策を更新する" : problems(s) + " 台のウイルス対策を更新する"),
        unknown: pcNextUnknown,
      },
    },
    impact: {
      bad: "ウイルスが入っても気づけず、社内のほかの PC にも広がるおそれがあります。",
      warn: "新しいウイルスを見逃すおそれのある PC があります。",
      unknown: "PC がウイルスから守られているかどうか、今はわかりません。",
    },
    employee: {
      bad: "担当者に伝えてください。",
      warn: "ウイルス対策ソフトを開いて、更新してください。",
      unknown: "担当者に伝えてください。",
    },
    ok: {
      manager: () => "確認した PC では、ウイルス対策が動いていて、更新も止まっていません。",
      admin: (f) => {
        const s = ((f && f.signals) || [])[0];
        return s && s.checked > 1 ? "確認した " + s.checked + " 台すべてで動いていて、更新も 1 週間以内です。" : "ウイルス対策が動いていて、更新も 1 週間以内です。";
      },
      employee: () => "この PC のウイルス対策は動いていて、更新も止まっていません。",
    },
    fallback: {
      bad: "ウイルス対策が動いていない PC があります。",
      warn: "ウイルス対策の更新が古い PC があります。",
      unknown: "ウイルス対策の状態を確認できませんでした。",
    },
    nextFallback: { bad: "ウイルス対策を動かす", warn: "ウイルス対策を更新する", unknown: "社員に「自分の PC の診断」を回してもらう" },
  });

  function supportLine(s) {
    return reasonLines(s, [
      [reasonN(s, "past_end_of_support"), "OS のサポートがもう終わっています。新しく見つかった弱点が直りません。"],
      [reasonN(s, "support_ending"), "OS のサポートが 3 か月以内に終わります。"],
    ], "OS のサポート期限に注意が要ります。");
  }
  function supportNext(s) {
    const past = reasonN(s, "past_end_of_support");
    const n = past || reasonN(s, "support_ending") || problems(s);
    const what = past ? "OS を新しい版へ上げる" : "OS を新しい版へ上げる準備をする";
    return s.checked === 1 ? what : n + " 台の " + what;
  }

  const osUpdate = makeScene({
    id: "os_update",
    title: "OS の更新",
    critical: false,
    pcScene: true,
    answerIds: [],
    evaluate(d, ctx, engine) {
      return result(engine, [
        pcSig(ctx, engine, "os_support", "os_support"),
        pcSig(ctx, engine, "os_update", "os_update"),
        pcSig(ctx, engine, "browser", "browser"),
      ]);
    },
    say: {
      os_support: {
        bad: (s) => supportLine(s),
        warn: (s) => supportLine(s),
        unknown: (s) => pcUnknown(s, "OS のサポート期限"),
      },
      os_update: {
        bad: (s) => of(s, problems(s)) + "は、OS の更新が 1 か月以上止まっています。",
        warn: (s) => of(s, problems(s)) + "は、OS の更新が 1 か月以上止まっています。",
        unknown: (s) => pcUnknown(s, "OS の更新"),
      },
      browser: {
        warn: (s) => of(s, problems(s)) + "は、ブラウザが古いままです。",
        bad: (s) => of(s, problems(s)) + "は、ブラウザが古いままです。",
        unknown: (s) => pcUnknown(s, "ブラウザの版"),
      },
    },
    hint: {
      os_support: "サポートが終わった OS は、新しい版へ上げるか、PC の買い替えを検討してください。",
      os_update: "更新の画面で止まっている更新を当て、再起動まで済ませてもらってください。",
      browser: "ブラウザは閉じて開き直すと更新が終わることが多いので、まずブラウザの開き直しをお願いしてください。",
    },
    next: {
      os_support: {
        bad: supportNext,
        warn: supportNext,
        unknown: pcNextUnknown,
      },
      os_update: {
        bad: (s) => (s.checked === 1 ? "OS を更新する" : problems(s) + " 台の持ち主に更新をお願いする"),
        warn: (s) => (s.checked === 1 ? "OS を更新する" : problems(s) + " 台の持ち主に更新をお願いする"),
        unknown: pcNextUnknown,
      },
      browser: {
        warn: (s) => (s.checked === 1 ? "ブラウザを更新する" : problems(s) + " 台のブラウザを更新する"),
        bad: (s) => (s.checked === 1 ? "ブラウザを更新する" : problems(s) + " 台のブラウザを更新する"),
        unknown: pcNextUnknown,
      },
    },
    impact: {
      bad: "直っていない弱点からウイルスが入りやすく、業務が止まるきっかけになります。",
      warn: "更新が遅れている PC や、サポートが切れた OS の PC から、ウイルスが入りやすくなっています。",
      unknown: "PC の更新が止まっていないかどうか、今はわかりません。",
    },
    employee: {
      bad: "担当者に相談してください。",
      warn: "できる更新は済ませ、OS の入れ替えが要るものは担当者に相談してください。",
      unknown: "担当者に伝えてください。",
    },
    ok: {
      manager: () => "確認した PC は、OS もブラウザも更新されています。",
      admin: (f) => {
        const s = ((f && f.signals) || [])[0];
        return s && s.checked > 1 ? "確認した " + s.checked + " 台すべてで、OS はサポート期間内、更新も 1 か月以内、ブラウザも新しい版です。" : "OS はサポート期間内で、更新も 1 か月以内、ブラウザも新しい版です。";
      },
      employee: () => "この PC は、OS もブラウザも更新されています。",
    },
    fallback: {
      bad: "更新が止まっている PC があります。",
      warn: "更新が遅れている PC があります。",
      unknown: "OS とブラウザの更新を確認できませんでした。",
    },
    nextFallback: { bad: "OS を更新する", warn: "OS とブラウザを更新する", unknown: "社員に「自分の PC の診断」を回してもらう" },
  });

  function networkOk(f) {
    const said = [];
    if (okSig(f, "wifi_guest_separated")) said.push("来客用の Wi-Fi は分かれています。");
    if (okSig(f, "wifi_password_changed")) said.push("Wi-Fi のパスワードも変えています。");
    if (okSig(f, "nas_updated")) said.push("共有フォルダ用の機器も、最新か確かめてあります。");
    if (okSig(f, "systems_updated")) said.push("会社の機器やシステムの更新も、定期的にしています。");
    if (okSig(f, "cloud_sync")) said.push("確認した PC の同期ソフトは、会社が使っているものだけです。");
    return said.length ? said.join("") : "回答の範囲では、問題は見つかりませんでした。";
  }

  const network = makeScene({
    id: "office_network",
    title: "社内の Wi-Fi と共有フォルダ",
    critical: false,
    pcScene: false,
    answerIds: ["wifi_guest_separated", "wifi_password_changed", "nas_exists", "nas_updated", "systems_updated", "mail_service", "cloud_extra", "cloud_extra_which"],
    evaluate(d, ctx, engine) {
      const allowed = allowedCloud(ctx.answers);
      // メール・ファイル共有の質問が聞かれていない（経営者だけの回答など）ときは、方針を「決める」と促さず、この項目を数えない
      let cloud = null;
      if (asked(ctx.answers, "mail_service")) {
        cloud = pcSig(ctx, engine, "cloud_sync", "cloud_sync", { allowedCloud: allowed });
        cloud.extra = unapprovedProducts(ctx.pcs, allowed);
      }
      return result(engine, [
        answerSig(ctx, engine, "wifi_guest_separated", { separated: "ok", same: "warn" }),
        answerSig(ctx, engine, "wifi_password_changed", { yes: "ok", no: "warn" }),
        answerSig(ctx, engine, "nas_exists", { yes: "ok", no: "ok" }),
        answerSig(ctx, engine, "nas_updated", { yes: "ok", no: "warn" }, { nas_exists: ["yes"] }),
        // 社外から社内につなぐ会社では、外からの侵入の場面で数える（二重に数えない）
        connectsIn(ctx.answers) ? null : answerSig(ctx, engine, "systems_updated", { yes: "ok", no: "warn" }),
        cloud,
      ]);
    },
    say: {
      wifi_guest_separated: {
        warn: () => "来客も社員と同じ Wi-Fi を使っていて、来客の端末から社内の PC や共有フォルダが見えるおそれがあります。",
        unknown: () => "来客用の Wi-Fi が分かれているか、把握している人がいませんでした。",
      },
      wifi_password_changed: {
        warn: () => "Wi-Fi のパスワードがずっと同じで、辞めた人もつなげるおそれがあります。",
        unknown: () => "Wi-Fi のパスワードを変えているか、把握している人がいませんでした。",
      },
      nas_exists: { unknown: () => "共有フォルダ用の機器があるか、把握している人がいませんでした。" },
      nas_updated: {
        warn: () => "共有フォルダ用の機器が最新の状態か、確かめていません。",
        unknown: () => "共有フォルダ用の機器が最新の状態か、把握している人がいませんでした。",
      },
      systems_updated: {
        warn: () => "ルーターや共有フォルダの機器、業務ソフトなど、会社の機器やシステムを定期的に更新している人がいません。",
        unknown: () => "会社の機器やシステムを定期的に更新しているか、把握している人がいませんでした。",
      },
      cloud_sync: {
        warn: (s) => of(s, problems(s)) + "に、会社として使っていないクラウドの同期ソフト" + (s.extra && s.extra.length ? "（" + s.extra.join("、") + "）" : "") + "が入っています。",
        bad: (s) => of(s, problems(s)) + "に、会社として使っていないクラウドの同期ソフト" + (s.extra && s.extra.length ? "（" + s.extra.join("、") + "）" : "") + "が入っています。",
        unknown: (s) => (reasonN(s, "no_policy") ? "会社として使っているクラウドのサービスがわからないため、PC の同期ソフトが認めたものか確認できませんでした。" : pcUnknown(s, "クラウドの同期ソフト")),
      },
    },
    hint: {
      wifi_guest_separated: "Wi-Fi の機器に「ゲスト用」の設定があれば、それを使うと分けられます。",
      wifi_password_changed: "パスワードを変えたら、社員にだけ新しいものを伝えてください。",
      nas_updated: "機器の管理画面か業者に、最新の更新が当たっているかを確かめてください。",
      systems_updated: "ルーター、共有フォルダの機器、業務ソフトの更新を誰が受け持つかを業者と決めてください。保守の契約があれば、その範囲に更新が入っているかを確かめてください。",
      cloud_sync: (s) => (reasonN(s, "no_policy") ? "会社として使うメールとファイル共有のサービスを決めて、この診断の質問に答え直してください。" : "仕事のファイルを個人のクラウドに置いていないか、持ち主に聞いてください。"),
    },
    next: {
      wifi_guest_separated: { warn: "来客用の Wi-Fi を分ける", unknown: ASK },
      wifi_password_changed: { warn: "Wi-Fi のパスワードを変える", unknown: ASK },
      nas_exists: { unknown: ASK },
      nas_updated: { warn: "共有フォルダ用の機器が最新か確かめる", unknown: ASK },
      systems_updated: { warn: "機器やシステムの更新を誰がするか、業者と決める", unknown: ASK },
      cloud_sync: {
        warn: "会社で使うクラウドのサービスを決めて、社員に伝える",
        bad: "会社で使うクラウドのサービスを決めて、社員に伝える",
        unknown: (s) => (reasonN(s, "no_policy") ? "会社として使うクラウドのサービスを決める" : pcNextUnknown(s)),
      },
    },
    impact: {
      bad: "社内のデータが、会社の目の届かない所に出ていくおそれがあります。",
      warn: "社内のデータが、会社の目の届かない所から見られたり、持ち出されたりするおそれがあります。",
      unknown: "社内のネットワークとデータの置き場所が守られているかどうか、今はわかりません。",
    },
    employee: {
      bad: "仕事のファイルは、会社が決めた場所に置いてください。",
      warn: "仕事のファイルは、会社が決めた場所に置いてください。",
      unknown: "担当者が確認する項目です。",
    },
    ok: {
      manager: (f) => networkOk(f),
      admin: (f) => networkOk(f),
      employee: () => "この PC に、会社が使っていない同期ソフトは見つかりませんでした。",
    },
    fallback: {
      bad: "社内のデータが外に出ていくおそれがあります。",
      warn: "社内のネットワークに、見直したい所があります。",
      unknown: "社内のネットワークの状態を、把握している人がいませんでした。",
    },
    nextFallback: { bad: "会社で使うクラウドのサービスを決める", warn: "来客用の Wi-Fi を分ける", unknown: ASK },
  });

  function incidentOk(f) {
    const said = [];
    if (okSig(f, "incident_contact")) said.push("事故に気づいたときの最初の連絡先が決まっていて、社員にも伝わっています。");
    if (okSig(f, "security_owner")) said.push("担当者も決まっています。");
    if (okSig(f, "incident_vendor")) said.push("相談できる業者の連絡先もすぐ出せます。");
    if (okSig(f, "incident_procedure")) said.push("事故のときの手順も書いてあります。");
    if (okSig(f, "training")) said.push("社員への呼びかけもしています。");
    if (okSig(f, "rules_documented")) said.push("社員が守るルールも文書になっています。");
    return said.length ? said.join("") : "回答の範囲では、問題は見つかりませんでした。";
  }

  const incident = makeScene({
    id: "incident_response",
    title: "事故が起きたときの連絡と手順",
    critical: false,
    pcScene: false,
    answerIds: ["security_owner", "incident_contact", "incident_vendor", "incident_procedure", "training", "rules_documented"],
    evaluate(d, ctx, engine) {
      return result(engine, [
        answerSig(ctx, engine, "incident_contact", { yes: "ok", no: "warn" }),
        answerSig(ctx, engine, "security_owner", { yes: "ok", no: "warn" }),
        answerSig(ctx, engine, "incident_vendor", { yes: "ok", no: "warn" }),
        answerSig(ctx, engine, "incident_procedure", { yes: "ok", no: "warn" }),
        answerSig(ctx, engine, "training", { yes: "ok", no: "warn" }),
        answerSig(ctx, engine, "rules_documented", { yes: "ok", no: "warn" }),
      ]);
    },
    say: {
      incident_contact: {
        warn: () => "おかしいと気づいた社員が、最初に誰へ知らせればいいかが決まっていないか、伝わっていません。",
        unknown: () => "事故に気づいたときの連絡先が決まっているか、把握している人がいませんでした。",
      },
      security_owner: {
        warn: () => "会社の PC やデータを守る担当者が決まっていません。",
        unknown: () => "会社の PC やデータを守る担当者がいるか、把握している人がいませんでした。",
      },
      incident_vendor: {
        warn: () => "事故のときに相談できる業者の連絡先が、すぐには出せません。",
        unknown: () => "事故のときに相談できる業者がいるか、把握している人がいませんでした。",
      },
      incident_procedure: {
        warn: () => "事故のときにまず何をするかを書いた手順がありません。",
        unknown: () => "事故のときの手順があるか、把握している人がいませんでした。",
      },
      training: {
        warn: () => "この 1 年、怪しいメールの見分け方などを社員に伝える機会がありませんでした。",
        unknown: () => "社員に怪しいメールの見分け方などを伝えているか、把握している人がいませんでした。",
      },
      rules_documented: {
        warn: () => "社員が守るルールが文書になっていません。",
        unknown: () => "社員が守るルールが文書になっているか、把握している人がいませんでした。",
      },
    },
    hint: {
      incident_contact: "連絡先を 1 人（不在のときの代わりも 1 人）に決め、社内のチャットや掲示で全員に伝えてください。",
      security_owner: "兼任でかまわないので 1 人決め、この診断の結果を渡してください。",
      incident_vendor: "IT の保守業者か、IPA（情報処理推進機構）の相談窓口の連絡先を、社内の決まった場所に控えてください。",
      incident_procedure: "「ネットから外す」「連絡先に知らせる」「電源は切らない」の 3 つを書いた 1 枚から始めてください。",
      training: "朝礼や社内への連絡で、最近の怪しいメールの例を 1 つ見せるだけでも効果があります。",
      rules_documented: "IPA（情報処理推進機構）の「中小企業の情報セキュリティ対策ガイドライン」にあるひな型を使うと、短時間で作れます。",
    },
    next: {
      incident_contact: { warn: "最初の連絡先を決めて全員に伝える", unknown: ASK },
      security_owner: { warn: "担当者を 1 人決める", unknown: ASK },
      incident_vendor: { warn: "相談できる業者の連絡先を控える", unknown: ASK },
      incident_procedure: { warn: "事故のときの手順を 1 枚にまとめる", unknown: ASK },
      training: { warn: "怪しいメールの例を社員に見せる", unknown: ASK },
      rules_documented: { warn: "社員が守るルールを文書にする", unknown: ASK },
    },
    impact: {
      bad: "事故に気づいてから動き出すまでに時間がかかり、被害が広がるおそれがあります。",
      warn: "事故に気づいてから動き出すまでに時間がかかり、被害が広がるおそれがあります。",
      unknown: "事故が起きたときに、すぐ動ける体制かどうか、今はわかりません。",
    },
    employee: {
      bad: "おかしいと思ったら、すぐ担当者に知らせてください。",
      warn: "おかしいと思ったら、すぐ担当者に知らせてください。",
      unknown: "おかしいと思ったら、すぐ担当者に知らせてください。",
    },
    ok: {
      manager: (f) => incidentOk(f),
      admin: (f) => incidentOk(f),
      employee: () => "おかしいと思ったら、決められた連絡先へすぐ知らせてください。",
    },
    fallback: {
      bad: "事故のときの動き方が決まっていません。",
      warn: "事故のときの動き方に、足りない所があります。",
      unknown: "事故のときの動き方を、把握している人がいませんでした。",
    },
    nextFallback: { bad: "最初の連絡先を決めて全員に伝える", warn: "最初の連絡先を決めて全員に伝える", unknown: ASK },
  });

  return [ransomware, departed, email, remote, pcLoss, antivirus, osUpdate, network, incident];
})();

if (typeof module !== "undefined") module.exports = SC_SCENES;
else window.SC_SCENES = SC_SCENES;
