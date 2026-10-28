/**
 * 判定エンジン。ブラウザ（クラシックスクリプト）と bun の両方で動く。
 * 同じ入力と同じ today なら同じ出力。Date.now() は使わず、日数の差は UTC の日付で計算する。
 *
 * 状態は "ok" | "warn" | "bad" | "unknown"。reason は短い機械用の文字列
 * （needs_admin / not_supported / error / missing / unknown_check / no_product / definitions_unknown /
 *  definitions_stale / scan_stale / past_end_of_support / support_ending / no_baseline / below_min / no_policy ほか）。
 * 日本語にするのは scenes.js 側。
 *
 * evaluateCheck の ctx: { baseline, today, answers, os?, osVersion?, allowedCloud? }
 *   os            "windows" | "mac"。os_support の照合に使う（aggregatePcs は各 PC の os を入れる）。
 *   allowedCloud  回答で認めたクラウド同期サービス名の配列（小文字比較）。未指定なら cloud_sync は unknown。
 */
const SC_ENGINE = (function () {
  const CHECK_IDS = ["antivirus", "disk_encryption", "os_update", "os_support", "firewall", "screen_lock", "local_admin", "remote_access", "vpn_client", "cloud_sync", "browser"];

  function dayNumber(s) {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(typeof s === "string" ? s : "");
    if (!m) return null;
    return Math.floor(Date.UTC(+m[1], +m[2] - 1, +m[3]) / 86400000);
  }
  // from から to までの日数（to が後なら正）。読めなければ null
  function daysBetween(from, to) {
    const a = dayNumber(from), b = dayNumber(to);
    return a === null || b === null ? null : b - a;
  }
  function parts(v) {
    return String(v == null ? "" : v).split(".").map((x) => parseInt(x, 10)).map((n) => (Number.isNaN(n) ? 0 : n));
  }
  function cmpVersion(a, b) {
    const pa = parts(a), pb = parts(b);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const d = (pa[i] || 0) - (pb[i] || 0);
      if (d !== 0) return d < 0 ? -1 : 1;
    }
    return 0;
  }
  const r = (status, reason) => ({ status, reason: reason || null });

  const arr = (v) => (Array.isArray(v) ? v : []);
  const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const UNAVAILABLE = ["needs_admin", "not_supported", "error"];

  function antivirus(f, c) {
    const t = c.baseline.thresholds;
    const enabled = arr(f.products).filter((p) => p && p.enabled);
    if (enabled.length === 0) return r("bad", "no_product");
    const age = daysBetween(f.definitionsUpdatedAt, c.today);
    if (age === null) return r("unknown", "definitions_unknown");
    let status, reason = null;
    if (age <= t.avDefinitionsOkDays) status = "ok";
    else if (age <= t.avDefinitionsWarnDays) { status = "warn"; reason = "definitions_stale"; }
    else { status = "bad"; reason = "definitions_stale"; }
    if (status === "ok") {
      const scan = daysBetween(f.lastScanAt, c.today);
      if (scan !== null && scan > t.avLastScanWarnDays) return r("warn", "scan_stale");
    }
    return r(status, reason);
  }

  function osUpdate(f, c) {
    const t = c.baseline.thresholds;
    const age = daysBetween(f.lastInstalledAt, c.today);
    if (age === null) return r("unknown", "update_unknown");
    if (age <= t.osUpdateOkDays) return r("ok");
    if (age <= t.osUpdateWarnDays) return r("warn", "update_stale");
    return r("bad", "update_stale");
  }

  function windowsBuild(v) {
    const p = String(v == null ? "" : v).split(".");
    const n = parseInt(p.length >= 3 ? p[2] : p[0], 10);
    return Number.isNaN(n) ? null : n;
  }
  function macMajor(v) {
    const n = parseInt(String(v == null ? "" : v).split(".")[0], 10);
    return Number.isNaN(n) ? null : n;
  }
  function osSupport(f, c) {
    const os = c.os || (/mac/i.test(String(f.name || "")) ? "mac" : "windows");
    let key = null;
    if (os === "windows") key = windowsBuild(f.build != null ? f.build : c.osVersion);
    else key = macMajor(f.version != null ? f.version : c.osVersion);
    if (key === null) return r("unknown", "os_unknown");
    const kind = os === "windows" ? "windowsBuild" : "macMajor";
    const row = (c.baseline.osSupport || []).find((e) => e.os === os && e.match && e.match.kind === kind && key >= e.match.min && key <= e.match.max);
    if (!row) return r("unknown", "os_not_in_baseline");
    if (row.endOfSupport == null) return r("ok");
    const left = daysBetween(c.today, row.endOfSupport);
    if (left === null) return r("unknown", "os_unknown");
    if (left <= 0) return r("bad", "past_end_of_support");
    if (left <= c.baseline.thresholds.osSupportWarnDays) return r("warn", "support_ending");
    return r("ok");
  }

  function screenLock(f, c) {
    const t = c.baseline.thresholds;
    if (f.requiresPassword === false) return r("bad", "no_password");
    if (typeof f.timeoutMinutes !== "number" || f.requiresPassword == null) return r("unknown", "lock_unknown");
    if (f.timeoutMinutes <= t.screenLockOkMinutes) return r("ok");
    if (f.timeoutMinutes <= t.screenLockWarnMinutes) return r("warn", "timeout_long");
    return r("bad", "timeout_long");
  }

  function remoteAccess(f) {
    const vals = [f.rdpEnabled, f.sshEnabled, f.screenSharingEnabled];
    if (vals.some((v) => v === true)) return r("warn", "remote_enabled");
    if (vals.every((v) => v == null)) return r("unknown", "remote_unknown");
    return r("ok");
  }

  function lookup(map, name) {
    const n = String(name || "").toLowerCase();
    for (const k of Object.keys(map || {})) if (k.toLowerCase() === n) return map[k];
    return undefined;
  }
  function vpnClient(f, c) {
    const products = arr(f.products).filter(isObj);
    if (products.length === 0) return r("unknown", "no_product");
    let anyBaseline = false;
    for (const p of products) {
      const min = lookup(c.baseline.vpnMinVersion, p.name);
      if (min === undefined) continue;
      anyBaseline = true;
      if (cmpVersion(p.version, min) < 0) return r("warn", "below_min");
    }
    return anyBaseline ? r("ok") : r("ok", "no_baseline");
  }

  function cloudSync(f, c) {
    if (!Array.isArray(c.allowedCloud)) return r("unknown", "no_policy");
    const allowed = c.allowedCloud.map((x) => String(x).toLowerCase());
    const extra = arr(f.products).some((p) => allowed.indexOf(String(p).toLowerCase()) < 0);
    return extra ? r("warn", "unapproved_service") : r("ok");
  }

  function browserKey(name) {
    const n = String(name || "").toLowerCase();
    if (n.indexOf("edge") >= 0) return "edge";
    if (n.indexOf("chrome") >= 0) return "chrome";
    if (n.indexOf("firefox") >= 0) return "firefox";
    if (n.indexOf("safari") >= 0) return "safari";
    return null;
  }
  function browser(f, c) {
    let seen = 0;
    let old = false;
    for (const b of arr(f.browsers)) {
      if (!isObj(b)) continue;
      const key = browserKey(b.name);
      const min = key && c.baseline.browserMinMajor ? c.baseline.browserMinMajor[key] : undefined;
      if (min === undefined) continue;
      seen++;
      const major = parseInt(String(b.version == null ? "" : b.version).split(".")[0], 10);
      if (Number.isNaN(major)) return r("unknown", "browser_unknown");
      if (major < min) old = true;
    }
    if (seen === 0) return r("unknown", "no_product");
    return old ? r("warn", "below_min") : r("ok");
  }

  const EVALUATORS = {
    antivirus,
    disk_encryption: (f) => (f.encrypted === true ? r("ok") : f.encrypted === false ? r("bad", "not_encrypted") : r("unknown", "encryption_unknown")),
    os_update: osUpdate,
    os_support: osSupport,
    firewall: (f) => (f.enabled === true ? r("ok") : f.enabled === false ? r("warn", "firewall_off") : r("unknown", "firewall_unknown")),
    screen_lock: screenLock,
    local_admin: (f) => (f.isAdmin === false ? r("ok") : f.isAdmin === true ? r("warn", "is_admin") : r("unknown", "admin_unknown")),
    remote_access: remoteAccess,
    vpn_client: vpnClient,
    cloud_sync: cloudSync,
    browser,
  };

  // 形の崩れた結果でも例外を出さず、わからない（error）として扱う
  function evaluateCheck(checkId, result, ctx) {
    if (!result) return r("unknown", "missing");
    if (!isObj(result)) return r("unknown", "error");
    if (result.unavailable != null) return r("unknown", UNAVAILABLE.indexOf(result.unavailable) >= 0 ? result.unavailable : "error");
    const fn = Object.prototype.hasOwnProperty.call(EVALUATORS, checkId) ? EVALUATORS[checkId] : null;
    if (!fn) return r("unknown", "unknown_check");
    try {
      return fn(isObj(result.facts) ? result.facts : {}, ctx || {});
    } catch (e) {
      return r("unknown", "error");
    }
  }

  function latestPcs(pcs) {
    const byLabel = new Map();
    const order = [];
    (Array.isArray(pcs) ? pcs : []).forEach((pc, i) => {
      if (!validPc(pc)) return;
      const key = pc.label == null ? "\u0000" + i : String(pc.label);
      const prev = byLabel.get(key);
      if (!prev) { byLabel.set(key, pc); order.push(key); }
      else if (String(pc.checkedAt || "") > String(prev.checkedAt || "")) byLabel.set(key, pc);
    });
    return order.map((k) => byLabel.get(k));
  }

  function pcCheck(pc, checkId, ctx) {
    const result = isObj(pc) && isObj(pc.checks) ? pc.checks[checkId] : undefined;
    return evaluateCheck(checkId, result, Object.assign({}, ctx, { os: isObj(pc) ? pc.os : undefined, osVersion: isObj(pc) ? pc.osVersion : undefined }));
  }

  function aggregatePcs(pcs, checkId, ctx) {
    const list = Array.isArray(pcs) ? pcs : [];
    const counts = { ok: 0, warn: 0, bad: 0, unknown: 0 };
    list.forEach((pc) => {
      let st = "unknown";
      try { st = pcCheck(pc, checkId, ctx).status; } catch (e) { /* 読めなかった PC は「わからない」に数える */ }
      counts[counts[st] === undefined ? "unknown" : st]++;
    });
    const n = list.length;
    let status;
    if (n === 0) status = "unknown";
    else if (counts.bad * 2 >= n) status = "bad";
    else if (counts.bad > 0 || counts.warn > 0) status = "warn";
    else if (counts.ok === n) status = "ok";
    else status = "unknown";
    return { status, counts, checked: n };
  }

  function answerStatus(answers, questionId, map) {
    const v = answers ? answers[questionId] : undefined;
    if (v === undefined || v === null) return "unknown";
    const vals = Array.isArray(v) ? v : [v];
    if (vals.length === 0) return "unknown";
    const sts = vals.map((x) => (x === "unknown" || x === "later" ? "unknown" : (map && Object.prototype.hasOwnProperty.call(map, x) ? map[x] : "unknown")));
    return combine(sts);
  }

  function combine(statuses) {
    if (!statuses || statuses.length === 0) return "unknown";
    if (statuses.indexOf("bad") >= 0) return "bad";
    if (statuses.indexOf("unknown") >= 0) return "unknown";
    if (statuses.indexOf("warn") >= 0) return "warn";
    return "ok";
  }

  function computeLevel(sceneResults) {
    const all = sceneResults || [];
    const crit = all.filter((s) => s.critical);
    const critBad = crit.filter((s) => s.status === "bad").length;
    if (critBad >= 2) return "E";
    if (critBad === 1) return "D";
    const anyBad = all.some((s) => s.status === "bad");
    const critSoft = crit.filter((s) => s.status === "warn" || s.status === "unknown").length;
    if (anyBad || critSoft >= 2) return "C";
    const soft = all.filter((s) => s.status === "warn" || s.status === "unknown").length;
    if (soft === 0) return "A";
    return soft <= 2 ? "B" : "C";
  }

  // 読める PC の結果とは、オブジェクトで、checks もオブジェクトのもの
  function validPc(pc) { return isObj(pc) && isObj(pc.checks); }

  function countUnreadable(diagnosis) {
    const d = isObj(diagnosis) ? diagnosis : {};
    const raw = Array.isArray(d.pcs) ? d.pcs : [];
    const files = typeof d.unreadablePcFiles === "number" && d.unreadablePcFiles > 0 ? d.unreadablePcFiles : 0;
    return raw.filter((x) => !validPc(x)).length + files;
  }

  // 社員の結果ファイル（pcs.js の中身）を 1 件ずつ読み、diagnosis.pcs に足す。読めなかった数を返す。
  // raw の要素は JSON 文字列（またはオブジェクト）。壊れたものは 1 件ずつ失敗として数え、ほかには影響させない。
  function mergePcs(diagnosis, raw) {
    if (!isObj(diagnosis)) return 0;
    const list = Array.isArray(raw) ? raw : [];
    let bad = raw === undefined || raw === null || Array.isArray(raw) ? 0 : 1;
    const add = [];
    list.forEach((item) => {
      try {
        const pc = typeof item === "string" ? JSON.parse(item) : item;
        if (!validPc(pc)) throw new Error("shape");
        add.push(pc);
      } catch (e) {
        bad++;
      }
    });
    diagnosis.pcs = (Array.isArray(diagnosis.pcs) ? diagnosis.pcs : []).concat(add);
    diagnosis.unreadablePcFiles = bad;
    return bad;
  }

  function pcSummary(pcs, diagnosis, ctx) {
    const checked = pcs.length;
    let ok = 0, needsAction = 0;
    pcs.forEach((pc) => {
      // 「VPN 製品なし」「クラウド同期の方針なし」は PC の不備ではないので、PC 単位の集計では除く
      const sts = CHECK_IDS.map((id) => pcCheck(pc, id, ctx))
        .filter((x) => x.reason !== "no_policy" && !(x.reason === "no_product" && x.status === "unknown"))
        .map((x) => x.status);
      if (sts.indexOf("bad") >= 0 || sts.indexOf("warn") >= 0) needsAction++;
      else if (sts.every((s) => s === "ok")) ok++;
    });
    const co = isObj(diagnosis.company) ? diagnosis.company : {};
    // 台数が不明（未入力・0 以下・確認できた台数より少ない）なら total は null にして「全部確認できた」と扱わない
    const known = typeof co.pcCount === "number" && co.pcCount > 0 && co.pcCount >= checked;
    const total = known ? co.pcCount : null;
    return { total, checked, unchecked: known ? total - checked : null, ok, needsAction, unreadable: countUnreadable(diagnosis) };
  }

  function buildReport(diagnosis, scenes, baseline, today, questions) {
    const d = isObj(diagnosis) ? diagnosis : {};
    const pcs = latestPcs(d.pcs);
    const answers = isObj(d.answers) ? d.answers : {};
    const pcMode = d.mode === "pc";
    // 自分の PC の診断（pc モード）は、立場に関係なく本人向けの文言にする
    const role = pcMode ? "employee" : d.role;
    const ctx = { baseline, today, answers, pcs, mode: d.mode };
    const engine = api;
    const summary = pcSummary(pcs, d, ctx);
    const used = (scenes || []).filter((s) => !pcMode || s.pcScene);
    const evaluated = used.map((s) => {
      let out;
      try {
        out = s.evaluate(d, ctx, engine);
      } catch (e) {
        return { critical: !!s.critical, row: { id: s.id, title: s.title, status: "unknown", text: "この場面は、結果の形が崩れていて確かめられませんでした。", next: "担当者に伝える" } };
      }
      const facts = out.facts || {};
      const pick = (tbl, status) => {
        const f = tbl && tbl[status];
        return typeof f === "function" ? f(facts) : "";
      };
      const byRole = s.text && (s.text[role] || s.text.manager || s.text.admin);
      let status = out.status;
      let text = pick(byRole, status);
      let next = pick(s.next, status);
      // 会社の PC の台数より確認できた台数が少ないときは、確認できた分が良くても「守れている」と言わない
      if (s.pcScene && !pcMode && status === "ok" && summary.total === null) {
        status = "unknown";
        text += "ただし、会社の PC の台数がわからないため、全部の PC を確認できたかは判断できません。";
        next = "会社の PC の台数を確かめ、まだの社員に「自分の PC の診断」を回してもらう";
      } else if (s.pcScene && !pcMode && status === "ok" && summary.unchecked > 0) {
        status = "unknown";
        text += "ただし、PC は全部で " + summary.total + " 台あり、まだ " + summary.unchecked + " 台を確認できていないため、全体としては判断できません。";
        next = "残りの " + summary.unchecked + " 台の社員に「自分の PC の診断」を回してもらう";
      }
      return { critical: !!s.critical, row: { id: s.id, title: s.title, status, text, next } };
    });
    const qs = Array.isArray(questions) ? questions : [];
    const asklist = [];
    Object.keys(answers).forEach((id) => {
      const v = answers[id];
      const vals = Array.isArray(v) ? v : [v];
      if (!vals.some((x) => x === "unknown" || x === "later")) return;
      const q = qs.find((x) => x && x.id === id);
      if (q) asklist.push({ questionId: id, text: q.text, howToAsk: q.howToAsk });
    });
    return {
      level: computeLevel(evaluated.map((e) => ({ critical: e.critical, status: e.row.status }))),
      scenes: evaluated.map((e) => e.row),
      pcSummary: summary,
      asklist,
      baselineAsOf: baseline && baseline.asOf,
    };
  }

  // ---- HTML 描画（文字列を返す。値はすべてエスケープする）----
  const STATUS_LABEL = { bad: "危ない", warn: "一部危ない", unknown: "わからない", ok: "守れている" };
  const STATUS_CLASS = { bad: "bad", warn: "warn", unknown: "unk", ok: "ok" };
  const LEVEL_TEXT = {
    A: "大きな事故につながる穴は見つかりませんでした。",
    B: "大きな穴はありませんが、直したほうがよい所がいくつかあります。",
    C: "大きな事故が 1 つ起きると、業務が止まるおそれがあります。",
    D: "重大な場面に危ない所があり、事故が起きると業務への影響が大きくなります。",
    E: "重大な場面に危ない所が複数あり、早めの対応が必要です。",
  };
  const CHECK_NAME = {
    antivirus: "ウイルス対策", disk_encryption: "ディスクの暗号化", os_update: "OS の更新", os_support: "OS のサポート期限",
    firewall: "ファイアウォール", screen_lock: "画面ロック", local_admin: "管理者権限での利用", remote_access: "遠隔操作の入口",
    vpn_client: "VPN", cloud_sync: "クラウド同期", browser: "ブラウザの版",
  };
  const REASON_TEXT = {
    needs_admin: "管理者権限が必要", not_supported: "この PC では確認できません", error: "確認中にエラーが出ました", missing: "結果がありません",
    unknown_check: "確認できません", no_product: "対象の製品が見つかりません", definitions_unknown: "定義ファイルの更新日がわかりません",
    definitions_stale: "定義ファイルが古い", scan_stale: "しばらくスキャンされていません", past_end_of_support: "サポートが終了しています",
    support_ending: "サポートがまもなく終わります", os_not_in_baseline: "基準表にない OS です", os_unknown: "OS の版がわかりません",
    below_min: "版が古い", not_encrypted: "暗号化されていません", encryption_unknown: "暗号化の状態がわかりません",
    update_stale: "更新が止まっています", update_unknown: "更新日がわかりません", firewall_off: "オフになっています", firewall_unknown: "状態がわかりません",
    timeout_long: "ロックまでの時間が長い", no_password: "ロック解除にパスワードが要りません", lock_unknown: "設定がわかりません",
    is_admin: "普段から管理者の権限で使っています", admin_unknown: "権限がわかりません", remote_enabled: "遠隔操作が有効です", remote_unknown: "状態がわかりません",
    unapproved_service: "認めていないサービスが使われています", no_policy: "会社として認めたサービスが未確認です", browser_unknown: "版がわかりません",
  };

  function esc(v) {
    return String(v == null ? "" : v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function pill(status) {
    const st = STATUS_LABEL[status] ? status : "unknown";
    return '<span class="pill ' + STATUS_CLASS[st] + '">' + STATUS_LABEL[st] + "</span>";
  }
  function dateJa(s) {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(typeof s === "string" ? s : "");
    return m ? m[1] + "年" + +m[2] + "月" + +m[3] + "日" : String(s == null ? "" : s);
  }
  function navLinks(current, mode) {
    const items = [["report.html", "レポート"], ["asklist.html", "聞くことリスト"]];
    if (mode !== "pc") items.push(["pcs.html", "PC ごとの結果（担当者向け）"]);
    return '<nav class="nav">' + items.map((it) => (it[0] === current ? '<span aria-current="page">' + it[1] + "</span>" : '<a href="' + it[0] + '">' + it[1] + "</a>")).join("") + "</nav>";
  }

  function unreadableNote(n) {
    return '<div class="foot">読めなかった社員の結果ファイルが ' + esc(n) + " 件あります。ファイルが壊れているか、書き換えられている可能性があります。送った社員に、もう一度診断を動かして送り直してもらってください。</div>";
  }

  // meta: { name, date, mode } 省略可
  function renderReport(report, role, meta) {
    const m = meta || {};
    const pcMode = m.mode === "pc";
    const sm = report.pcSummary || {};
    const title = pcMode ? "あなたの PC のセキュリティ診断" : (m.name ? esc(m.name) + " セキュリティ診断" : "セキュリティ診断");
    const metaLines = [];
    if (m.date) metaLines.push(dateJa(m.date) + " 診断");
    if (!pcMode && typeof sm.total === "number") metaLines.push("PC " + sm.total + " 台中 " + sm.checked + " 台を確認");
    else if (!pcMode && typeof sm.checked === "number") metaLines.push("PC " + sm.checked + " 台を確認（全体の台数は不明）");
    const cards = (report.scenes || []).map((s) => {
      const st = STATUS_LABEL[s.status] ? s.status : "unknown";
      return '<div class="scene s-' + STATUS_CLASS[st] + '"><h3>' + esc(s.title) + " " + pill(st) + "</h3>" +
        (s.text ? "<p>" + esc(s.text) + "</p>" : "") + (s.next ? '<div class="next">→ ' + esc(s.next) + "</div>" : "") + "</div>";
    }).join("");
    const notes = [];
    if (role === "manager" && !pcMode) notes.push("担当者に確認してもらった内容があれば、答えを足して、より詳しく確かめ直せます。この結果は経営者への質問だけで出した目安です。");
    let foot = "";
    if (!pcMode && (sm.unchecked > 0 || sm.checked === 0 || sm.total === null)) {
      const head = sm.checked === 0 ? "PC は 1 台も確認できていません" + (sm.total === null ? "。" : "（未確認 " + sm.total + " 台）。")
        : sm.total === null ? "会社の PC の台数がわからないため、未確認の PC があるかどうか判断できません。"
        : "未確認の PC が " + sm.unchecked + " 台あります。";
      foot = '<div class="foot">' + head +
        "社員に「自分の PC の診断」を回してもらい、できた結果ファイルを「社員PC結果」フォルダに入れてもらうと、次の診断でこの結果に足されます。</div>";
    }
    if (!pcMode && sm.unreadable > 0) foot += unreadableNote(sm.unreadable);
    const lv = /^[A-E]$/.test(String(report.level)) ? String(report.level) : "";
    return '<div class="paper"><div class="head"><h2>' + title + '</h2><div class="meta">' + metaLines.map(esc).join("<br>") + "</div></div>" +
      navLinks("report.html", m.mode) +
      '<div class="level"><div class="grade g-' + lv + '">' + esc(lv) + '</div><p><b>' + esc(LEVEL_TEXT[lv] || "") +
      "</b><small>レベルは A〜E の目安で、安全を保証するものではありません。" +
      "基準表：" + esc(report.baselineAsOf) + " 時点</small></p></div>" +
      notes.map((n) => '<p class="note">' + esc(n) + "</p>").join("") +
      '<div class="scenes">' + cards + "</div>" + foot + "</div>";
  }

  function renderAsklist(report, meta) {
    const m = meta || {};
    const list = report.asklist || [];
    const body = list.length === 0
      ? "<p>いま、業者や担当者に確認が必要な項目はありません。</p>"
      : '<ol class="todo">' + list.map((a) => "<li><b>" + esc(a.text) + "</b><span>" + esc(a.howToAsk) + "</span></li>").join("") + "</ol>";
    return '<div class="paper"><div class="head"><h2>業者・担当者に聞くことリスト</h2><div class="meta">基準表：' + esc(report.baselineAsOf) + " 時点</div></div>" +
      navLinks("asklist.html", m.mode) +
      "<p>診断で「わからない」「あとで確認」と答えた項目と、設定を任せている業者や担当者に回した項目です。そのまま読み上げるか、メールに貼って聞いてください。</p>" + body + "</div>";
  }

  function renderPcs(diagnosis, ctx) {
    const d = isObj(diagnosis) ? diagnosis : {};
    const pcs = latestPcs(d.pcs);
    const c = Object.assign({ answers: isObj(d.answers) ? d.answers : {} }, ctx);
    let failed = 0;
    const cards = pcs.map((pc) => {
      try {
        const rows = CHECK_IDS.map((id) => {
          const res = pcCheck(pc, id, c);
          const why = typeof res.reason === "string" && Object.prototype.hasOwnProperty.call(REASON_TEXT, res.reason) ? REASON_TEXT[res.reason] : "";
          return "<tr><td>" + esc(CHECK_NAME[id]) + "</td><td>" + pill(res.status) + "</td><td>" + esc(why) + "</td></tr>";
        }).join("");
        const osName = pc.os === "mac" ? "Mac" : pc.os === "windows" ? "Windows" : "";
        return '<section class="pc"><h3>' + esc(pc.label == null ? "（名前なし）" : pc.label) + '<span class="sub">' + esc(osName) +
          (pc.checkedAt ? " ・ " + esc(dateJa(pc.checkedAt)) + " 確認" : "") + '</span></h3><div class="tablewrap"><table><thead><tr><th>項目</th><th>状態</th><th>理由</th></tr></thead><tbody>' + rows + "</tbody></table></div></section>";
      } catch (e) {
        failed++;
        return "";
      }
    }).join("");
    const unreadable = countUnreadable(d) + failed;
    return '<div class="paper"><div class="head"><h2>PC ごとの結果（担当者向け）</h2><div class="meta">確認できた PC ' + (pcs.length - failed) + " 台</div></div>" +
      navLinks("pcs.html", "company") +
      '<p class="note">担当者向けのページです。社員の名前が出ているので、経営者や社員に見せたり、共有したりするときは注意してください。</p>' +
      (unreadable > 0 ? unreadableNote(unreadable) : "") +
      (pcs.length - failed === 0 ? "<p>確認できた PC はまだありません。</p>" : cards) + "</div>";
  }

  const api = { evaluateCheck, latestPcs, aggregatePcs, answerStatus, combine, computeLevel, buildReport, mergePcs, countUnreadable, CHECK_IDS, renderReport, renderAsklist, renderPcs };
  return api;
})();

if (typeof module !== "undefined") module.exports = SC_ENGINE;
else window.SC_ENGINE = SC_ENGINE;
