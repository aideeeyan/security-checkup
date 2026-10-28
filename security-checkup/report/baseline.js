/**
 * 基準表（しきい値・OS のサポート期限・ブラウザ/VPN の最低版）。
 * 診断中にネットワークへは出ない。値は作成時点（asOf）の公開情報を手で写したもの。
 *
 * 出典（2026-10-24 に確認）:
 *  - Windows 11 Home/Pro: https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro
 *  - Windows 10 Home/Pro: https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro
 *  - ビルド番号:          https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
 *  - macOS:               https://support.apple.com/en-us/100100 （Apple はサポート終了日を公表しない）
 *  - Chrome 157 / Edge 156 / Firefox 158.0.1 / Safari 27 が現行安定版
 *      https://chromiumdash.appspot.com/ , https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnote-stable-channel ,
 *      https://product-details.mozilla.org/1.0/firefox_versions.json , https://support.apple.com/en-us/149039
 *
 * 方針メモ:
 *  - Windows 11 は Home/Pro の日付を使う（Enterprise/Education はこれより長い。中小企業の想定）。
 *    Microsoft の日付は太平洋時間の終了時刻で、UTC の翌日 06:59 になるため、太平洋時間の日付を書いている。
 *  - Windows 10 の 2025-10-14 は通常のサポート。有償/消費者向け ESU（延長更新）の有無は考慮しない。
 *  - macOS: Apple は終了日を公表しない。規則「最新から数えて 3 世代より古い＝サポート外」とし、
 *    現行 3 世代（27 / 26 / 15）は endOfSupport を null（期限なし＝現在サポート中）にする。
 *    外れた世代の endOfSupport は、それを 4 世代目に押し出した新世代の公開日で近似した推定値。
 *  - ブラウザ最低版: 現行安定版より約 2 世代前（Chrome は 2 週間周期のため 2 世代＝約 4 週間）。
 *    Firefox は ESR (153) 利用者を警告しないよう 153。Safari は 1 世代前の 26。
 *  - VPN: 公式の修正版を一次情報で確認できなかったため空にしている（二次情報のみの値は入れない）。
 *
 * osSupport の match の形（engine.js が os_support の facts {name, version, build} と照合する）:
 *   { kind: "windowsBuild", min: <整数>, max: <整数> }
 *       facts.build（例 "26100" または "10.0.26100.9711" の 3 番目）を整数にして min <= build <= max なら一致。
 *   { kind: "macMajor", min: <整数>, max: <整数> }
 *       facts.version（例 "26.7.1"）の先頭の数字（メジャー）を整数にして min <= major <= max なら一致。
 *   os は PcResult.os と同じ値（"windows" | "mac"）。同じ os の範囲は重ならない。
 *   どれにも一致しなければ「わからない」。endOfSupport が null は現在サポート中（期限なし）。
 *   endOfSupport が日付なら、today がそれ以降で bad、osSupportWarnDays 日以内で warn。
 */
const SC_BASELINE = {
  asOf: "2026-10-24",
  thresholds: {
    avDefinitionsOkDays: 7,
    avDefinitionsWarnDays: 30,
    avLastScanWarnDays: 30,
    osUpdateOkDays: 30,
    osUpdateWarnDays: 60,
    osSupportWarnDays: 90,
    screenLockOkMinutes: 10,
    screenLockWarnMinutes: 30,
  },
  osSupport: [
    { os: "windows", match: { kind: "windowsBuild", min: 10240, max: 21999 }, name: "Windows 10", endOfSupport: "2025-10-14" },
    { os: "windows", match: { kind: "windowsBuild", min: 22000, max: 22000 }, name: "Windows 11 21H2", endOfSupport: "2023-10-10" },
    { os: "windows", match: { kind: "windowsBuild", min: 22621, max: 22621 }, name: "Windows 11 22H2", endOfSupport: "2024-10-08" },
    { os: "windows", match: { kind: "windowsBuild", min: 22631, max: 22631 }, name: "Windows 11 23H2", endOfSupport: "2025-11-11" },
    { os: "windows", match: { kind: "windowsBuild", min: 26100, max: 26100 }, name: "Windows 11 24H2", endOfSupport: "2026-10-13" },
    { os: "windows", match: { kind: "windowsBuild", min: 26200, max: 26200 }, name: "Windows 11 25H2", endOfSupport: "2027-10-12" },
    { os: "windows", match: { kind: "windowsBuild", min: 26300, max: 26300 }, name: "Windows 11 26H2", endOfSupport: "2028-10-09" },
    { os: "windows", match: { kind: "windowsBuild", min: 28000, max: 28000 }, name: "Windows 11 26H1", endOfSupport: "2028-03-14" },
    { os: "mac", match: { kind: "macMajor", min: 10, max: 12 }, name: "macOS 12 以前", endOfSupport: "2024-09-16" },
    { os: "mac", match: { kind: "macMajor", min: 13, max: 13 }, name: "macOS Ventura 13", endOfSupport: "2025-09-15" },
    { os: "mac", match: { kind: "macMajor", min: 14, max: 14 }, name: "macOS Sonoma 14", endOfSupport: "2026-09-14" },
    { os: "mac", match: { kind: "macMajor", min: 15, max: 15 }, name: "macOS Sequoia 15", endOfSupport: null },
    { os: "mac", match: { kind: "macMajor", min: 26, max: 26 }, name: "macOS Tahoe 26", endOfSupport: null },
    { os: "mac", match: { kind: "macMajor", min: 27, max: 27 }, name: "macOS Golden Gate 27", endOfSupport: null },
  ],
  browserMinMajor: { chrome: 155, edge: 154, safari: 26, firefox: 153 },
  vpnMinVersion: {},
};

if (typeof module !== "undefined") module.exports = SC_BASELINE;
else window.SC_BASELINE = SC_BASELINE;
