# データの形

このスキルで受け渡す 2 種類のファイルの形を定める。Claude は `diagnosis.json` を Write ツールで書き、レポートはその中身だけを読む。

## PcResult（PC 1 台の結果）

実行スクリプトが出力する。社員が担当者に渡すファイルの中身も同じ形。

```json
{
  "version": 1,
  "label": "山田",
  "checkedAt": "2026-10-24",
  "os": "windows",
  "osVersion": "10.0.26100",
  "checks": {
    "antivirus": { "facts": { "...": "..." }, "unavailable": null }
  }
}
```

- `version` は 1 固定。
- `label` は PC を見分ける名前（社員の姓など）。同じ `label` が複数あれば、`checkedAt` が新しいものだけを使う。
- `os` は `"windows"` か `"mac"`。
- `unavailable` は `null`（読めた）／`"needs_admin"`（管理者権限が必要）／`"not_supported"`（その OS にない項目）／`"error"`（読み取りに失敗）のどれか。`null` 以外のとき、判定は `unknown`。
- 日付はすべて `YYYY-MM-DD` の文字列。読めない値は `null`。
- ユーザー名、ホスト名、個人のファイルパスは入れない。

## diagnosis.json

```json
{
  "version": 1,
  "createdAt": "2026-10-24",
  "mode": "company",
  "role": "admin",
  "literacy": 2,
  "company": { "name": "サンプル商事", "pcCount": 38 },
  "answers": { "backup_exists": "yes", "backup_restore_tested": "later" },
  "pcs": [ "PcResult..." ]
}
```

| 項目 | 内容 |
|---|---|
| `mode` | `"company"`（会社全体の診断）か `"pc"`（自分の PC だけ） |
| `role` | `"manager"`（経営者）／`"admin"`（情報システム担当）／`"employee"`（社員） |
| `literacy` | 相手の詳しさ。1（不慣れ）〜3（詳しい） |
| `company.pcCount` | 会社の PC の台数。`pcs` の件数と比べて「未確認 N 台」を出す。不明なら入れない（入れない・0 以下・確認台数より少ないときは「台数不明」として PC の場面を「守れている」にしない） |
| `answers` | 質問 id をキー、選んだ選択肢の id を値にする。複数選択は配列 |
| `pcs` | PcResult の配列。1 台もなければ空配列。会社診断では空配列にし、社員の結果は `report` の `--pcs-dir` / `-PcsDir` で渡す（下記） |

### 社員の結果ファイル（pcs.js）

`report` に `--pcs-dir`（Mac）／`-PcsDir`（Windows）でフォルダを渡すと、出力フォルダに `pcs.js` ができる。`window.SC_PCS = ["<ファイル 1 の中身を JS の文字列にしたもの>", ...];` の形で、`*.json` を 1 件につき 1 つの文字列として入れる（`\` `"` `<` と改行を escape するので、中身は式として実行されない）。レポートのページが 1 件ずつ JSON として読み、`pcs` に足す。JSON として読めない、または PcResult の形（オブジェクトで `checks` を持つ）でないファイルは「読めなかった結果ファイル」として件数だけ数える。`--pcs-dir` を付けない `report` は、空の `window.SC_PCS = [];` を書く（前の結果を残さない）。

回答の予約 id は 2 つ。`"unknown"`（わからない）と `"later"`（あとで確認）。どちらも判定は `unknown` になり、聞くことリストに載る。

## 部品の id と facts

Windows と Mac で同じ形。ない項目は `null`。

| id | facts | 判定の目安 |
|---|---|---|
| `antivirus` | `products: [{name, enabled, upToDate}]`, `definitionsUpdatedAt`, `lastScanAt` | 有効な製品なし → bad。定義が 7 日以内 → ok、30 日以内 → warn、それより古い → bad。最終スキャンが 30 日より前 → warn に下げる |
| `disk_encryption` | `encrypted: bool\|null` | true → ok、false → bad |
| `os_update` | `lastInstalledAt`, `pendingCount` | 30 日以内 → ok、60 日以内 → warn、それより前 → bad |
| `os_support` | `name`, `version`, `build` | 基準表のサポート終了日を過ぎている → bad、90 日以内 → warn |
| `firewall` | `enabled: bool` | true → ok、false → warn |
| `screen_lock` | `timeoutMinutes`, `requiresPassword` | 10 分以内かつパスワードあり → ok、30 分以内 → warn、それ以外 → bad |
| `local_admin` | `isAdmin: bool` | false → ok、true → warn |
| `remote_access` | `rdpEnabled`, `sshEnabled`, `screenSharingEnabled`（ない項目は null） | すべて false → ok、どれか true → warn |
| `vpn_client` | `products: [{name, version}]` | 基準表の最低版以上 → ok、未満 → warn、製品なし → unknown |
| `cloud_sync` | `products: [name]` | 回答で認めたサービス以外がある → warn、それ以外 → ok |
| `browser` | `browsers: [{name, version}]` | すべて基準表の最低メジャー版以上 → ok、それ以外 → warn |

しきい値の実際の値は `report/baseline.js` が持つ。この表は目安。

## 状態

判定結果は 4 つのどれか。

- `ok`：守れている
- `warn`：一部危ない
- `bad`：危ない
- `unknown`：わからない（未確認、管理者権限が必要、回答が「わからない」など）
