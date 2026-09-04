<div align="center">
  <img src="../assets/brand/logo.png" alt="Custodexa — Guard Access. Preserve Evidence." width="440">
</div>

<p align="center"><a href="../../README.md">English</a> | <a href="../zh-TW/README.md">繁體中文</a> | <b>日本語</b> | <a href="../README.md">他の言語 →</a></p>
<p align="center"><a href="https://custodexa.org/ja/">公式サイト</a> · <a href="https://custodexa.org/ja/docs/quickstart/">オンラインドキュメント</a></p>
<p align="center">
  <a href="https://sonarcloud.io/summary/new_code?id=custodexa_custodexa"><img src="https://sonarcloud.io/api/project_badges/measure?project=custodexa_custodexa&metric=alert_status" alt="Quality Gate"></a>
  <a href="https://sonarcloud.io/summary/new_code?id=custodexa_custodexa"><img src="https://sonarcloud.io/api/project_badges/measure?project=custodexa_custodexa&metric=security_rating" alt="Security Rating"></a>
  <a href="https://sonarcloud.io/summary/new_code?id=custodexa_custodexa"><img src="https://sonarcloud.io/api/project_badges/measure?project=custodexa_custodexa&metric=sqale_rating" alt="Maintainability Rating"></a>
  <a href="https://sonarcloud.io/summary/new_code?id=custodexa_custodexa"><img src="https://sonarcloud.io/api/project_badges/measure?project=custodexa_custodexa&metric=reliability_rating" alt="Reliability Rating"></a>
  <a href="https://github.com/custodexa/custodexa/releases"><img src="https://img.shields.io/github/v/release/custodexa/custodexa" alt="Latest release"></a>
  <a href="https://github.com/custodexa/custodexa/commits"><img src="https://img.shields.io/github/last-commit/custodexa/custodexa" alt="Last commit"></a>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="License: AGPL-3.0"></a>
</p>

**誰が何に接続し、何をしたのか。録画が答えます。**

オープンソースの特権アクセスゲートウェイです。入口はブラウザ、ターゲット側の導入は不要で、
すべての接続はポリシーを通ってから開きます。残るのは録画とコマンドの軌跡で、監査人がオフラインで検証できる
署名つきの証拠パッケージにまとまります。

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/architecture-dark.svg">
    <img alt="アーキテクチャ図。運用担当者はブラウザから Custodexa ゲートウェイ（認証ゲート、ポリシーエンジン、プロトコルプロキシ、監査、証拠エクスポート）を経由して、SSH、RDP/VNC、データベース、Kubernetes の各ターゲットへ接続します。ターゲット側へのエージェント導入は不要で、すべてのセッションが録画、コマンドログ、Ed25519 で封印された監査チェーンを残します。" src="../assets/architecture-light.svg" width="920">
  </picture>
</p>

## Custodexa を使う理由

多数のサーバーとデータベースを管理しているチームは、いずれ同じ問題に突き当たります。

- **インシデントの後に答えが出せない。** 誰が、いつ、どのマシンへ接続し、何をしたのか。
  手元にあるのはシェル履歴と推測だけです。
- **資格情報があちこちにある。** root パスワードやデータベースの資格情報がメモアプリや
  チャットで受け渡され、一人の退職が全社的な入れ替えを強います。
- **監査人は証拠を求める。** 「統制はあります」では監査は通りません。実際に提出できる
  完全な操作ログとセッション録画が必要です。

## ひとつの接続、五つのゲート

すべてのセッションが同じ道を通り、証拠はその途中で出来上がります。

| | 何をするか |
|---|---|
| **01 認証ゲート** | ローカルアカウント、LDAP と Active Directory、OIDC シングルサインオン、TOTP による多要素認証、そしてディレクトリサービスが止まった日のためのブレークグラス経路。 |
| **02 ポリシーエンジン** | 資産ごとに開放、理由必須、承認必須の三段階を設定します。承認された時点で期限つきの権限がそろい、あいだに空きはありません。「なぜこの人が接続できるのか」に答えが出せます。ロールベースの権限は、誰がどのマシンのどのアカウントを使えるかまで届きます。 |
| **03 プロトコルプロキシ** | SSH、RDP、VNC、MySQL、PostgreSQL、SQL Server、Redis、Kubernetes exec が、いずれもブラウザのタブひとつで開きます。資格情報はこの層で終端し、ブラウザには届きません。ワンタイムの接続トークンとホストキー検証を備えます。危険なコマンドとデータベースの文はその場で警告または遮断でき、クリップボードとファイル転送の内容も記録されます。 |
| **04 資格情報のローテーション** | Linux と Windows のローカルアカウントをスケジュールで変更し、新しいパスワードはターゲット上で自己検証、失敗はターゲット上でロールバックします。ローテーション証跡レポートが、アカウントごとに何日変更されていないかを示します。 |
| **05 録画と監査** | すべてのプロトコルで全セッションを録画し、再生（シーク、速度調整）できます。コマンドと文の軌跡は vim のような全画面プログラムも正しく扱います。Webhook 通知、区間を封印するチェックポイントチェーン、マニフェストと署名を収めた証拠パッケージ、オブジェクトストレージへの遠隔地コピーを備えます。 |

**完全なオープンソース、単一エディション。** エンタープライズ版も、有料で解放される機能もありません。
見えているものがすべてで、ライセンスは AGPL-3.0 です。

**導入は簡単。** docker compose のコマンドひとつ、本番構成はコンテナ四つ、出荷時から https、
起動後は外向きのネットワークを必要としません。

## 既存のやり方との比較

比べているのは方式であって、製品名ではありません。各列は一般的な形を述べたもので、
お使いの環境とは異なる場合があります。各セルの読み取り基準と確認日は
[比較ページ](https://custodexa.org/ja/docs/compare/)にあります。

| | SSH 踏み台 | VPN | オープンソース踏み台 | 商用 PAM | Custodexa |
|---|---|---|---|---|---|
| **アクセスの境界** | ホスト一台へのログインをそのまま許す | ネットワークの一区画をまとめて通す | ターゲット一台を権限の単位とする | ターゲット一台またはアカウントを権限の単位とする | 資産ごとに開放、理由必須、承認必須を設定できます |
| **接続前の承認** | 承認は置かれていない | トンネルを張るときに一度だけ権限を出す | 実装により、接続ごとの承認は置かれていない | 申請と承認の流れを備える | 承認された時点で期限つきの権限がそろい、あいだに空きはありません |
| **データベースの文の監査** | 管轄の外にある | ネットワーク層までが範囲で、文は解析しない | 実装により、一部のプロトコルを扱う | バージョンにより、備えるものもある | 実行の前に記録し、危険な文はその場でブロックできます |
| **証拠のパッケージ化** | ログから自分でまとめる | 接続ログを自分でまとめる | 記録と録画の書き出しを備える | レポートと書き出しを備える | 一つの ZIP にマニフェストと署名が入り、ファイルごとのハッシュをオフラインで検証できます |
| **資格情報のローテーション** | 人手で管理する | ディレクトリサービスに任せる | 実装により、人手で管理する | スケジュールでのローテーションを備える | Linux と Windows をスケジュールで変更し、ローテーション証跡レポートが付きます |
| **ライセンス** | OS に含まれるコンポーネントのライセンスをそのまま使う | 実装により、オープンソースと商用が並ぶ | オープンソースのライセンスが中心 | 商用の購読または買い切りライセンス | オープンソース、AGPL-3.0、コードを自分で確認できます |

## スクリーンショット

| | |
|---|---|
| ![ダッシュボード](../../screenshots/dashboard-overview.png) | ![ワークスペースの Web ターミナル](../../screenshots/workspace-terminal.png) |
| ![コマンドログ付きのセッション再生](../../screenshots/session-playback.png) | ![コマンド監査](../../screenshots/command-audit.png) |

左上から右下の順に、ダッシュボード、ワークスペースの Web ターミナル（利用者の
ウォーターマーク付き）、セッション単位のコマンドログを伴う再生画面、セッションを横断した
コマンド監査です。

## クイックスタート

```bash
git clone https://github.com/custodexa/custodexa.git
cd custodexa
bash scripts/quickstart.sh --up
```

このスクリプトは `.env` を確認し（初回はテンプレートから作成します）、未設定のシークレットを
CSPRNG で生成し、スタックを起動し、バックエンドが healthy になるまで待ってから、URL と管理者の
ログイン情報を表示します。すでに記入済みの値には手を触れません。

既定では、プラットフォーム自身のマスターキーがディスクへ書き出されることはありません。最初に
アクセスすると**マスターキー初期化ページ**が開き、キーはお使いのブラウザ内で生成されます。
必ず保管してください。再起動のたびに、再入力するまで封印された状態が続きます。無人での運用が
必要な場合は、`.env` で `env` モードまたは KMS モードへ切り替えられます。手作業で進めたい場合は、
`.env.example` を `.env` へコピーし、ファイル内の注記に従ってから `docker compose up -d` を
実行してください。Windows では WSL の中でスクリプトを実行してください。

スタックはポート 443 で https を提供し、80 はそこへリダイレクトするため、アドレスにポート番号は
付きません。そのポートを別のサービスがすでに使っているホストでは、`.env` の `TLS_HTTPS_PORT` と
`TLS_HTTP_PORT` で別の組を指定します。初期状態では自身で生成した証明書を使うため、スクリプトが表示するアドレスは、付属の認証局をインストールするまで
ブラウザの警告を伴って開きます。認証局は `/custodexa-ca.crt` からダウンロードし、接続元の
マシンへ配布してください。自前の証明書を持ち込む場合や、すでに運用しているロードバランサーへ
TLS を任せる場合は、それぞれ設定ひとつで済みます。詳細は [QUICKSTART.md](QUICKSTART.md) を
参照してください。

`admin` と、ご自身で設定した初期パスワードでログインします。初回ログインでは必須のパスワード
変更を求められ、その後に資産の登録と接続の開始へ進めます。

工場出荷時のパスワードは存在せず、4 つのシークレットはすべてご自身で設定する必要があります。
これは意図的な設計です。踏み台ホストが初期資格情報のまま稼働してよいことはありません。
設定項目の全体、開発モード、トラブルシューティングは [QUICKSTART.md](QUICKSTART.md) が扱います。

**開発に参加したい場合。** `.env` の `COMPOSE_FILE=docker-compose.dev.yml` のコメントを外すと
開発スタックへ切り替わります（フロントエンドとバックエンドのホットリロードに加え、各プロトコルの
テスト用ターゲットが含まれます）。まずは [CONTRIBUTING.md](CONTRIBUTING.md) からお読みください。

## アーキテクチャ

**バックエンド** Go · Gin · GORM · PostgreSQL 16　**フロントエンド** Vue 3 · Element Plus · Vite
**テキストターミナル** xterm.js とバックエンドの独自プロキシ　**グラフィカルプロトコル**
Apache Guacamole（guacd。RDP/VNC のみ）

システム全体を形づくっている決定が 2 つあります。

- **プロトコルのハンドシェイクはすべてバックエンドで行われます。** ブラウザはディスプレイと
  キーボードにすぎません。「フロントエンドは平文の資格情報に触れない」が成り立つのはこのためです。
  `backend/internal/proxy/` を参照してください。
- **SSH、データベース CLI、Kubernetes exec は単一のテキストターミナル基盤を共有します。**
  録画、コマンド監査、遮断、リアルタイム監視は一度だけ実装され、8 種類のプロトコルすべてに
  同じかたちで適用されます。

## ドキュメント

> README と主要な運用文書は英語・繁體中文・日本語で提供しています。API リファレンスなどの
> 参照文書は単一の言語で維持されています。翻訳の改善提案を歓迎します。

三言語のドキュメント一覧は [ドキュメント索引](../README.md) にあります。

| やりたいこと | 読むもの |
|------|------|
| 導入して運用する | [QUICKSTART.md](QUICKSTART.md)（セットアップ、設定、トラブルシューティング）、[ops/](ops/)（バックアップと復旧、アップグレード、デプロイ構成、プラットフォーム資格情報のローテーション） |
| 開発に参加する | [CONTRIBUTING.md](CONTRIBUTING.md)（DCO、作業の流れ）、[docs/dev/](../dev/)（アーキテクチャとテストの規律）、[openspec/specs/](../../openspec/specs/)（振る舞いの仕様。細部はこれが正となります） |
| API やスキーマを調べる | [docs/API_SPEC.md](../API_SPEC.md)、[docs/DB_SCHEMA.md](../DB_SCHEMA.md) |
| セキュリティ問題を報告する | [SECURITY.md](SECURITY.md)（非公開の報告窓口と対応方針） |

## 設計上の境界

導入前に知っておく価値のある点です。

- **Custodexa が統制できるのは、そこを通る接続だけです。** ターゲットホストへ直接つながる通信は
  視界の外にあります。ネットワーク層（ファイアウォールやセキュリティグループ）で直接アクセスを
  塞ぎ、踏み台を唯一の入口にしてください。
- **テキストに基づくコマンド監査には原理的な限界があります**（一部の全画面プログラムの端の
  挙動、エコーのない入力）。判断に迷う場合は、**セッション録画の再生**が真実の拠りどころです。
  実際の画面を記録したものであり、再構成も推測も含みません。
- **監査の書き込みに失敗しても接続が切られることはありません。** ただし UI は、何事もないかの
  ように振る舞うのではなく、機能が低下した状態であることを明確に示します。

## 関連プロジェクト

- [Apache Guacamole](https://guacamole.apache.org/) - クライアントレスのリモートデスクトップゲートウェイ

## ライセンス

本プロジェクトは **GNU Affero General Public License v3.0（AGPL-3.0）** のもとで公開されています。
全文は [LICENSE](../../LICENSE) を参照してください。

AGPL-3.0 のネットワーク条項（第 13 条）は、本ソフトウェアを改変してネットワークサービスとして
提供する場合、その改変版に対応する完全なソースコードを、当該サービスの利用者へも提供することを
求めています。

**単一エディション、階層なし。** エンタープライズ版も、有料での機能解放も、別ライセンスの
モジュールもありません。コントリビューションは CLA ではなく DCO のもとで受け入れます
（[CONTRIBUTING.md](CONTRIBUTING.md) を参照）。本プロジェクトは、外部からのコントリビューションを
クローズドソースのライセンスへ再ライセンスする権利を求めませんし、保有もしません。

### サードパーティコンポーネント

配布物には 218 件のサードパーティコンポーネントが含まれ、それぞれが元のライセンスを保持して
います。一覧は [THIRD-PARTY-LICENSES.md](../../THIRD-PARTY-LICENSES.md)、Apache License 2.0 の
帰属表示は [NOTICE](../../NOTICE)、ライセンス本文の写しは [`licenses/`](../../licenses/) にあります。

コンテナイメージは Alpine Linux をベースとし、別プロセスとして動作する GPL/LGPL コンポーネントを
含みます。バージョン表と、対応するソースコードの入手方法は
[THIRD-PARTY-LICENSES.md](../../THIRD-PARTY-LICENSES.md) の第 3 節にあります。ソースコードへ
到達できない場合は、リポジトリの issue でお知らせください。
