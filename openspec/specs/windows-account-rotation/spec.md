# windows-account-rotation

## Purpose

Windows 主機本機帳號的密碼改密：經 WinRM（NTLM 認證、訊息層加密）或 SSH 到 PowerShell 兩條通道，
接入既有改密狀態機（候選憑證、三態失敗、提交、脫組、記錄、告警），密碼投遞與傳輸安全維持與 Linux 路徑同級的紅線。

## Requirements

### Requirement: 改密通道

資產 SHALL 持有「改密通道」設定，值域為 `posix_ssh`、`windows_winrm`、`windows_ssh`、`none`；未設定時 SHALL 依協定推導：ssh 協定為 `posix_ssh`，其餘為 `none`。
`windows_winrm` 與 `windows_ssh` SHALL 只允許 rdp 或 ssh 協定的資產；`posix_ssh` SHALL 只允許 ssh 協定。
通道為 `none` 的資產於改密計劃執行時 SHALL 記為 skipped 並帶「未設定改密通道」機器碼；秘密型別為 SSH 金鑰時，Windows 兩通道 SHALL 記為 skipped 並帶「秘密型別不支援」機器碼。
資產協定改為不支援該通道的值時，系統 SHALL 清空通道與其附屬欄位並於資產變更審計留痕。

#### Scenario: rdp 資產預設不改密

- **WHEN** rdp 資產未設定改密通道且被計劃涵蓋
- **THEN** 該資產記為 skipped、原因為未設定改密通道，遠端不被觸碰

#### Scenario: ssh 資產行為不變

- **WHEN** ssh 資產未設定改密通道
- **THEN** 以 `posix_ssh` 執行，行為與本能力引入前相同

#### Scenario: 協定切換清空通道

- **WHEN** 已設 `windows_winrm` 的 rdp 資產改為 vnc 協定
- **THEN** 通道與 WinRM 附屬欄位被清空，資產變更審計記錄此清空

#### Scenario: 金鑰型別不支援

- **WHEN** 秘密型別為 ssh_key 的計劃涵蓋 `windows_ssh` 資產
- **THEN** 該帳號記為 skipped、原因為秘密型別不支援

### Requirement: WinRM 傳輸不變式

`windows_winrm` 通道 SHALL 以 NTLM 認證，且 SHALL 一律啟用 WinRM 訊息層加密；系統 SHALL NOT 提供關閉加密的設定，SHALL NOT 支援 Basic 認證。
目標僅接受未加密請求時，系統 SHALL 拒絕連線並記錄「WinRM 加密不可用」機器碼，SHALL NOT 回退為明文。
WinRM 附屬設定 SHALL 含 scheme（http／https）、埠（0＝依 scheme 預設 5985／5986）、TLS 模式（僅 https：`system`／`ca`／`insecure`）與 CA 憑證（僅 `ca`）；`insecure` SHALL 於傳輸安全階梯標示風險。
上述不變式 SHALL 有機器可見的守衛：對「要求明文」的假目標拒連的測試，以及對改密模組原始碼掃描不得出現關閉加密或 Basic 認證符號的測試。

#### Scenario: 目標要求明文即拒連

- **WHEN** 目標 WinRM 服務只接受未加密請求
- **THEN** 改密記錄為 failed、原因為 WinRM 加密不可用，候選被清除，遠端未被變更

#### Scenario: https 自簽憑證需顯式 insecure

- **WHEN** 目標為 https 且憑證非系統信任亦未上傳 CA，TLS 模式為 `system`
- **THEN** 連線在指令送出前因憑證不受信任而失敗，記錄為 failed、原因為無法建立工作階段，候選清除，且不自動降級為 insecure

### Requirement: 密碼投遞與腳本契約

Windows 兩通道 SHALL 共用同一份內嵌 PowerShell 腳本，腳本文字對所有目標相同；腳本文字 SHALL NOT 含新密碼、舊密碼或帳號名；新密碼、舊密碼與帳號名 SHALL 只經標準輸入投遞（第一行新密碼、第二行舊密碼、第三行帳號名），腳本 SHALL 以 UTF-8 解碼標準輸入而 SHALL NOT 依賴宿主的主控台輸入編碼，讀取後以 SecureString 交付 `Set-LocalUser`；帳號名 SHALL 以變數交給 `Set-LocalUser` 與本機驗證器，SHALL NOT 拼接進指令文字。
標準輸入缺任一行時腳本 SHALL 在觸碰帳號前以結局碼 3 結束，系統 SHALL 將其記為 failed 並帶「密碼未投遞」機器碼，SHALL NOT 視為成功。
腳本 SHALL 在 `Set-LocalUser` 之後於目標本機驗證新密碼可登入；驗證不通過時 SHALL 當場以舊密碼改回並以結局碼 4 結束；改回也失敗時 SHALL 以結局碼 5 結束。目標機離開腳本時 SHALL 只處於「已驗證的新密碼」或「舊密碼」兩態之一，結局碼 5 為唯一例外且系統 SHALL 記為狀態不可知。
腳本 SHALL 在改密前先以舊密碼校準本機驗證器；驗證器對舊密碼回報不通過或拋出例外時，SHALL 視為驗證器不可用：改密後不做自驗、SHALL NOT 回滾，並以結局碼 6 結束，系統 SHALL 對結局碼 6 沿既有重連驗證判定結果。
`Set-LocalUser` 設定新密碼失敗時腳本 SHALL 以結局碼 1 結束（帳號未變更），錯誤原文只進錯誤串流。
腳本 SHALL 在每個結束點先於標準輸出印一行只含結局碼的結果標記，再以同一碼退出；標記 SHALL NOT 含任何密碼。結局碼的傳遞 SHALL NOT 只依賴退出碼：目標的預設 shell 可能改寫退出碼，系統 SHALL 以標記為準、退出碼為輔。
帳號名 SHALL 於送出前依 Windows 本機帳號的規則本地驗證：長度 1 至 20（以 UTF-16 碼元計）；不含 `"`、`/`、`\`、`[`、`]`、`:`、`;`、`|`、`=`、`,`、`+`、`*`、`?`、`<`、`>` 與控制字元；不可全為點或空白；首尾非空白。其餘字元（含非 ASCII 字元、`@`、`$`、單引號、中間的空白）SHALL 允許。違者 SHALL 記為 failed（未觸碰遠端）。單機回歸 SHALL 含一個帳號名同時含非 ASCII 字元與 `@` 的帳號，於 WinRM 與 SSH 兩通道各完成一次改密與驗證。舊密碼為空或含換行、歸位、NUL 時 SHALL 於送出前本地攔下並帶「現行密碼無法投遞」機器碼，遠端未被觸碰。
誠實邊界：新密碼與舊密碼於目標 PowerShell 行程記憶體中會短暫以明文存在，此為 `Set-LocalUser` 介面所致，SHALL 於文件明載。

#### Scenario: 腳本字串不含密碼

- **WHEN** 組裝任一通道的改密指令
- **THEN** 指令字串（含編碼後腳本）不含新密碼、舊密碼與帳號名，標準輸入內容為新密碼、舊密碼、帳號名各一行

#### Scenario: 每個結束點都有結果標記

- **WHEN** 檢視改密腳本文字
- **THEN** 每個 `exit` 前緊接同碼的結果標記輸出，標記文字只含結局碼

#### Scenario: 標準輸入未投遞

- **WHEN** 腳本讀到空的標準輸入或只讀到一行
- **THEN** 遠端帳號密碼未變更，記錄為 failed、原因為密碼未投遞

#### Scenario: 帳號名不合 Windows 規則被本地攔下

- **WHEN** 帳號名含反斜線、冒號或其他 Windows 本機帳號不允許的字元，或長度逾 20 個 UTF-16 碼元，或首尾為空白
- **THEN** 記錄為 failed、遠端未被觸碰、候選被清除

#### Scenario: 帳號名含非 ASCII 字元或 @ 照常改密

- **WHEN** 帳號名為 Windows 允許的名字，含非 ASCII 字元、`@`、`$` 或單引號
- **THEN** 本地驗證通過；帳號名經標準輸入第三行以 UTF-8 送達，腳本文字不含它，改密與驗證與其他帳號相同

#### Scenario: 自驗不通過即回滾

- **WHEN** `Set-LocalUser` 成功但腳本以新密碼在目標本機驗證不通過，且以舊密碼改回成功
- **THEN** 腳本以結局碼 4 結束，記錄為 failed、原因為目標自驗失敗已回滾，候選清除，舊密碼仍可登入、新密碼不可登入

#### Scenario: 自驗不通過且回滾失敗

- **WHEN** 腳本以新密碼驗證不通過，且以舊密碼改回時 `Set-LocalUser` 失敗
- **THEN** 腳本以結局碼 5 結束，記錄為 unverified、原因為目標自驗失敗且回滾失敗，候選保留交重試執行器

#### Scenario: 驗證器不可用不回滾

- **WHEN** 目標本機驗證器對舊密碼回報不通過或拋出例外
- **THEN** 改密後腳本不自驗、不回滾，以結局碼 6 結束；系統以新密碼另建連線驗證，通過即 success

#### Scenario: 舊密碼含換行被本地攔下

- **WHEN** 帳號現行密碼含換行字元
- **THEN** 記錄為 failed、原因為現行密碼無法投遞、遠端未被觸碰、候選清除

### Requirement: 驗證與失敗分流

改密後系統 SHALL 以新密碼建立新的連線（WinRM 新 session 或 SSH 新連線）執行無副作用指令，成功才提交憑證；驗證 SHALL 以固定重試序列重試，序列用盡仍失敗 SHALL 記為 unverified 並保留候選。此重連驗證 SHALL 於腳本退出碼 0 與 6 皆執行，作為目標端自驗之外的第二道。
WinRM 的失敗分流 SHALL 以「改密指令是否已送出」為閘：指令送出前無法建立工作階段（連線被拒或未回應、撥號逾時、憑證驗證失敗、交握失敗）＝failed，遠端確定未變更，候選清除，原因碼 SHALL 區分加密不可用、憑證被拒與其餘的無法建立工作階段；指令送出後回報完成＝依結局碼分流，結局碼 SHALL 以標準輸出的結果標記為準、退出碼為輔：標記存在即依標記——1（`Set-LocalUser` 失敗）、3（密碼未投遞）與 4（自驗失敗已回滾）＝failed、候選清除；5（自驗失敗且回滾失敗）＝unverified、候選保留並帶專屬原因碼；0 與 6 交重連驗證。標記缺失且退出碼非零＝結局分不清，SHALL 記 unverified 帶遠端狀態不可知、候選保留，SHALL NOT 判為確定失敗；標記缺失且退出碼 0 交重連驗證；標記值不在契約表（0、1、3、4、5、6）內同為結局分不清，SHALL 記 unverified 帶遠端狀態不可知、候選保留。指令送出後未回報完成（連線中斷、指令逾時）＝unverified 帶遠端狀態不可知；指令逾時 SHALL 兩通道同值、自指令送出起算，到期 SHALL 關閉該連線不再等待目標。SSH 通道的登入階段沿既有分流（舊憑證登入失敗＝failed），指令送出後的分流與 WinRM 相同，且 SHALL NOT 依賴目標預設 shell 對退出碼的處理（預設 shell 為 PowerShell 時目標會把非零退出碼改寫為 1，分流以標記為準不受影響）。
同一資產的多個帳號 SHALL 序列改密；系統 SHALL 對 WinRM 全域並發設上限。
單機回歸 SHALL 涵蓋自驗通過的改密（腳本以結局碼 0 結束），以及結局碼 3（標準輸入為空）、4（強制自驗不通過的回滾）、6（強制驗證器不可用）三條路徑：WinRM 各一，SSH 在目標預設 shell 為 PowerShell 與 cmd 兩種設定下各一；SSH 通道另 SHALL 涵蓋指令逾時（強制腳本停住超過逾時）於兩種預設 shell 各一。每個案例 SHALL 斷言分流的狀態與原因碼、候選處置，以及目標上此刻哪個密碼可登入。結局碼 5 只以假端點覆蓋。強制注入 SHALL 只存在於回歸專用建置，正式碼 SHALL 有守衛測試確認不含該開關。

#### Scenario: 遠端完成但退出非零

- **WHEN** `Set-LocalUser` 因權限不足失敗，腳本以結局碼 1 結束
- **THEN** 記錄為 failed、候選清除、原憑證不變

#### Scenario: 退出碼被目標預設 shell 改寫

- **WHEN** 腳本以結局碼 6 結束、標準輸出含結局碼 6 的結果標記，而系統收到的退出碼為 1
- **THEN** 依結局碼 6 處理：以新密碼另建連線驗證，通過即 success、候選提交；候選不因退出碼被清除

#### Scenario: 結果標記缺失且退出碼非零

- **WHEN** 指令回報完成、退出碼非零，標準輸出沒有可辨識的結果標記
- **THEN** 記錄為 unverified、原因為遠端狀態不可知、候選保留、本地憑證不動

#### Scenario: 結果標記值不在契約表內

- **WHEN** 指令回報完成，標準輸出的結果標記是契約表外的值
- **THEN** 記錄為 unverified、原因為遠端狀態不可知、候選保留、本地憑證不動

#### Scenario: 連線中斷

- **WHEN** 改密指令送出後連線中斷
- **THEN** 記錄為 unverified、候選保留、交重試執行器

#### Scenario: 指令逾時

- **WHEN** 改密指令送出後目標在指令逾時內未回報完成（任一通道）
- **THEN** 記錄為 unverified、原因為遠端狀態不可知、候選保留、本地憑證不動，且系統關閉該連線不再等待目標

#### Scenario: 指令送出前無法建立工作階段

- **WHEN** 目標連線被拒、撥號逾時，或對交握回非預期的狀態碼
- **THEN** 記錄為 failed、原因為無法建立工作階段、候選清除、遠端未被觸碰

#### Scenario: 結局碼 4 與 5 的分流經狀態機落地

- **WHEN** 目標回報結局碼 4
- **THEN** 記錄為 failed、原因為目標自驗失敗已回滾、候選清除、本地憑證不動
- **WHEN** 目標回報結局碼 5
- **THEN** 記錄為 unverified、原因為目標自驗失敗且回滾失敗、候選保留、本地憑證不動

#### Scenario: 回歸專用注入不進正式碼

- **WHEN** 掃描改密模組的正式原始碼
- **THEN** 不含強制自驗失敗的開關與回歸建置的符號，且掃描檔數不為零

### Requirement: SSH 到 PowerShell 通道

`windows_ssh` 通道 SHALL 沿用既有 SSH 撥號、host key 驗證與標準輸入投遞；指令 SHALL 顯式以 64 位元 `powershell.exe` 非互動模式執行內嵌腳本，SHALL NOT 依賴目標預設 shell；SHALL NOT 使用 `chpasswd`、`sudo` 或任何 POSIX 假設。
ssh 協定資產設為 `windows_ssh` 時沿資產埠；rdp 資產設為 `windows_ssh` 時 SHALL 使用改密 SSH 埠（0＝22）。

#### Scenario: Windows OpenSSH 預設 shell 為 cmd

- **WHEN** 目標 OpenSSH 預設 shell 為 cmd.exe
- **THEN** 改密仍成功，因指令顯式呼叫 powershell.exe

### Requirement: 前置條件與驗證面

文件 SHALL 列出目標機前置條件：WinRM 服務與監聽器啟用、`LocalAccountTokenFilterPolicy=1`、`AllowUnencrypted` 維持 false、Basic 維持關閉、https 時的伺服器憑證；SHALL NOT 要求設定 `TrustedHosts`（與本產品無關）。
本產品 SHALL 以持續整合環境的 Windows 單機回歸（同一台 Windows 主機兼任客戶端與目標）作為機器驗證面；文件 SHALL 明載其限制（單一 Windows Server 版本、單機回送網路）。

#### Scenario: 前置條件文件不含無關設定

- **WHEN** 客戶依文件準備目標機
- **THEN** 文件不要求 TrustedHosts，且明確要求維持 AllowUnencrypted 為 false
