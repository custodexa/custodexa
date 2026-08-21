// KEK 材料的文件化生成指令（kek-encoding-and-unseal-entry 決策 8）。
//
// **權威事實源在後端** `config.KEKGenerateCommands`；本模組只是介面側的取用入口，
// 資料放在 JSON 以便 backend 守衛（TestFrontendKEKCommandsMatchBackend）逐條比對
// ——`.env.example`、列 3b 錯誤訊息與本檔三處一致由測試強制，不是人工約定。
//
// **指令字串不翻譯**：它們是要貼進 shell 的字面。說明文字才走 i18n。
//
// 缺陷史：使用者於全新安裝時因介面只有一顆「本地生成」按鈕、沒有指令參考，
// 自行想了 `openssl rand -hex 32` 而被舊規則拒絕——那其實是一把完全正確的金鑰。
// 列出指令的目的正是讓人有現成的正確做法可抄，而不是自己編。

import data from './kek-generate-commands.json'

/** @type {{command: string, form: 'raw'|'hex'|'base64'}[]} */
export const KEK_GENERATE_COMMANDS = data.commands
