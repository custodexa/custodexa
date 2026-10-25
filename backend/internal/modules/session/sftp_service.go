package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/sshmaterial"
	"gorm.io/gorm"
)

const sftpDialTimeout = 5 * time.Second

// 路徑驗證錯誤：必須絕對路徑且不得含 .. 片段
var ErrInvalidRemotePath = errors.New("遠端路徑必須為絕對路徑且不得包含 ..")

// SFTP 撥號失敗的穩定分類：遠端送來的任何文字（離線訊息、拒絕訊息）都不進錯誤字串
var (
	ErrSFTPAuthFailed      = errors.New("SFTP 認證失敗")
	ErrSFTPDialTimeout     = errors.New("SFTP 連線逾時")
	ErrSFTPUnreachable     = errors.New("SFTP 無法連線到目標主機")
	ErrSFTPSubsystemFailed = errors.New("目標拒絕開啟 SFTP 子系統")
)

// classifySFTPDialError 把 SSH 撥號錯誤收斂為穩定分類；asset 的哨兵（私鑰無法解析、主機金鑰查核失敗、
// 主機金鑰不符）原樣透傳供 handler 分碼。
func classifySFTPDialError(err error) error {
	for _, sentinel := range []error{asset.ErrPrivateKeyInvalid, asset.ErrHostKeyCheckFailed, asset.ErrHostKeyChanged, asset.ErrAssetNoUsableAccount} {
		if errors.Is(err, sentinel) {
			return err
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrSFTPDialTimeout
	}
	if strings.Contains(err.Error(), "unable to authenticate") || strings.Contains(err.Error(), "no supported methods remain") {
		return ErrSFTPAuthFailed
	}
	return fmt.Errorf("%w (%s)", ErrSFTPUnreachable, sshmaterial.RemoteErrorClass(err))
}

// sftpAuthResult 撥號結果對應的認證結果（供憑證已送出的補記審計）
func sftpAuthResult(err error) string {
	switch {
	case err == nil:
		return asset.HostKeyAuthSucceeded
	case strings.Contains(err.Error(), "unable to authenticate") || strings.Contains(err.Error(), "no supported methods remain"):
		return asset.HostKeyAuthFailed
	default:
		return asset.HostKeyAuthUnknown
	}
}

// ErrRemoveDirNotEmpty 刪除目錄失敗（須為空目錄）——可行動指引，handler 以
// errors.Is 映射專碼，不與「底層出錯」的泛碼混為一談
var ErrRemoveDirNotEmpty = errors.New("刪除目錄失敗（須為空目錄）")

// ErrSessionAccountNotFound 以 session_id 沿用帳號時，該會話不存在／不屬於
// 本人或本資產（fail-close）
var ErrSessionAccountNotFound = errors.New("會話不存在或不屬於此使用者與資產")

// FileEntry 目錄列表項目
type FileEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime int64  `json:"mod_time"` // Unix 秒
	IsDir   bool   `json:"is_dir"`
}

// SFTPService SSH 資產的檔案操作（每請求短連線，操作完即關）
type SFTPService struct {
	assetService *asset.AssetService
	hostKeys     *asset.HostKeyService
}

// NewSFTPService 建立 SFTP 服務
func NewSFTPService(assetService *asset.AssetService, hostKeys *asset.HostKeyService) *SFTPService {
	return &SFTPService{assetService: assetService, hostKeys: hostKeys}
}

// ValidateRemotePath 驗證遠端路徑：必須絕對路徑，且原始輸入不得含 .. 片段
// （檢查須在 Clean 之前——Clean 會把 .. 解析掉，事後檢查形同虛設）
func ValidateRemotePath(p string) (string, error) {
	if !strings.HasPrefix(p, "/") {
		return "", ErrInvalidRemotePath
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == ".." {
			return "", ErrInvalidRemotePath
		}
	}
	return path.Clean(p), nil
}

// AccountForSession 自會話沿用連線帳號：檔案分頁由
// 某會話進入時，檔案操作應與該會話同帳號，否則使用者以 root 開的終端旁邊卻是
// 以 app 帳號在傳檔。以 (id, user_id, asset_id) 現查，非本人／非本資產的會話
// 一律回 ErrSessionAccountNotFound（fail-close，不退回預設帳號）。
//
// 回傳 0＝該會話未帶帳號（多帳號前的歷史會話），呼叫端據此走預設帳號。
func (s *SFTPService) AccountForSession(userID, assetID, sessionID uint) (uint, error) {
	var sess model.Session
	err := database.DB.Select("account_id").
		Where("id = ? AND user_id = ? AND asset_id = ?", sessionID, userID, assetID).
		First(&sess).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, ErrSessionAccountNotFound
		}
		return 0, fmt.Errorf("查詢會話帳號失敗: %w", err)
	}
	return sess.AccountID, nil
}

// AccountIdentity 解析檔案操作將實際使用的帳號身分（accountID=0＝預設帳號）。
// 供 handler 於連線帳號授權複查（強制點 3／3）取得判定所需的 username——
// 檔案面與終端面共用同一組帳號授權判定，不另立語義
func (s *SFTPService) AccountIdentity(assetID, accountID uint) (asset.AccountIdentity, error) {
	return s.assetService.ResolveAccountIdentity(assetID, accountID)
}

// FileOpContext 一次檔案操作的連線脈絡（host-key-verification）：主機金鑰不符時的審計、
// 觀察紀錄與告警以此記連線使用者、連線識別（自會話進入時為會話主鍵，否則 0）與來源位址。
type FileOpContext struct {
	UserID    uint
	Username  string
	SessionID uint
	ClientIP  string
}

func (op FileOpContext) hostKeyDialContext(assetID, accountID uint) asset.HostKeyDialContext {
	dc := asset.HostKeyDialContext{
		AssetID: assetID, Path: asset.HostKeyPathFileTransfer,
		UserID: op.UserID, Username: op.Username, AccountID: accountID, ClientIP: op.ClientIP,
	}
	if op.SessionID != 0 {
		dc.ConnectionRef = fmt.Sprintf("%d", op.SessionID)
	}
	return dc
}

// ListResult 列目錄的結果。HostKeyMismatch 為真表示這次連線的主機金鑰與記錄不符
// （已留痕並放行），檔案管理據此顯示警示；其他操作不帶旗標，只寫審計。
type ListResult struct {
	Entries         []FileEntry
	HostKeyMismatch bool
}

// connect 以資產收口模式建立短連線 SFTP client；呼叫端負責 closeFn。
//
// accountID=0＝預設帳號：SFTP 獨立入口（檔案管理頁直接進）走預設帳號；
// 自會話分頁進入者由呼叫端以 AccountForSession 帶入該會話的帳號。
// 回傳的主機金鑰結果供呼叫端判斷這次連線是否不符（檔案傳輸屬互動路徑，不符時留痕後放行）。
func (s *SFTPService) connect(assetID, accountID uint, op FileOpContext) (*sftp.Client, func(), *asset.HostKeyDialResult, error) {
	creds, err := s.assetService.GetWithCredentialsForAccount(assetID, accountID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer creds.Destroy()
	assetRow := creds.Asset
	// 零帳號資產：與連線入口同語義，明確回「無可用帳號」而非落到下方
	// 「未設定可用憑證」——後者訊息指向憑證欄，會誤導管理員去改資產表單
	if creds.AccountID == 0 {
		return nil, nil, nil, asset.ErrAssetNoUsableAccount
	}
	if assetRow.Protocol != model.ProtocolSSH {
		return nil, nil, nil, errors.New("僅 SSH 資產支援檔案管理")
	}

	password := sshmaterial.NewPassword(creds.Password)
	hostKeyCB, hostKeyResult := s.hostKeys.CallbackFor(op.hostKeyDialContext(assetRow.ID, creds.AccountID))
	sshClient, err := dialSFTP(context.Background(), creds, password, hostKeyCB)
	creds.Destroy()
	// 不符放行後憑證已實際送出：無論認證結果都補記（同 correlation_id）
	s.hostKeys.RecordCredentialSent(hostKeyResult, sftpAuthResult(err))
	if err != nil {
		// 交握與認證錯誤收斂為穩定分類：遠端可控的離線訊息不進日誌與回應
		return nil, nil, nil, fmt.Errorf("SSH 連線失敗: %w", classifySFTPDialError(err))
	}

	client, err := sftp.NewClient(sshClient)
	if err != nil {
		sshClient.Close()
		// 冒充主機可把剛收到的密碼塞進 channel reject／子系統拒絕訊息：只留原因碼
		return nil, nil, nil, fmt.Errorf("%w (%s)", ErrSFTPSubsystemFailed, sshmaterial.RemoteErrorClass(err))
	}

	closeFn := func() {
		client.Close()
		sshClient.Close()
	}
	return client, closeFn, hostKeyResult, nil
}

// List 列出遠端目錄
func (s *SFTPService) List(assetID, accountID uint, remotePath string, op FileOpContext) (ListResult, error) {
	cleaned, err := ValidateRemotePath(remotePath)
	if err != nil {
		return ListResult{}, err
	}

	client, closeFn, hostKey, err := s.connect(assetID, accountID, op)
	if err != nil {
		return ListResult{}, err
	}
	defer closeFn()

	infos, err := client.ReadDir(cleaned)
	if err != nil {
		return ListResult{}, fmt.Errorf("讀取目錄失敗: %w", err)
	}

	entries := make([]FileEntry, 0, len(infos))
	for _, info := range infos {
		entries = append(entries, FileEntry{
			Name:    info.Name(),
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime().Unix(),
			IsDir:   info.IsDir(),
		})
	}
	return ListResult{Entries: entries, HostKeyMismatch: hostKey.Mismatch()}, nil
}

// Upload 串流上傳到遠端路徑（不落地暫存）
func (s *SFTPService) Upload(assetID, accountID uint, remotePath string, src io.Reader, op FileOpContext) (int64, error) {
	cleaned, err := ValidateRemotePath(remotePath)
	if err != nil {
		return 0, err
	}

	client, closeFn, _, err := s.connect(assetID, accountID, op)
	if err != nil {
		return 0, err
	}
	defer closeFn()

	dst, err := client.Create(cleaned)
	if err != nil {
		return 0, fmt.Errorf("建立遠端檔案失敗: %w", err)
	}
	defer dst.Close()

	written, err := io.Copy(dst, src)
	if err != nil {
		return written, fmt.Errorf("上傳失敗: %w", err)
	}
	return written, nil
}

// Download 開啟遠端檔案供串流下載；呼叫端負責關閉回傳的 reader 與連線
func (s *SFTPService) Download(assetID, accountID uint, remotePath string, op FileOpContext) (io.ReadCloser, int64, func(), error) {
	cleaned, err := ValidateRemotePath(remotePath)
	if err != nil {
		return nil, 0, nil, err
	}

	client, closeFn, _, err := s.connect(assetID, accountID, op)
	if err != nil {
		return nil, 0, nil, err
	}

	file, err := client.Open(cleaned)
	if err != nil {
		closeFn()
		return nil, 0, nil, fmt.Errorf("開啟遠端檔案失敗: %w", err)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		closeFn()
		return nil, 0, nil, fmt.Errorf("讀取檔案資訊失敗: %w", err)
	}
	if stat.IsDir() {
		file.Close()
		closeFn()
		return nil, 0, nil, errors.New("無法下載目錄")
	}

	return file, stat.Size(), closeFn, nil
}

// Mkdir 建立遠端目錄
func (s *SFTPService) Mkdir(assetID, accountID uint, remotePath string, op FileOpContext) error {
	cleaned, err := ValidateRemotePath(remotePath)
	if err != nil {
		return err
	}

	client, closeFn, _, err := s.connect(assetID, accountID, op)
	if err != nil {
		return err
	}
	defer closeFn()

	if err := client.Mkdir(cleaned); err != nil {
		return fmt.Errorf("建立目錄失敗: %w", err)
	}
	return nil
}

// Delete 刪除遠端檔案或空目錄
func (s *SFTPService) Delete(assetID, accountID uint, remotePath string, op FileOpContext) error {
	cleaned, err := ValidateRemotePath(remotePath)
	if err != nil {
		return err
	}

	client, closeFn, _, err := s.connect(assetID, accountID, op)
	if err != nil {
		return err
	}
	defer closeFn()

	stat, err := client.Stat(cleaned)
	if err != nil {
		return fmt.Errorf("讀取目標失敗: %w", err)
	}

	if stat.IsDir() {
		if err := client.RemoveDirectory(cleaned); err != nil {
			return fmt.Errorf("%w: %w", ErrRemoveDirNotEmpty, err)
		}
		return nil
	}
	if err := client.Remove(cleaned); err != nil {
		return fmt.Errorf("刪除檔案失敗: %w", err)
	}
	return nil
}

func dialSFTP(ctx context.Context, creds *asset.AssetCredentials, password *sshmaterial.Password, hostKey ssh.HostKeyCallback) (*ssh.Client, error) {
	defer creds.Destroy()
	defer password.Destroy()
	var methods []ssh.AuthMethod
	if !creds.PrivateKey.IsEmpty() {
		// 與寫入驗證、終端撥號同一個解析函式；失敗時回包裝 asset.ErrPrivateKeyInvalid 的錯誤
		signer, err := material.Use(creds.PrivateKey, asset.ParsePrivateKey)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if !password.Empty() {
		methods = append(methods, ssh.PasswordCallback(password.Callback))
	}
	if len(methods) == 0 {
		return nil, errors.New("資產未設定可用憑證")
	}
	return sshmaterial.Dial(ctx, fmt.Sprintf("%s:%d", creds.Asset.Host, creds.Asset.Port), &ssh.ClientConfig{
		User: creds.Username, Auth: methods, HostKeyCallback: hostKey, Timeout: sftpDialTimeout,
	})
}
