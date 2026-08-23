package session

import (
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"gorm.io/gorm"
)

const sftpDialTimeout = 5 * time.Second

// 路徑驗證錯誤：必須絕對路徑且不得含 .. 片段
var ErrInvalidRemotePath = errors.New("遠端路徑必須為絕對路徑且不得包含 ..")

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

// connect 以資產收口模式建立短連線 SFTP client；呼叫端負責 closeFn。
//
// accountID=0＝預設帳號：SFTP 獨立入口（檔案管理頁直接進）走預設帳號；
// 自會話分頁進入者由呼叫端以 AccountForSession 帶入該會話的帳號
func (s *SFTPService) connect(assetID, accountID uint) (*sftp.Client, func(), error) {
	creds, err := s.assetService.GetWithCredentialsForAccount(assetID, accountID)
	if err != nil {
		return nil, nil, err
	}
	assetRow, password, privateKey := creds.Asset, creds.Password, creds.PrivateKey
	// 零帳號資產：與連線入口同語義，明確回「無可用帳號」而非落到下方
	// 「未設定可用憑證」——後者訊息指向憑證欄，會誤導管理員去改資產表單
	if creds.AccountID == 0 {
		return nil, nil, asset.ErrAssetNoUsableAccount
	}
	if assetRow.Protocol != model.ProtocolSSH {
		return nil, nil, errors.New("僅 SSH 資產支援檔案管理")
	}

	var methods []ssh.AuthMethod
	if privateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			return nil, nil, fmt.Errorf("解析私鑰失敗: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if password != "" {
		methods = append(methods, ssh.Password(password))
	}
	if len(methods) == 0 {
		return nil, nil, errors.New("資產未設定可用憑證")
	}

	sshClient, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", assetRow.Host, assetRow.Port), &ssh.ClientConfig{
		User:            creds.Username, // 與憑證同帳號
		Auth:            methods,
		HostKeyCallback: s.hostKeys.Callback(assetRow.ID), // TOFU（host-key-verification），與 SSH 連線路徑同庫
		Timeout:         sftpDialTimeout,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("SSH 連線失敗: %w", err)
	}

	client, err := sftp.NewClient(sshClient)
	if err != nil {
		sshClient.Close()
		return nil, nil, fmt.Errorf("建立 SFTP 失敗: %w", err)
	}

	closeFn := func() {
		client.Close()
		sshClient.Close()
	}
	return client, closeFn, nil
}

// List 列出遠端目錄
func (s *SFTPService) List(assetID, accountID uint, remotePath string) ([]FileEntry, error) {
	cleaned, err := ValidateRemotePath(remotePath)
	if err != nil {
		return nil, err
	}

	client, closeFn, err := s.connect(assetID, accountID)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	infos, err := client.ReadDir(cleaned)
	if err != nil {
		return nil, fmt.Errorf("讀取目錄失敗: %w", err)
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
	return entries, nil
}

// Upload 串流上傳到遠端路徑（不落地暫存）
func (s *SFTPService) Upload(assetID, accountID uint, remotePath string, src io.Reader) (int64, error) {
	cleaned, err := ValidateRemotePath(remotePath)
	if err != nil {
		return 0, err
	}

	client, closeFn, err := s.connect(assetID, accountID)
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
func (s *SFTPService) Download(assetID, accountID uint, remotePath string) (io.ReadCloser, int64, func(), error) {
	cleaned, err := ValidateRemotePath(remotePath)
	if err != nil {
		return nil, 0, nil, err
	}

	client, closeFn, err := s.connect(assetID, accountID)
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
func (s *SFTPService) Mkdir(assetID, accountID uint, remotePath string) error {
	cleaned, err := ValidateRemotePath(remotePath)
	if err != nil {
		return err
	}

	client, closeFn, err := s.connect(assetID, accountID)
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
func (s *SFTPService) Delete(assetID, accountID uint, remotePath string) error {
	cleaned, err := ValidateRemotePath(remotePath)
	if err != nil {
		return err
	}

	client, closeFn, err := s.connect(assetID, accountID)
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
