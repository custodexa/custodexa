package agentmcp

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/gin-gonic/gin"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"log"
	"strings"
	"time"
)

func (h *Handler) watchMCP(s *mcp.ServerSession) {
	h.mu.Lock()
	if h.watchers[s.ID()] {
		h.mu.Unlock()
		return
	}
	h.watchers[s.ID()] = true
	h.mu.Unlock()
	go func() {
		_ = s.Wait()
		h.mu.Lock()
		var entries []*ownedSession
		for handle, e := range h.sessions {
			if e.owner.MCP == s.ID() {
				entries = append(entries, e)
				delete(h.sessions, handle)
			}
		}
		delete(h.watchers, s.ID())
		h.mu.Unlock()
		for _, e := range entries {
			e.connection.Transport.Close()
			<-e.connection.Done
		}
	}()
}
func (h *Handler) watchConnection(c *gin.Context, e *ownedSession) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	credential := ""
	if fields := strings.Fields(c.GetHeader("Authorization")); len(fields) == 2 {
		credential = fields[1]
	}
	for {
		select {
		case <-e.connection.Done:
			return
		case <-e.ended:
			return
		case <-ticker.C:
			// Expiry applies to existing connections and in-flight tools, not only HTTP auth.
			identity, _ := h.ssh.AuthService.ValidateAgentToken(credential, sourceip.Of(c))
			valid := identity != nil
			sess := e.connection.Session
			if _, err := h.ssh.AuthorizationService.MatchRequestItem(*sess.AccessRequestID, sess.UserID, *sess.AssetID, sess.AccountUsername, time.Now()); err != nil {
				valid = false
			}
			if !valid {
				// Persist all-items expiry before closing. Existing revoke services also use
				// the registry path; this bounded check closes expiry and out-of-band races.
				if _, err := h.requests.ExpireApprovedItems(time.Now()); err != nil {
					log.Printf("[MCP] task expiry persistence failed session=%d: %v", sess.ID, err)
				}
				if err := h.ssh.SessionService.Terminate(sess.ID, model.EndReasonRevoked); err != nil {
					log.Printf("[MCP] session termination settlement failed session=%d: %v", sess.ID, err)
				}
				e.connection.Transport.Close()
				return
			}
		}
	}
}
