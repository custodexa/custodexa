package sshproxy

// Transport is the terminal bridge's complete client-side transport contract.
// *websocket.Conn implements it without an adapter.
type Transport interface {
	ReadMessage() (int, []byte, error)
	WriteMessage(int, []byte) error
	Close() error
}
