// Command wasmopaque exposes pkg/opaque to the browser.
//
// The web console and the CLI must speak the same OPAQUE envelope format, and
// the only way to guarantee that is to run the same Go code. A JavaScript
// reimplementation would drift: the RFC 9807 messages match, the envelope
// layouts do not. This wraps pkg/opaque for js/wasm, so the browser performs
// the identical exchange the CLI performs.
//
// The password never leaves the page. It enters this module and only the wire
// messages come back out.
package main

import (
	"encoding/base64"
	"strconv"
	"sync"
	"syscall/js"

	agentsopaque "github.com/The-17/agentsecrets/pkg/opaque"
	"github.com/bytemare/opaque"
)

// The OPAQUE client cannot cross the JS boundary, so it is parked in a map and
// addressed by an opaque handle for the matching finish call. Entries are
// deleted on use: an exchange is one start and one finish.
var (
	mu      sync.Mutex
	pending = map[string]*opaque.Client{}
	nextID  int
)

func park(client *opaque.Client) string {
	mu.Lock()
	defer mu.Unlock()
	nextID++
	handle := "h" + strconv.Itoa(nextID)
	pending[handle] = client
	return handle
}

func take(handle string) (*opaque.Client, bool) {
	mu.Lock()
	defer mu.Unlock()
	client, ok := pending[handle]
	if ok {
		delete(pending, handle)
	}
	return client, ok
}

func b64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

func errObj(err error) any { return map[string]any{"error": err.Error()} }

func registerStart(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return map[string]any{"error": "password required"}
	}
	client, req, err := agentsopaque.RegisterStart(args[0].String())
	if err != nil {
		return errObj(err)
	}
	return map[string]any{"reg_request": b64(req), "handle": park(client)}
}

func registerFinish(_ js.Value, args []js.Value) any {
	if len(args) < 3 {
		return map[string]any{"error": "handle, reg_response and credential_id required"}
	}
	client, ok := take(args[0].String())
	if !ok {
		return map[string]any{"error": "unknown handle"}
	}
	regResponse, err := agentsopaque.DecodeB64(args[1].String())
	if err != nil {
		return errObj(err)
	}
	record, err := agentsopaque.RegisterFinish(client, regResponse, args[2].String())
	if err != nil {
		return errObj(err)
	}
	return map[string]any{"reg_record": b64(record)}
}

func loginStart(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return map[string]any{"error": "password required"}
	}
	client, ke1, err := agentsopaque.LoginStart(args[0].String())
	if err != nil {
		return errObj(err)
	}
	return map[string]any{"ke1": b64(ke1), "handle": park(client)}
}

func loginFinish(_ js.Value, args []js.Value) any {
	if len(args) < 3 {
		return map[string]any{"error": "handle, ke2 and credential_id required"}
	}
	client, ok := take(args[0].String())
	if !ok {
		return map[string]any{"error": "unknown handle"}
	}
	ke3, sessionKey, err := agentsopaque.LoginFinish(client, args[1].String(), args[2].String())
	if err != nil {
		return errObj(err)
	}
	return map[string]any{"ke3": b64(ke3), "session_key": b64(sessionKey)}
}

func main() {
	js.Global().Set("opaqueRegisterStart", js.FuncOf(registerStart))
	js.Global().Set("opaqueRegisterFinish", js.FuncOf(registerFinish))
	js.Global().Set("opaqueLoginStart", js.FuncOf(loginStart))
	js.Global().Set("opaqueLoginFinish", js.FuncOf(loginFinish))
	// Block forever: a js/wasm main must not return, or the runtime exits and
	// every exported function becomes unusable.
	select {}
}
