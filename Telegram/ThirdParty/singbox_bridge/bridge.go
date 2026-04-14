package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/google/uuid"
)

type instance struct {
	box  *box.Box
	port int
	user string
	pass string
}

var (
	mu        sync.Mutex
	instances = map[int32]*instance{}
	nextID    int32

	errMu   sync.Mutex
	lastErr string
)

func setErr(err error) {
	errMu.Lock()
	defer errMu.Unlock()
	if err == nil {
		lastErr = ""
	} else {
		lastErr = err.Error()
	}
}

func pickFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port, nil
}

//export SingboxStart
func SingboxStart(outboundJSON *C.char) C.int {
	setErr(nil)

	outStr := C.GoString(outboundJSON)
	if outStr == "" {
		setErr(fmt.Errorf("empty outbound json"))
		return 0
	}

	port, err := pickFreePort()
	if err != nil {
		setErr(fmt.Errorf("pick port: %w", err))
		return 0
	}

	user := uuid.NewString()
	pass := uuid.NewString()

	full := fmt.Sprintf(`{
  "log": {"level": "warn", "timestamp": false},
  "inbounds": [{
    "type": "socks",
    "tag": "socks-in",
    "listen": "127.0.0.1",
    "listen_port": %d,
    "users": [{"username": %q, "password": %q}]
  }],
  "outbounds": [
    %s,
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "proxy"}
}`, port, user, pass, outStr)

	ctx := include.Context(context.Background())

	var opts option.Options
	if err := json.UnmarshalContext(ctx, []byte(full), &opts); err != nil {
		setErr(fmt.Errorf("parse config: %w", err))
		return 0
	}

	b, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		setErr(fmt.Errorf("box new: %w", err))
		return 0
	}
	if err := b.Start(); err != nil {
		_ = b.Close()
		setErr(fmt.Errorf("box start: %w", err))
		return 0
	}

	id := atomic.AddInt32(&nextID, 1)
	mu.Lock()
	instances[id] = &instance{box: b, port: port, user: user, pass: pass}
	mu.Unlock()
	return C.int(id)
}

//export SingboxStop
func SingboxStop(id C.int) C.int {
	mu.Lock()
	inst, ok := instances[int32(id)]
	if ok {
		delete(instances, int32(id))
	}
	mu.Unlock()
	if !ok {
		return 0
	}
	_ = inst.box.Close()
	return 1
}

//export SingboxGetPort
func SingboxGetPort(id C.int) C.int {
	mu.Lock()
	defer mu.Unlock()
	if inst, ok := instances[int32(id)]; ok {
		return C.int(inst.port)
	}
	return 0
}

//export SingboxGetUser
func SingboxGetUser(id C.int) *C.char {
	mu.Lock()
	defer mu.Unlock()
	if inst, ok := instances[int32(id)]; ok {
		return C.CString(inst.user)
	}
	return C.CString("")
}

//export SingboxGetPass
func SingboxGetPass(id C.int) *C.char {
	mu.Lock()
	defer mu.Unlock()
	if inst, ok := instances[int32(id)]; ok {
		return C.CString(inst.pass)
	}
	return C.CString("")
}

//export SingboxLastError
func SingboxLastError() *C.char {
	errMu.Lock()
	defer errMu.Unlock()
	return C.CString(lastErr)
}

//export SingboxFreeString
func SingboxFreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

func main() {}
