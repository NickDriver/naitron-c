// Package naitron is the controller SDK for the naitron-c framework (v2 wire).
package naitron

import (
	"encoding/binary"
	"os"
	"strconv"
	"strings"
)

const (
	magic     = 0x4E544331
	version   = 2
	tHELLO    = 1
	tREQUEST  = 3
	tRESPONSE = 4
	tPING     = 5
	tPONG     = 6
)

// Request is a decoded HTTP request forwarded from the gateway.
type Request struct {
	Method, Path, Query string
	Headers, Params     map[string]string
	Sub, Scope          string
	Body                []byte
}

// Handler returns (status, content_type, body).
type Handler func(Request) (int, string, []byte)

func readExact(f *os.File, n int) []byte {
	buf := make([]byte, n)
	got := 0
	for got < n {
		r, err := f.Read(buf[got:])
		if r > 0 {
			got += r
			continue
		}
		if err != nil || r == 0 {
			return nil
		}
	}
	return buf
}

func writeAll(f *os.File, data []byte) {
	for len(data) > 0 {
		n, err := f.Write(data)
		if err != nil {
			return
		}
		data = data[n:]
	}
}

func sendFrame(f *os.File, typ uint8, rid uint32, payload []byte) {
	h := make([]byte, 16)
	binary.BigEndian.PutUint32(h[0:], magic)
	h[4] = version
	h[5] = typ
	binary.BigEndian.PutUint32(h[8:], rid)
	binary.BigEndian.PutUint32(h[12:], uint32(len(payload)))
	writeAll(f, h)
	if len(payload) > 0 {
		writeAll(f, payload)
	}
}

func rdSlice16(p []byte, off int) ([]byte, int) {
	n := int(binary.BigEndian.Uint16(p[off:]))
	off += 2
	return p[off : off+n], off + n
}

func decodeRequest(p []byte) Request {
	off := 0
	var s []byte
	s, off = rdSlice16(p, off)
	method := string(s)
	s, off = rdSlice16(p, off)
	path := string(s)
	s, off = rdSlice16(p, off)
	query := string(s)
	nh := int(binary.BigEndian.Uint16(p[off:]))
	off += 2
	headers := map[string]string{}
	for i := 0; i < nh; i++ {
		var k, v []byte
		k, off = rdSlice16(p, off)
		v, off = rdSlice16(p, off)
		headers[strings.ToLower(string(k))] = string(v)
	}
	np := int(binary.BigEndian.Uint16(p[off:]))
	off += 2
	params := map[string]string{}
	for i := 0; i < np; i++ {
		var k, v []byte
		k, off = rdSlice16(p, off)
		v, off = rdSlice16(p, off)
		params[string(k)] = string(v)
	}
	var sub, scope []byte
	sub, off = rdSlice16(p, off)
	scope, off = rdSlice16(p, off)
	blen := int(binary.BigEndian.Uint32(p[off:]))
	off += 4
	return Request{method, path, query, headers, params, string(sub), string(scope), p[off : off+blen]}
}

func encodeResponse(status int, ctype string, body []byte) []byte {
	out := make([]byte, 8+len(ctype)+len(body))
	binary.BigEndian.PutUint16(out[0:], uint16(status))
	binary.BigEndian.PutUint16(out[2:], uint16(len(ctype)))
	copy(out[4:], ctype)
	o := 4 + len(ctype)
	binary.BigEndian.PutUint32(out[o:], uint32(len(body)))
	copy(out[o+4:], body)
	return out
}

// Run handles requests on the inherited socket until the core closes it.
func Run(handler Handler, name string) {
	fd, _ := strconv.Atoi(os.Getenv("NTC_CONTROLLER_FD"))
	f := os.NewFile(uintptr(fd), "ntc-controller")
	sendFrame(f, tHELLO, 0, []byte(name))
	for {
		hdr := readExact(f, 16)
		if hdr == nil {
			break
		}
		if binary.BigEndian.Uint32(hdr) != magic || hdr[4] != version {
			break
		}
		typ := hdr[5]
		rid := binary.BigEndian.Uint32(hdr[8:])
		plen := int(binary.BigEndian.Uint32(hdr[12:]))
		var payload []byte
		if plen > 0 {
			payload = readExact(f, plen)
			if payload == nil {
				break
			}
		}
		if typ == tPING {
			sendFrame(f, tPONG, rid, nil)
			continue
		}
		if typ != tREQUEST {
			continue
		}
		status, ctype, body := handler(decodeRequest(payload))
		sendFrame(f, tRESPONSE, rid, encodeResponse(status, ctype, body))
	}
}
