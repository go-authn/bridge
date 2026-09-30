// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// A minimal NFSv3-over-TLS client (RFC 9289): the AUTH_TLS probe, STARTTLS,
// MOUNT MNT, then GETATTR on the handle. Taken from go-fileshare's own
// nfs_identity_test.go and tls_test.go, so both repositories speak to the
// server the same way.

// nfsMount returns 0 when MNT and GETATTR both succeed, else the first
// refusal (13 is MNT3ERR_ACCES and NFS3ERR_ACCES).
func nfsMount(addr string, pool *x509.CertPool, cert *tls.Certificate, export string) (uint32, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := rpcCall(c, 1, 7); err != nil {
		return 0, err
	}
	if verf, stat, err := rpcReply(c); err != nil || string(verf) != "STARTTLS" || stat != 0 {
		return 0, fmt.Errorf("probe: %q %d %v", verf, stat, err)
	}
	cfg := &tls.Config{RootCAs: pool, ServerName: "localhost", NextProtos: []string{"sunrpc"}}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	tc := tls.Client(c, cfg)
	if err := tc.Handshake(); err != nil {
		return 0, fmt.Errorf("handshake: %w", err)
	}
	var conn net.Conn = tc
	words := []uint32{2, 0, 2, 100005, 3, 1, 0, 0, 0, 0}
	path := []byte(export)
	pad := (4 - len(path)%4) % 4
	n := 4*len(words) + 4 + len(path) + pad
	b := make([]byte, 4, 4+n)
	be32(b, 0x80000000|uint32(n))
	for _, w := range words {
		var x [4]byte
		be32(x[:], w)
		b = append(b, x[:]...)
	}
	var l [4]byte
	be32(l[:], uint32(len(path)))
	b = append(append(append(b, l[:]...), path...), make([]byte, pad)...)
	if _, err := conn.Write(b); err != nil {
		return 0, err
	}
	body, err := rpcRecord(conn)
	if err != nil {
		return 0, err
	}
	vlen := int(getBE32(body[16:]))
	off := 20 + (vlen+3)&^3
	if getBE32(body[off:]) != 0 {
		return 0, fmt.Errorf("accept status %d", getBE32(body[off:]))
	}
	if status := getBE32(body[off+4:]); status != 0 {
		return status, nil
	}
	hlen := int(getBE32(body[off+8:]))
	return nfsGetattr(conn, body[off+12:off+12+hlen])
}

func nfsGetattr(conn net.Conn, handle []byte) (uint32, error) {
	words := []uint32{3, 0, 2, 100003, 3, 1, 0, 0, 0, 0}
	pad := (4 - len(handle)%4) % 4
	n := 4*len(words) + 4 + len(handle) + pad
	b := make([]byte, 4, 4+n)
	be32(b, 0x80000000|uint32(n))
	for _, w := range words {
		var x [4]byte
		be32(x[:], w)
		b = append(b, x[:]...)
	}
	var l [4]byte
	be32(l[:], uint32(len(handle)))
	b = append(append(append(b, l[:]...), handle...), make([]byte, pad)...)
	if _, err := conn.Write(b); err != nil {
		return 0, err
	}
	body, err := rpcRecord(conn)
	if err != nil {
		return 0, err
	}
	vlen := int(getBE32(body[16:]))
	off := 20 + (vlen+3)&^3
	if getBE32(body[off:]) != 0 {
		return 0, fmt.Errorf("accept status %d", getBE32(body[off:]))
	}
	return getBE32(body[off+4:]), nil
}

func rpcRecord(c net.Conn) ([]byte, error) {
	var mark [4]byte
	if _, err := ioReadFull(c, mark[:]); err != nil {
		return nil, err
	}
	body := make([]byte, int(getBE32(mark[:])&^0x80000000))
	if _, err := ioReadFull(c, body); err != nil {
		return nil, err
	}
	return body, nil
}

func rpcCall(c net.Conn, xid uint32, flavor uint32) error {
	words := []uint32{xid, 0, 2, 100003, 3, 0, flavor, 0, 0, 0}
	b := make([]byte, 4+4*len(words))
	be32(b, 0x80000000|uint32(4*len(words)))
	for i, w := range words {
		be32(b[4+4*i:], w)
	}
	_, err := c.Write(b)
	return err
}

func rpcReply(c net.Conn) ([]byte, uint32, error) {
	body, err := rpcRecord(c)
	if err != nil {
		return nil, 0, err
	}
	n := len(body)
	if n < 24 || getBE32(body[4:]) != 1 || getBE32(body[8:]) != 0 {
		return nil, 0, fmt.Errorf("not an accepted reply: % x", body)
	}
	vlen := int(getBE32(body[16:]))
	off := 20 + (vlen+3)&^3
	if off+4 > n {
		return nil, 0, fmt.Errorf("short reply: % x", body)
	}
	return body[20 : 20+vlen], getBE32(body[off:]), nil
}

func be32(b []byte, v uint32) { b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v) }
func getBE32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func ioReadFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
