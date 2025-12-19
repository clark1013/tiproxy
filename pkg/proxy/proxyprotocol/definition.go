// Copyright 2023 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package proxyprotocol

import (
	"fmt"
	"net"
)

type ProxyVersion int

const (
	ProxyVersion2 ProxyVersion = iota + 2
)

type ProxyCommand int

const (
	ProxyCommandLocal ProxyCommand = iota
	ProxyCommandProxy
)

type ProxyAddressFamily int

const (
	ProxyAFUnspec ProxyAddressFamily = iota
	ProxyAFINet
	ProxyAFINet6
	ProxyAFUnix
)

type ProxyNetwork int

const (
	ProxyNetworkUnspec ProxyNetwork = iota
	ProxyNetworkStream
	ProxyNetworkDgram
)

type ProxyTlvType int

const (
	ProxyTlvALPN ProxyTlvType = iota + 0x01
	ProxyTlvAuthority
	ProxyTlvCRC32C
	ProxyTlvNoop
	ProxyTlvUniqueID
	ProxyTlvSSL ProxyTlvType = iota + 0x20
	ProxyTlvSSLCN
	ProxyTlvSSLCipher
	ProxyTlvSSLSignALG
	ProxyTlvSSLKeyALG
	ProxyTlvNetns ProxyTlvType = iota + 0x30
)

type ProxyTlv struct {
	Content []byte
	Typ     ProxyTlvType
}

type Proxy struct {
	SrcAddress net.Addr
	DstAddress net.Addr
	TLV        []ProxyTlv
	Version    ProxyVersion
	Command    ProxyCommand
}

func (p *Proxy) String() string {
	tlvs := "["
	for i, tlv := range p.TLV {
		if i > 0 {
			tlvs += ", "
		}
		content := fmt.Sprintf("%x", tlv.Content)
		if len(content) > 32 {
			content = content[:32] + "..."
		}
		tlvs += fmt.Sprintf("{Type: %d, Content: %s}", tlv.Typ, content)
	}
	tlvs += "]"
	return fmt.Sprintf("Proxy{Version: %d, Command: %d, Src: %v, Dst: %v, TLV: %s}",
		p.Version, p.Command, p.SrcAddress, p.DstAddress, tlvs)
}

type AddressWrapper interface {
	net.Addr
	Unwrap() net.Addr
}
