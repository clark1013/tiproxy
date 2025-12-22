// Copyright 2023 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package proxyprotocol

import (
	"fmt"
	"net"
	"regexp"

	"github.com/pingcap/tiproxy/lib/util/errors"
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
		content := fmt.Sprintf("%s", tlv.Content)
		tlvs += fmt.Sprintf("{Type: %d, Content: %s}", tlv.Typ, content)
	}
	tlvs += "]"
	awsVpcID := FindAWSVPCEndpointID(p.TLV)
	alibabaVpcID := FindAlibabaVPCID(p.TLV)
	alibabaVpcEndpointID := FindAlibabaVPCEndpointID(p.TLV)
	return fmt.Sprintf("Proxy{Version: %d, Command: %d, Src: %v, Dst: %v, TLV: %s}, AWS_VPC_ID: %s, Alibaba_VPC_ID: %s, Alibaba_VPC_Endpoint_ID: %s",
		p.Version, p.Command, p.SrcAddress, p.DstAddress, tlvs, awsVpcID, alibabaVpcID, alibabaVpcEndpointID)
}

const (
	// Amazon's extension
	PP2_TYPE_AWS            = 0xEA
	PP2_SUBTYPE_AWS_VPCE_ID = 0x01
)

var vpceRe = regexp.MustCompile("^[A-Za-z0-9-]*$")

func IsAWSVPCEndpointID(tlv ProxyTlv) bool {
	return tlv.Typ == PP2_TYPE_AWS && len(tlv.Content) > 0 && tlv.Content[0] == PP2_SUBTYPE_AWS_VPCE_ID
}

func AWSVPCEndpointID(tlv ProxyTlv) (string, error) {
	if !IsAWSVPCEndpointID(tlv) {
		return "", errors.New("not an AWS VPC endpoint ID TLV")
	}
	vpce := string(tlv.Content[1:])
	if !vpceRe.MatchString(vpce) {
		return "", errors.New("malformed AWS VPC endpoint ID TLV")
	}
	return vpce, nil
}

// FindAWSVPCEndpointID returns the first AWS VPC ID in the TLV if it exists and is well-formed.
func FindAWSVPCEndpointID(tlvs []ProxyTlv) string {
	for _, tlv := range tlvs {
		if vpc, err := AWSVPCEndpointID(tlv); err == nil && vpc != "" {
			return vpc
		}
	}
	return ""
}

const (
	PP2_TYPE_ALIBABA            = 0xE1
	PP2_TLV_VPC_ID_LEN          = 26 - 1
	PP2_TLV_VPC_ENDPOINt_ID_LEN = 24 - 1
)

func FindAlibabaVPCID(tlvs []ProxyTlv) string {
	for _, tlv := range tlvs {
		if tlv.Typ == PP2_TYPE_ALIBABA && len(string(tlv.Content)) == PP2_TLV_VPC_ID_LEN {
			return string(tlv.Content)
		}
	}
	return ""
}

func FindAlibabaVPCEndpointID(tlvs []ProxyTlv) string {
	for _, tlv := range tlvs {
		if tlv.Typ == PP2_TYPE_ALIBABA && len(string(tlv.Content)) == PP2_TLV_VPC_ENDPOINt_ID_LEN {
			return string(tlv.Content)
		}
	}
	return ""
}

type AddressWrapper interface {
	net.Addr
	Unwrap() net.Addr
}
