// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack_test

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

const (
	addr1     = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	addr2     = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	addr3     = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"
	linkAddr1 = "\x02\x02\x03\x04\x05\x06"
	linkAddr2 = "\x02\x02\x03\x04\x05\x07"
)

// TestDADDisabled tests that an address successfully resolves immediately
// when DAD is not enabled (the default for an empty stack.Options).
func TestDADDisabled(t *testing.T) {
	opts := stack.Options{}

	e := channel.New(10, 1280, linkAddr1)
	s := stack.New([]string{ipv6.ProtocolName}, []string{icmp.ProtocolName6}, opts)
	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(_) = %s", err)
	}

	if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
		t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
	}

	// Should get the address immediately since we should not have performed
	// DAD on it.
	addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("stack.GetMainNICAddress(_, _) err = %s", err)
	}
	if addr.Address != addr1 {
		t.Fatalf("got stack.GetMainNICAddress(_, _) = %s, want = %s", addr, addr1)
	}

	// We should not have sent any NDP NS messages.
	if got := s.Stats().ICMP.V6PacketsSent.NeighborSolicit.Value(); got != 0 {
		t.Fatalf("got NeighborSolicit = %d, want = 0", got)
	}
}

// TestDADResolve tests that an address successfully resolves after performing
// DAD for various values of DupAddrDetecTransmits and RetransTimer. Included in
// the subtests is a test to make sure that invalid RetransTimer (<0.5s) values
// get fixed to the default RetransTimer of 1s.
func TestDADResolve(t *testing.T) {
	tests := []struct {
		name                   string
		dupAddrDetectTransmits uint8
		retransTimer           time.Duration
		expectedRetransTimer   time.Duration
	}{
		{"1:1s:1s", 1, time.Second, time.Second},
		{"2:1s:1s", 2, time.Second, time.Second},
		{"1:2s:2s", 1, 2 * time.Second, 2 * time.Second},
		// 0s is an invalid RetransTimer timer and will be fixed to
		// the default RetransTimer value of 1s.
		{"1:0s:1s", 1, 0, time.Second},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := stack.Options{}
			opts.NDPConfigs.RetransTimer = test.retransTimer
			opts.NDPConfigs.DupAddrDetectTransmits = test.dupAddrDetectTransmits

			e := channel.New(10, 1280, linkAddr1)
			s := stack.New([]string{ipv6.ProtocolName}, []string{icmp.ProtocolName6}, opts)
			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(_) = %s", err)
			}

			if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
				t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
			}

			stat := s.Stats().ICMP.V6PacketsSent.NeighborSolicit

			// Should have sent an NDP NS immediately.
			if got := stat.Value(); got != 1 {
				t.Fatalf("got NeighborSolicit = %d, want = 1", got)

			}

			// Address should not be considered bound to the NIC yet (DAD ongoing).
			if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != tcpip.ErrNoLinkAddress {
				t.Fatalf("stack.GetMainNICAddress(_, _) = %s, %v", addr, err)
			}

			expectedTime := time.Duration(uint64(test.expectedRetransTimer) * uint64(test.dupAddrDetectTransmits))

			// Wait for 500ms less than the expectedTime to resolve
			// to make sure the address was still not resolved.
			time.Sleep(expectedTime - 500*time.Millisecond)
			if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != tcpip.ErrNoLinkAddress {
				t.Fatalf("stack.GetMainNICAddress(_, _) = %s, %v", addr, err)
			}

			// Wait for the remaining time (500ms) + 250ms, at which
			// point the address should be resolved.
			time.Sleep(750 * time.Millisecond)
			addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("stack.GetMainNICAddress(_, _) err = %s", err)
			}
			if addr.Address != addr1 {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = %s, want = %s", addr, addr1)
			}

			// Should not have sent any more NS messages.
			if got := stat.Value(); got != uint64(test.dupAddrDetectTransmits) {
				t.Fatalf("got NeighborSolicit = %d, want = %d", got, test.dupAddrDetectTransmits)
			}
		})
	}

}

// TestDADFail tests to make sure that the DAD process fails if another node is
// detected to be performing DAD on the same address (receive an NS message from
// a node doing DAD for the same address), or if another node is detected to own
// the address already (receive an NA message for the tentative address).
func TestDADFail(t *testing.T) {
	tests := []struct {
		name    string
		makeBuf func(tgt tcpip.Address) buffer.Prependable
		getStat func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter
	}{
		{
			"RxSolicit",
			func(tgt tcpip.Address) buffer.Prependable {
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.ICMPv6NeighborSolicitMinimumSize)
				pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborSolicitMinimumSize))
				pkt.SetType(header.ICMPv6NeighborSolicit)
				ns := header.NDPNeighborSolicit(pkt.Body())
				ns.SetTargetAddress(tgt)
				snmc := header.SolicitedNodeAddr(tgt)
				pkt.SetChecksum(header.ICMPv6Checksum(pkt, header.IPv6Any, snmc, buffer.VectorisedView{}))
				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(payloadLength),
					NextHeader:    uint8(icmp.ProtocolNumber6),
					HopLimit:      255,
					SrcAddr:       header.IPv6Any,
					DstAddr:       snmc,
				})

				return hdr

			},
			func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return s.NeighborSolicit
			},
		},
		{
			"RxAdvert",
			func(tgt tcpip.Address) buffer.Prependable {
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.ICMPv6NeighborAdvertSize)
				pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborAdvertSize))
				pkt.SetType(header.ICMPv6NeighborAdvert)
				na := header.NDPNeighborAdvert(pkt.Body())
				na.SetSolicitedFlag(true)
				na.SetOverrideFlag(true)
				na.SetTargetAddress(tgt)
				pkt.SetChecksum(header.ICMPv6Checksum(pkt, tgt, header.IPv6AllNodesMulticastAddress, buffer.VectorisedView{}))
				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(payloadLength),
					NextHeader:    uint8(icmp.ProtocolNumber6),
					HopLimit:      255,
					SrcAddr:       tgt,
					DstAddr:       header.IPv6AllNodesMulticastAddress,
				})

				return hdr

			},
			func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return s.NeighborAdvert
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := stack.Options{}
			opts.NDPConfigs.RetransTimer = time.Second * 2
			opts.NDPConfigs.DupAddrDetectTransmits = stack.DefaultDupAddrDetectTransmits

			e := channel.New(10, 1280, linkAddr1)
			s := stack.New([]string{ipv6.ProtocolName}, []string{icmp.ProtocolName6}, opts)
			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(_) = %s", err)
			}

			if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
				t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
			}

			// Address should not be considered bound to the NIC yet
			// (DAD ongoing).
			if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != tcpip.ErrNoLinkAddress {
				t.Fatalf("stack.GetMainNICAddress(_, _) = %s, %v", addr, err)
			}

			// Receive a packet to simulate multiple nodes owning or
			// attempting to own the same address.
			hdr := test.makeBuf(addr1)
			e.Inject(header.IPv6ProtocolNumber, hdr.View().ToVectorisedView())

			stat := test.getStat(s.Stats().ICMP.V6PacketsReceived)
			if got := stat.Value(); got != 1 {
				t.Fatalf("got stat = %d, want = 1", got)
			}

			// Wait 3 seconds to make sure that DAD did not resolve
			time.Sleep(3 * time.Second)
			if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != tcpip.ErrNoLinkAddress {
				t.Fatalf("stack.GetMainNICAddress(_, _) = %s, %v", addr, err)
			}
		})
	}
}

// TestSetNDPConfigurationsErr tests to make sure we get an error if we attempt
// to update NDP configurations using an invalid NICID.
func TestSetNDPConfigurationsErr(t *testing.T) {
	s := stack.New([]string{ipv6.ProtocolName}, []string{icmp.ProtocolName6}, stack.Options{})

	// No NIC with ID 1 yet.
	if got := s.SetNDPConfigurations(1, stack.NDPConfigurations{}); got != tcpip.ErrUnknownNICID {
		t.Fatalf("got s.SetNDPConfigurations = %v, want = %s", got, tcpip.ErrUnknownNICID)
	}
}

// TestSetNDPConfigurations tests that we can update and use per-interface NDP
// configurations without affecting the default NDP configurations or other
// interfaces' configurations.
func TestSetNDPConfigurations(t *testing.T) {
	e := channel.New(10, 1280, linkAddr1)
	s := stack.New([]string{ipv6.ProtocolName}, []string{icmp.ProtocolName6}, stack.Options{})

	// This NIC(1)'s NDP configurations will be updated to be different
	// from the default.
	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Created before updating NIC(1)'s NDP configurations but updating
	// NIC(1)'s NDP configurations should not affect other existing NICs.
	if err := s.CreateNIC(2, e); err != nil {
		t.Fatalf("CreateNIC(2) = %s", err)
	}

	// Update the NDP configurations on NIC(1) to use DAD.
	// Here we also use an invalid RetransTimer value to make sure it gets
	// fixed to the default value (1s).
	configs := stack.NDPConfigurations{
		DupAddrDetectTransmits: 1,
		RetransTimer:           0,
	}
	if err := s.SetNDPConfigurations(1, configs); err != nil {
		t.Fatalf("got SetNDPConfigurations(1, _) = %s", err)
	}

	// Created after updating NIC(1)'s NDP configurations but the stack's
	// default NDP configurations should not have been updated.
	if err := s.CreateNIC(3, e); err != nil {
		t.Fatalf("CreateNIC(3) = %s", err)
	}

	// Add addresses for each NIC.
	if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
		t.Fatalf("AddAddress(1, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
	}
	if err := s.AddAddress(2, header.IPv6ProtocolNumber, addr2); err != nil {
		t.Fatalf("AddAddress(2, %d, %s) = %s", header.IPv6ProtocolNumber, addr2, err)
	}
	if err := s.AddAddress(3, header.IPv6ProtocolNumber, addr3); err != nil {
		t.Fatalf("AddAddress(3, %d, %s) = %s", header.IPv6ProtocolNumber, addr3, err)
	}

	// Address should not be considered bound to NIC(1) yet (DAD ongoing).
	if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != tcpip.ErrNoLinkAddress {
		t.Fatalf("stack.GetMainNICAddress(1, _) = %s, %v", addr, err)
	}

	// Should get the address on NIC(2) and NIC(3) immediately since we
	// should not have performed DAD on it as the stack was configured to
	// not do DAD by default and we only updated the NDP configurations on
	// NIC(1).
	addr, err := s.GetMainNICAddress(2, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("stack.GetMainNICAddress(2, _) err = %s", err)
	}
	if addr.Address != addr2 {
		t.Fatalf("got stack.GetMainNICAddress(2, _) = %s, want = %s", addr, addr2)
	}
	addr, err = s.GetMainNICAddress(3, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("stack.GetMainNICAddress(3, _) err = %s", err)
	}
	if addr.Address != addr3 {
		t.Fatalf("got stack.GetMainNICAddress(3, _) = %s, want = %s", addr, addr3)
	}

	// Sleep for less than 1s to make sure the address didn't resolve on
	// NIC(1) (the RetransTimer should have been fixed to 1s).
	time.Sleep(500 * time.Millisecond)
	if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != tcpip.ErrNoLinkAddress {
		t.Fatalf("stack.GetMainNICAddress(1, _) = %s, %v", addr, err)
	}

	// Wait for the remaining 500ms + 250ms (to make sure DAD resolves).
	time.Sleep(time.Millisecond * 750)

	// Should get the address on NIC(1) now since DAD should have resolved.
	addr, err = s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("stack.GetMainNICAddress(1, _) err = %s", err)
	}
	if addr.Address != addr1 {
		t.Fatalf("got stack.GetMainNICAddress(1, _) = %s, want = %s", addr, addr1)
	}
}
