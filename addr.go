package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// DebugAddrSection represents the debug_addr section of DWARFv5.
// See DWARFv5 section 7.27 page 241 and following.
type DebugAddrSection struct {
	byteOrder binary.ByteOrder
	ptrSz     int
	data      []byte
}

func parseDebugAddr(data []byte) *DebugAddrSection {
	if len(data) == 0 {
		return nil
	}
	r := &DebugAddrSection{data: data}
	_, dwarf64, _, byteOrder := readDwarfLengthVersion(data)
	r.byteOrder = byteOrder
	data = data[6:]
	if dwarf64 {
		data = data[8:]
	}

	addrSz := data[0]
	segSelSz := data[1]
	r.ptrSz = int(addrSz + segSelSz)

	return r
}

// GetSubsection returns the subsection of debug_addr starting at addrBase
func (addr *DebugAddrSection) GetSubsection(addrBase uint64) *DebugAddr {
	if addr == nil {
		return nil
	}
	return &DebugAddr{DebugAddrSection: addr, addrBase: addrBase}
}

// DebugAddr represents a subsection of the debug_addr section with a specific base address
type DebugAddr struct {
	*DebugAddrSection
	addrBase uint64
}

// Get returns the address at index idx starting from addrBase.
func (addr *DebugAddr) Get(idx uint64) (uint64, error) {
	if addr == nil || addr.DebugAddrSection == nil {
		return 0, errors.New("debug_addr section not present")
	}
	off := idx*uint64(addr.ptrSz) + addr.addrBase
	return readUintRaw(bytes.NewReader(addr.data[off:]), addr.byteOrder, addr.ptrSz)
}

func readUintRaw(reader io.Reader, order binary.ByteOrder, ptrSize int) (uint64, error) {
	switch ptrSize {
	case 2:
		var n uint16
		if err := binary.Read(reader, order, &n); err != nil {
			return 0, err
		}
		return uint64(n), nil
	case 4:
		var n uint32
		if err := binary.Read(reader, order, &n); err != nil {
			return 0, err
		}
		return uint64(n), nil
	case 8:
		var n uint64
		if err := binary.Read(reader, order, &n); err != nil {
			return 0, err
		}
		return n, nil
	}
	return 0, fmt.Errorf("pointer size %d not supported", ptrSize)
}
