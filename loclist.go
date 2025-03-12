package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/go-delve/delve/pkg/dwarf"
	"github.com/go-delve/delve/pkg/dwarf/godwarf"
	"github.com/go-delve/delve/pkg/dwarf/leb128"
)

type loclistEntry struct {
	seek          int
	lowpc, highpc uint64
	instr         []byte
}

type loclistReader interface {
	Seek(int)
	Next(*loclistEntry) bool
}

type loclistReader2 struct {
	data  []byte
	cur   int
	ptrSz int
}

func newLoclistReader2(data []byte, ptrsz int) *loclistReader2 {
	return &loclistReader2{data: data, ptrSz: ptrsz}
}

func (rdr *loclistReader2) Seek(off int) {
	rdr.cur = off
}

func (rdr *loclistReader2) read(sz int) []byte {
	r := rdr.data[rdr.cur : rdr.cur+sz]
	rdr.cur += sz
	return r
}

func (rdr *loclistReader2) oneAddr() uint64 {
	switch rdr.ptrSz {
	case 4:
		addr := binary.LittleEndian.Uint32(rdr.read(rdr.ptrSz))
		if addr == ^uint32(0) {
			return ^uint64(0)
		}
		return uint64(addr)
	case 8:
		addr := uint64(binary.LittleEndian.Uint64(rdr.read(rdr.ptrSz)))
		return addr
	default:
		panic("bad address size")
	}
}

func (rdr *loclistReader2) Next(e *loclistEntry) bool {
	//e.seek = rdr.cur
	e.lowpc = rdr.oneAddr()
	e.highpc = rdr.oneAddr()

	if e.lowpc == 0 && e.highpc == 0 {
		return false
	}

	if e.BaseAddressSelection() {
		e.instr = nil
		return true
	}

	instrlen := binary.LittleEndian.Uint16(rdr.read(2))
	e.instr = rdr.read(int(instrlen))
	return true
}

type loclistSection5 struct {
	byteOrder binary.ByteOrder
	ptrSz     int
	data      []byte
}

func newLoclistSection5(data []byte, ptrsz int) *loclistSection5 {
	return &loclistSection5{byteOrder: binary.LittleEndian, ptrSz: ptrsz, data: data}
}

func (sec *loclistSection5) ReaderFor(base uint64, debugAddr *godwarf.DebugAddr) *loclistReader5 {
	return &loclistReader5{sec: sec, debugAddr: debugAddr, buf: bytes.NewBuffer(sec.data), base: base}
}

type loclistReader5 struct {
	sec       *loclistSection5
	debugAddr *godwarf.DebugAddr
	buf       *bytes.Buffer
	base      uint64

	atEnd        bool
	instr        []byte
	defaultInstr []byte
	err          error
}

func (rdr *loclistReader5) Seek(off int) {
	rdr.buf.Next(off)
}

const (
	_DW_LLE_end_of_list      uint8 = 0x0
	_DW_LLE_base_addressx    uint8 = 0x1
	_DW_LLE_startx_endx      uint8 = 0x2
	_DW_LLE_startx_length    uint8 = 0x3
	_DW_LLE_offset_pair      uint8 = 0x4
	_DW_LLE_default_location uint8 = 0x5
	_DW_LLE_base_address     uint8 = 0x6
	_DW_LLE_start_end        uint8 = 0x7
	_DW_LLE_start_length     uint8 = 0x8
)

func (rdr *loclistReader5) Next(le *loclistEntry) bool {
again:
	if rdr.err != nil || rdr.atEnd {
		return false
	}
	opcode, err := rdr.buf.ReadByte()
	if err != nil {
		rdr.err = err
		return false
	}

	le.seek = len(rdr.sec.data) - rdr.buf.Len()
	le.instr = []byte{}

	switch opcode {
	case _DW_LLE_end_of_list:
		rdr.atEnd = true
		return false

	case _DW_LLE_base_addressx:
		baseIdx, _ := leb128.DecodeUnsigned(rdr.buf)
		rdr.base, rdr.err = rdr.debugAddr.Get(baseIdx)
		goto again

	case _DW_LLE_startx_endx:
		startIdx, _ := leb128.DecodeUnsigned(rdr.buf)
		endIdx, _ := leb128.DecodeUnsigned(rdr.buf)
		rdr.readInstr()

		le.lowpc, rdr.err = rdr.debugAddr.Get(startIdx)
		if rdr.err == nil {
			le.highpc, rdr.err = rdr.debugAddr.Get(endIdx)
		}
		return true

	case _DW_LLE_startx_length:
		startIdx, _ := leb128.DecodeUnsigned(rdr.buf)
		length, _ := leb128.DecodeUnsigned(rdr.buf)
		rdr.readInstr()

		le.lowpc, rdr.err = rdr.debugAddr.Get(startIdx)
		le.highpc = le.lowpc + length
		return true

	case _DW_LLE_offset_pair:
		off1, _ := leb128.DecodeUnsigned(rdr.buf)
		off2, _ := leb128.DecodeUnsigned(rdr.buf)
		rdr.readInstr()

		le.lowpc = rdr.base + off1
		le.highpc = rdr.base + off2
		return true

	case _DW_LLE_default_location:
		rdr.readInstr()
		rdr.defaultInstr = rdr.instr
		goto again

	case _DW_LLE_base_address:
		rdr.base, rdr.err = dwarf.ReadUintRaw(rdr.buf, rdr.sec.byteOrder, rdr.sec.ptrSz)
		goto again

	case _DW_LLE_start_end:
		le.lowpc, rdr.err = dwarf.ReadUintRaw(rdr.buf, rdr.sec.byteOrder, rdr.sec.ptrSz)
		le.highpc, rdr.err = dwarf.ReadUintRaw(rdr.buf, rdr.sec.byteOrder, rdr.sec.ptrSz)
		rdr.readInstr()
		return true

	case _DW_LLE_start_length:
		le.lowpc, rdr.err = dwarf.ReadUintRaw(rdr.buf, rdr.sec.byteOrder, rdr.sec.ptrSz)
		length, _ := leb128.DecodeUnsigned(rdr.buf)
		rdr.readInstr()
		le.highpc = le.lowpc + length
		return true

	default:
		rdr.err = fmt.Errorf("unknown opcode %#x at %#x", opcode, len(rdr.sec.data)-rdr.buf.Len())
		rdr.atEnd = true
		return false
	}

	return true
}

func (rdr *loclistReader5) readInstr() {
	length, _ := leb128.DecodeUnsigned(rdr.buf)
	rdr.instr = rdr.buf.Next(int(length))
}
