package main

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/go-delve/delve/pkg/dwarf/frame"
	"github.com/go-delve/delve/pkg/dwarf/op"
)

var Dwarf *dwarf.Data
var TextStart uint64
var TextData []byte
var DebugLoc loclistReader
var DebugFrame frame.FrameDescriptionEntries
var Symbols []Sym
var DisassembleOne DisassembleFunc
var mu sync.Mutex

var ListenAddr = "127.0.0.1:0"

type Sym struct {
	Name string
	Addr uint64
	Off dwarf.Offset
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: diexplorer <executable file> [listen addr]\n")
	os.Exit(1)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type openFn func(string)

func openPE(path string) {
	file, _ := pe.Open(path)
	if file == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "Found PE executable\n")
	var err error
	Dwarf, err = file.DWARF()
	must(err)

	var ptrsz int

	var imageBase uint64
	switch oh := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		ptrsz = 4
		DisassembleOne = disassembleOne386
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		ptrsz = 8
		DisassembleOne = disassembleOneAmd64
		imageBase = oh.ImageBase
	default:
		panic(fmt.Errorf("pe file format not recognized"))
	}
	sect := file.Section(".text")
	if sect == nil {
		panic(fmt.Errorf("text section not found"))
	}
	TextStart = imageBase + uint64(sect.VirtualAddress)
	TextData, err = sect.Data()
	must(err)
	if locData, _ := GetDebugSectionPE(file, "loc"); locData != nil {
		DebugLoc.data = locData
		DebugLoc.ptrSz = ptrsz
	}
	if frameData, _ := GetDebugSectionPE(file, "frame"); frameData != nil {
		DebugFrame = frame.Parse(frameData, binary.LittleEndian, 0, ptrsz)
	}
	return
}

func openMacho(path string) {
	file, _ := macho.Open(path)
	if file == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "Found Macho-O executable\n")
	var err error
	Dwarf, err = file.DWARF()
	must(err)

	sect := file.Section("__text")
	if sect == nil {
		panic(fmt.Errorf("text section not found"))
	}
	switch file.Cpu {
	case macho.Cpu386:
		DisassembleOne = disassembleOne386
	case macho.CpuArm64:
		DisassembleOne = disassembleOneArm64
	case macho.CpuAmd64:
		fallthrough
	default:
		DisassembleOne = disassembleOneAmd64
	}
	TextStart = sect.Addr
	TextData, err = sect.Data()
	must(err)
	if locData, _ := GetDebugSectionMacho(file, "loc"); locData != nil {
		DebugLoc.data = locData
		DebugLoc.ptrSz = 8
	}
	if frameData, _ := GetDebugSectionMacho(file, "frame"); frameData != nil {
		DebugFrame = frame.Parse(frameData, binary.LittleEndian, 0, 8)
	}
	return
}

func openElf(path string) {
	file, _ := elf.Open(path)
	if file == nil {
		return
	}

	var ptrsz int = 8
	switch file.Machine {
	case elf.EM_386: // more 32bit arches go here...
		DisassembleOne = disassembleOne386
		ptrsz = 4
	case elf.EM_X86_64:
		DisassembleOne = disassembleOneAmd64
	case elf.EM_AARCH64:
		DisassembleOne = disassembleOneArm64
	}

	fmt.Fprintf(os.Stderr, "Found ELF executable\n")
	var err error
	Dwarf, err = file.DWARF()
	must(err)
	sect := file.Section(".text")
	if sect == nil {
		panic(fmt.Errorf("text section not found"))
	}
	TextStart = sect.Addr
	TextData, err = sect.Data()
	must(err)
	if locData, _ := GetDebugSectionElf(file, "loc"); locData != nil {
		DebugLoc.data = locData
		DebugLoc.ptrSz = ptrsz
	}
	if frameData, _ := GetDebugSectionElf(file, "frame"); frameData != nil {
		DebugFrame = frame.Parse(frameData, binary.LittleEndian, 0, ptrsz)
	}
	return
}

type EntryNode struct {
	E      *dwarf.Entry
	Childs []*EntryNode
	Ranges [][2]uint64

	allDebugFrames bool
}

func (en *EntryNode) IsFunction() bool {
	return en.E.Tag == dwarf.TagSubprogram
}

func (en *EntryNode) IsCompileUnit() bool {
	return en.E.Tag == dwarf.TagCompileUnit
}

func (entryNode *EntryNode) Frames() []interface{} {
	var frames []interface{}
	var cmn *frame.CommonInformationEntry
	for _, frame := range DebugFrame {
		frameRng := [2]uint64{frame.Begin(), frame.End()}
		o := false
		if entryNode.allDebugFrames {
			o = true
		}
		if !o {
			for _, rng := range entryNode.Ranges {
				if rangesOverlap(rng, frameRng) {
					o = true
					break
				}
			}
		}
		if o {
			if frame.CIE != cmn {
				frames = append(frames, frame.CIE)
				cmn = frame.CIE
			}
			frames = append(frames, frame)
		}
	}
	return frames
}

func toEntryNode(rdr *dwarf.Reader) (node *EntryNode, addOffs []dwarf.Offset) {
	e, err := rdr.Next()
	must(err)

	if e == nil {
		panic("invalid entry")
	}

	node = &EntryNode{E: e}

	if e.Tag == 0 {
		return node, addOffs
	}

	hasranges := false
	for _, field := range e.Field {
		if field.Class == dwarf.ClassReference {
			addOffs = append(addOffs, field.Val.(dwarf.Offset))
		} else if field.Attr == dwarf.AttrRanges || field.Attr == dwarf.AttrLowpc || field.Attr == dwarf.AttrHighpc {
			hasranges = true
		}
	}

	if hasranges {
		node.Ranges, err = Dwarf.Ranges(e)

	}

	if !e.Children {
		return node, addOffs
	}

	if e.Tag == dwarf.TagCompileUnit {
		for {
			e, err := rdr.Next()
			must(err)
			if e == nil {
				break
			}

			node.Childs = append(node.Childs, &EntryNode{E: e})

			rdr.SkipChildren()

			if e.Tag == 0 {
				break
			}
		}

		return node, addOffs
	}

	for {
		n, a := toEntryNode(rdr)
		addOffs = append(addOffs, a...)
		node.Childs = append(node.Childs, n)
		if n.E.Tag == 0 {
			break
		}
	}

	return node, addOffs
}

func countNodes(nodes []*EntryNode) int {
	r := 1
	for i := range nodes {
		r += countNodes(nodes[i].Childs)
	}
	return r
}

func allCompileUnits(nodes []*EntryNode) bool {
	for _, n := range nodes {
		if n.E.Tag != dwarf.TagCompileUnit {
			return false
		}
	}
	return true
}

type loclistReader struct {
	data  []byte
	cur   int
	ptrSz int
}

func (rdr *loclistReader) Seek(off int) {
	rdr.cur = off
}

func (rdr *loclistReader) read(sz int) []byte {
	r := rdr.data[rdr.cur : rdr.cur+sz]
	rdr.cur += sz
	return r
}

func (rdr *loclistReader) oneAddr() uint64 {
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

func (rdr *loclistReader) Next(e *loclistEntry) bool {
	e.seek = rdr.cur
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

type loclistEntry struct {
	seek          int
	lowpc, highpc uint64
	instr         []byte
}

func (e *loclistEntry) BaseAddressSelection() bool {
	return e.lowpc == ^uint64(0)
}

func loclistPrint(off int64, cu *dwarf.Entry) string {
	var buf bytes.Buffer
	DebugLoc.Seek(int(off))

	var base uint64
	curange, _ := Dwarf.Ranges(cu)
	if len(curange) > 0 {
		base = curange[0][0]
	}

	var e loclistEntry
	for DebugLoc.Next(&e) {
		if e.BaseAddressSelection() {
			fmt.Fprintf(&buf, "Base address: %#x\n", e.highpc)
			base = e.highpc
		} else {
			fmt.Fprintf(&buf, "<input type='checkbox' id='ll%x' onclick='javascript:window.parent.parent.frames[1].repaint()'></input>", e.seek)
			fmt.Fprintf(&buf, "%#x %#x ", e.lowpc+base, e.highpc+base)
			op.PrettyPrint(&buf, e.instr)
			fmt.Fprintf(&buf, "\n")
		}
	}
	return buf.String()
}

var compileUnits []*dwarf.Entry

func findSymbols() {
	rdr := Dwarf.Reader()
	for {
		e, err := rdr.Next()
		must(err)
		if e == nil {
			break
		}
		switch e.Tag {
		case dwarf.TagCompileUnit:
			compileUnits = append(compileUnits, e)
		case dwarf.TagSubprogram:
			addr, okAddr := e.Val(dwarf.AttrLowpc).(uint64)
			name, okName := e.Val(dwarf.AttrName).(string)
			if okAddr && okName {
				Symbols = append(Symbols, Sym{
					Name: name,
					Addr: addr,
					Off: e.Offset,
				})
			}
		case dwarf.TagVariable:
			loc, okLoc := e.Val(dwarf.AttrLocation).([]byte)
			name, okName := e.Val(dwarf.AttrName).(string)
			if okLoc && okName {
				if loc[0] != 0x3 {
					// not DW_OP_addr
					break
				}
				addr := uint64(0)
				switch len(loc[1:]) {
				case 4:
					addr = uint64(binary.LittleEndian.Uint32(loc[1:]))
				case 8:
					addr = binary.LittleEndian.Uint64(loc[1:])
				default:
					// C bullshit
					//panic(fmt.Errorf("wrong location %v", loc))
				}
				Symbols = append(Symbols, Sym{
					Name: name,
					Addr: addr,
					Off: e.Offset,
				})
			}
		}
		if e.Tag != dwarf.TagCompileUnit {
			rdr.SkipChildren()
		}
	}
	sort.Slice(Symbols, func(i, j int) bool {
		return Symbols[i].Addr < Symbols[j].Addr
	})
}

func findCompileUnit(e *EntryNode) *dwarf.Entry {
	if len(e.Ranges) <= 0 {
		return nil
	}
	pc := e.Ranges[0][0]

	for i := range compileUnits {
		ranges, _ := Dwarf.Ranges(compileUnits[i])
		for _, rng := range ranges {
			if pc >= rng[0] && pc < rng[1] {
				return compileUnits[i]
			}
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	if len(os.Args) >= 3 {
		ListenAddr = os.Args[2]
	}

	for _, fn := range []openFn{openPE, openElf, openMacho} {
		fn(os.Args[1])
		if Dwarf != nil {
			break
		}
	}

	findSymbols()

	serve()
}
