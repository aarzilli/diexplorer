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
	"runtime"
	"sort"
	"sync"

	"github.com/go-delve/delve/pkg/dwarf/frame"
	"github.com/go-delve/delve/pkg/dwarf/godwarf"
	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/dwarf/regnum"
)

var Dwarf *dwarf.Data
var UnitVersions map[dwarf.Offset]uint8
var TextStart uint64
var TextData []byte
var DebugLoc2 *loclistReader2
var DebugLoc5 *loclistSection5
var DebugAddr5 *godwarf.DebugAddrSection
var DebugFrame frame.FrameDescriptionEntries
var Symbols []Sym
var DisassembleOne DisassembleFunc
var RegnumToString func(uint64) string
var mu sync.Mutex

var ListenAddr = "127.0.0.1:0"

type Sym struct {
	Name string
	Addr uint64
	Off  dwarf.Offset
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
	initializeSections(ptrsz, func(name string) []byte {
		data, _ := GetDebugSectionPE(file, name)
		return data
	})
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
	initializeSections(8, func(name string) []byte {
		data, _ := GetDebugSectionMacho(file, name)
		return data
	})
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
		RegnumToString = regnum.I386ToName
		ptrsz = 4
	case elf.EM_X86_64:
		DisassembleOne = disassembleOneAmd64
		RegnumToString = regnum.AMD64ToName
	case elf.EM_AARCH64:
		DisassembleOne = disassembleOneArm64
		RegnumToString = regnum.ARM64ToName
	case elf.EM_PPC64:
		DisassembleOne = disassembleOnePpc64
		RegnumToString = regnum.PPC64LEToName
	case elf.EM_RISCV:
		DisassembleOne = disassembleOneRiscv64
		RegnumToString = regnum.RISCV64ToName
	default:
		fmt.Printf("unknown machine %s\n", file.Machine)
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
	initializeSections(ptrsz, func(name string) []byte {
		data, _ := GetDebugSectionElf(file, name)
		return data
	})
	return
}

func initializeSections(ptrsz int, getSection func(name string) []byte) {
	if locData := getSection("loc"); locData != nil {
		DebugLoc2 = newLoclistReader2(locData, ptrsz)
	}
	if locData := getSection("loclists"); locData != nil {
		DebugLoc5 = newLoclistSection5(locData, ptrsz)
	}
	if frameData := getSection("frame"); frameData != nil {
		DebugFrame, _ = frame.Parse(frameData, binary.LittleEndian, 0, ptrsz, 0)
	}
	if infoData := getSection("info"); infoData != nil {
		readUnitVersions(infoData)
	}
	if addrData := getSection("addr"); addrData != nil {
		DebugAddr5 = godwarf.ParseAddr(addrData)
	}
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

func (e *loclistEntry) BaseAddressSelection() bool {
	return e.lowpc == ^uint64(0)
}

func loclistPrint(off int64, cu *dwarf.Entry, debugLoc loclistReader) string {
	var buf bytes.Buffer
	debugLoc.Seek(int(off))

	var base uint64
	curange, _ := Dwarf.Ranges(cu)
	if len(curange) > 0 {
		base = curange[0][0]
	}

	var e loclistEntry
	for debugLoc.Next(&e) {
		if e.BaseAddressSelection() {
			fmt.Fprintf(&buf, "Base address: %#x\n", e.highpc)
			base = e.highpc
		} else {
			fmt.Fprintf(&buf, "<input type='checkbox' id='ll%x' onclick='javascript:window.parent.parent.frames[1].repaint()'></input>", e.seek)
			fmt.Fprintf(&buf, "%#x %#x ", e.lowpc+base, e.highpc+base)
			op.PrettyPrint(&buf, e.instr, RegnumToString)
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
					Off:  e.Offset,
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
					Off:  e.Offset,
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
	if len(e.Ranges) > 0 {
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

	for i := range compileUnits {
		if compileUnits[i].Offset > e.E.Offset {
			return compileUnits[i-1]
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

	for _, ver := range UnitVersions {
		if ver >= 5 {
			if !VersionAfterOrEqual(runtime.Version(), 1, 25) {
				fmt.Fprintf(os.Stderr, "Executable uses DWARFv5 but diexplorer was not built with go1.25 or later")
				os.Exit(1)
			}
		}
	}

	serve()
}

type InlinedCall struct {
	FnName string
	Offset dwarf.Offset
}

func collectInlinedCalls(entryNode *EntryNode) []InlinedCall {
	rdr := Dwarf.Reader()
	rdr.Seek(0)

	calls := []InlinedCall{}

	var fn *dwarf.Entry
	for {
		e, err := rdr.Next()
		must(err)
		if e == nil {
			break
		}
		switch e.Tag {
		case dwarf.TagSubprogram:
			fn = e
		case dwarf.TagInlinedSubroutine:
			if e.Val(dwarf.AttrAbstractOrigin).(dwarf.Offset) == entryNode.E.Offset {
				name := fn.Val(dwarf.AttrName).(string)
				if name == "" {
					name = fmt.Sprintf("function at %x", fn.Offset)
				}
				calls = append(calls, InlinedCall{name, fn.Offset})
			}
		}
	}

	return calls
}

func readDwarfLengthVersion(data []byte) (length uint64, dwarf64 bool, version uint8, byteOrder binary.ByteOrder) {
	if len(data) < 4 {
		return 0, false, 0, binary.LittleEndian
	}

	lengthfield := binary.LittleEndian.Uint32(data)
	voff := 4
	if lengthfield == ^uint32(0) {
		dwarf64 = true
		voff = 12
	}

	if voff+1 >= len(data) {
		return 0, false, 0, binary.LittleEndian
	}

	byteOrder = binary.LittleEndian
	x, y := data[voff], data[voff+1]
	switch {
	default:
		fallthrough
	case x == 0 && y == 0:
		version = 0
		byteOrder = binary.LittleEndian
	case x == 0:
		version = y
		byteOrder = binary.BigEndian
	case y == 0:
		version = x
		byteOrder = binary.LittleEndian
	}

	if dwarf64 {
		length = byteOrder.Uint64(data[4:])
	} else {
		length = uint64(byteOrder.Uint32(data))
	}

	return length, dwarf64, version, byteOrder
}

func readUnitVersions(data []byte) {
	const (
		_DW_UT_compile = 0x1 + iota
		_DW_UT_type
		_DW_UT_partial
		_DW_UT_skeleton
		_DW_UT_split_compile
		_DW_UT_split_type
	)

	UnitVersions = make(map[dwarf.Offset]uint8)
	off := dwarf.Offset(0)
	for len(data) > 0 {
		length, dwarf64, version, _ := readDwarfLengthVersion(data)

		data = data[4:]
		off += 4
		secoffsz := 4
		if dwarf64 {
			off += 8
			secoffsz = 8
			data = data[8:]
		}

		var headerSize int

		switch version {
		case 2, 3, 4:
			headerSize = 3 + secoffsz
		default: // 5 and later?
			unitType := data[2]

			switch unitType {
			case _DW_UT_compile, _DW_UT_partial:
				headerSize = 4 + secoffsz

			case _DW_UT_skeleton, _DW_UT_split_compile:
				headerSize = 4 + secoffsz + 8

			case _DW_UT_type, _DW_UT_split_type:
				headerSize = 4 + secoffsz + 8 + secoffsz
			}
		}

		UnitVersions[off+dwarf.Offset(headerSize)] = version

		data = data[length:] // skip contents
		off += dwarf.Offset(length)
	}
}

func loclistReaderForEntry(en *EntryNode) loclistReader {
	const dwarfAttrAddrBase = 0x73
	cu := findCompileUnit(en)
	ver := UnitVersions[cu.Offset]
	if ver >= 5 {
		addrBase := cu.Val(dwarfAttrAddrBase).(int64)
		ranges, _ := Dwarf.Ranges(cu)

		return DebugLoc5.ReaderFor(ranges[0][0], DebugAddr5.GetSubsection(uint64(addrBase)))
	}
	return DebugLoc2
}
