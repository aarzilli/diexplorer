package main

import (
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"sync"
)

var Dwarf *dwarf.Data
var TextStart uint64
var TextData []byte
var Symbols []Sym
var mu sync.Mutex

type Sym struct {
	Name string
	Addr uint64
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: diexplorer <executable file>\n")
	os.Exit(1)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type openFn func(string) (dwarf *dwarf.Data, textStart uint64, textData []byte)

func openPE(path string) (*dwarf.Data, uint64, []byte) {
	file, _ := pe.Open(path)
	if file == nil {
		return nil, 0, nil
	}
	fmt.Fprintf(os.Stderr, "Found PE executable\n")
	dwarf, err := file.DWARF()
	must(err)

	var imageBase uint64
	switch oh := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	default:
		panic(fmt.Errorf("pe file format not recognized"))
	}
	sect := file.Section(".text")
	if sect == nil {
		panic(fmt.Errorf("text section not found"))
	}
	textStart := imageBase + uint64(sect.VirtualAddress)
	textData, err := sect.Data()
	must(err)
	return dwarf, textStart, textData
}

func openMacho(path string) (*dwarf.Data, uint64, []byte) {
	file, _ := macho.Open(path)
	if file == nil {
		return nil, 0, nil
	}
	fmt.Fprintf(os.Stderr, "Found Macho-O executable\n")
	dwarf, err := file.DWARF()
	must(err)

	sect := file.Section("__text")
	if sect == nil {
		panic(fmt.Errorf("text section not found"))
	}
	textStart := sect.Addr
	textData, err := sect.Data()
	must(err)

	return dwarf, textStart, textData
}

func openElf(path string) (*dwarf.Data, uint64, []byte) {
	file, _ := elf.Open(path)
	if file == nil {
		return nil, 0, nil
	}
	fmt.Fprintf(os.Stderr, "Found ELF executable\n")
	dwarf, err := file.DWARF()
	must(err)
	sect := file.Section(".text")
	if sect == nil {
		panic(fmt.Errorf("text section not found"))
	}
	textStart := sect.Addr
	textData, err := sect.Data()
	must(err)
	return dwarf, textStart, textData
}

type EntryNode struct {
	E      *dwarf.Entry
	Childs []*EntryNode
	Ranges [][2]uint64
}

func (en *EntryNode) IsFunction() bool {
	return en.E.Tag == dwarf.TagSubprogram
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
				if node.E.Offset == 0 {
					// append other compile units as additional offsets to print
					for {
						e, err := rdr.Next()
						must(err)
						if e == nil {
							break
						}

						addOffs = append(addOffs, e.Offset)
						rdr.SkipChildren()
					}
				}

				break
			}
		}

		return node, addOffs
	}

childrenLoop:
	for {
		n, a := toEntryNode(rdr)
		addOffs = append(addOffs, a...)
		node.Childs = append(node.Childs, n)
		switch n.E.Tag {
		case 0:
			break childrenLoop
		}
	}

	return node, addOffs
}

func findSymbols() {
	rdr := Dwarf.Reader()
	for {
		e, err := rdr.Next()
		must(err)
		if e == nil {
			break
		}
		switch e.Tag {
		case dwarf.TagSubprogram:
			addr, okAddr := e.Val(dwarf.AttrLowpc).(uint64)
			name, okName := e.Val(dwarf.AttrName).(string)
			if okAddr && okName {
				Symbols = append(Symbols, Sym{
					Name: name,
					Addr: addr,
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
					panic(fmt.Errorf("wrong location %v", loc))
				}
				Symbols = append(Symbols, Sym{
					Name: name,
					Addr: addr,
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

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	for _, fn := range []openFn{openPE, openElf, openMacho} {
		Dwarf, TextStart, TextData = fn(os.Args[1])
		if Dwarf != nil {
			break
		}
	}

	findSymbols()

	serve()
}
