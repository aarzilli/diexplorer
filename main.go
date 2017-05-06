package main

import (
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
	"sync"
)

var Dwarf *dwarf.Data
var mu sync.Mutex

func usage() {
	fmt.Fprintf(os.Stderr, "usage: diexplorer <executable file>\n")
	os.Exit(1)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type openFn func(string) *dwarf.Data

func openPE(path string) *dwarf.Data {
	file, _ := pe.Open(path)
	if file == nil {
		return nil
	}
	fmt.Fprintf(os.Stderr, "Found PE executable\n")
	dwarf, err := file.DWARF()
	must(err)
	return dwarf
}

func openMacho(path string) *dwarf.Data {
	file, _ := macho.Open(path)
	if file == nil {
		return nil
	}
	fmt.Fprintf(os.Stderr, "Found Macho-O executable\n")
	dwarf, err := file.DWARF()
	must(err)
	return dwarf
}

func openElf(path string) *dwarf.Data {
	file, _ := elf.Open(path)
	if file == nil {
		return nil
	}
	fmt.Fprintf(os.Stderr, "Found ELF executable\n")
	dwarf, err := file.DWARF()
	must(err)
	return dwarf
}

type EntryNode struct {
	E      *dwarf.Entry
	Childs []*EntryNode
	Ranges [][2]uint64
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

func main() {
	if len(os.Args) != 2 {
		usage()
	}

	for _, fn := range []openFn{openPE, openElf, openMacho} {
		Dwarf = fn(os.Args[1])
		if Dwarf != nil {
			break
		}
	}

	serve()
}
