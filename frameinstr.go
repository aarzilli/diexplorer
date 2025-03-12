package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/go-delve/delve/pkg/dwarf/leb128"
	"github.com/go-delve/delve/pkg/dwarf/op"
)

//go:generate go run scripts/gen-frame-opcodes.go ./frame_opcodes.txt ./frame_opcodes.go

func PrettyPrintFrameInstr(instrs []uint8, lowpc uint64) string {
	in := bytes.NewBuffer(instrs)
	out := bytes.NewBuffer([]byte{})

	fmt.Fprintf(out, "\t")

	loc := lowpc

	for {
		opcode, err := in.ReadByte()
		if err != nil {
			break
		}

		high2 := (opcode & 0xc0) >> 6
		low6 := opcode & 0x3f

		name, found := frameOpcodeHigh2[high2]
		if found {
			opcode = opcode & 0xc0
			fmt.Fprintf(out, "%s %#x ", name, low6)
			if name == "DW_CFA_advance_loc" {
				loc += uint64(low6)
				fmt.Fprintf(out, "to %#x ", loc)
			}
		} else {
			name, found = frameOpcodeLow6[low6]
			if found {
				fmt.Fprintf(out, "%s ", name)
			}
		}
		if !found {
			fmt.Fprintf(out, "\n\t")
			continue
		}

		for _, arg := range frameOpcodeArgs[opcode] {
			switch arg {
			case 's':
				n, _ := leb128.DecodeSigned(in)
				fmt.Fprintf(out, "%#x ", n)
			case 'u':
				n, _ := leb128.DecodeUnsigned(in)
				fmt.Fprintf(out, "%#x ", n)
			case '1':
				var x uint8
				binary.Read(in, binary.LittleEndian, &x)
				fmt.Fprintf(out, "%#x ", x)
				if name == "DW_CFA_advance_loc1" {
					loc += uint64(x)
					fmt.Fprintf(out, "to %#x ", loc)
				}
			case '2':
				var x uint16
				binary.Read(in, binary.LittleEndian, &x)
				fmt.Fprintf(out, "%#x ", x)
				if name == "DW_CFA_advance_loc2" {
					loc += uint64(x)
					fmt.Fprintf(out, "to %#x ", loc)
				}
			case '4':
				var x uint32
				binary.Read(in, binary.LittleEndian, &x)
				fmt.Fprintf(out, "%#x ", x)
				if name == "DW_CFA_advance_loc4" {
					loc += uint64(x)
					fmt.Fprintf(out, "to %#x ", loc)
				}
			case '8':
				var x uint64
				binary.Read(in, binary.LittleEndian, &x)
				fmt.Fprintf(out, "%#x ", x)
				if name == "DW_CFA_set_loc" {
					//TODO: set loc
					fmt.Fprintf(out, "to %#x ", loc)
				}
			case 'B':
				sz, _ := leb128.DecodeUnsigned(in)
				data := make([]byte, sz)
				sz2, _ := in.Read(data)
				data = data[:sz2]
				op.PrettyPrint(out, data, RegnumToString)
				fmt.Fprintf(out, "")
			}
		}
		fmt.Fprintf(out, "\n\t")
	}

	return out.String()
}
