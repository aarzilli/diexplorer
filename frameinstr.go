package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/derekparker/delve/pkg/dwarf/op"
	"github.com/derekparker/delve/pkg/dwarf/util"
)

//go:generate go run scripts/gen-frame-opcodes.go ./frame_opcodes.txt ./frame_opcodes.go

func PrettyPrint(instrs []uint8) string {
	in := bytes.NewBuffer(instrs)
	out := bytes.NewBuffer([]byte{})

	fmt.Fprintf(out, "\t")

	for {
		opcode, err := in.ReadByte()
		if err != nil {
			break
		}

		high2 := (opcode & 0xc0) >> 6
		low6 := opcode & 0x3f

		found := false
		if name, ok := frameOpcodeHigh2[high2]; ok {
			found = true
			opcode = opcode & 0xc0
			fmt.Fprintf(out, "%s %#x ", name, low6)
		} else if name, ok := frameOpcodeLow6[low6]; ok {
			fmt.Fprintf(out, "%s ", name)
			found = true
		}
		if !found {
			fmt.Fprintf(out, "\n\t")
			continue
		}

		for _, arg := range frameOpcodeArgs[opcode] {
			switch arg {
			case 's':
				n, _ := util.DecodeSLEB128(in)
				fmt.Fprintf(out, "%#x ", n)
			case 'u':
				n, _ := util.DecodeULEB128(in)
				fmt.Fprintf(out, "%#x ", n)
			case '1':
				var x uint8
				binary.Read(in, binary.LittleEndian, &x)
				fmt.Fprintf(out, "%#x ", x)
			case '2':
				var x uint16
				binary.Read(in, binary.LittleEndian, &x)
				fmt.Fprintf(out, "%#x ", x)
			case '4':
				var x uint32
				binary.Read(in, binary.LittleEndian, &x)
				fmt.Fprintf(out, "%#x ", x)
			case '8':
				var x uint64
				binary.Read(in, binary.LittleEndian, &x)
				fmt.Fprintf(out, "%#x ", x)
			case 'B':
				sz, _ := util.DecodeULEB128(in)
				data := make([]byte, sz)
				sz2, _ := in.Read(data)
				data = data[:sz2]
				op.PrettyPrint(out, data)
				fmt.Fprintf(out, "")
			}
		}
		fmt.Fprintf(out, "\n\t")
	}

	return out.String()
}
