package main

import (
	"debug/dwarf"
	"encoding/binary"
	"fmt"
	"html"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/ppc64/ppc64asm"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/arch/riscv64/riscv64asm"
)

type symLookup func(addr uint64) (string, uint64)

type lookupper struct {
	sym *Sym
}

func (l *lookupper) lookup(addr uint64) (string, uint64) {
	i := sort.Search(len(Symbols), func(i int) bool { return addr < Symbols[i].Addr })
	if i > 0 {
		s := &Symbols[i-1]
		if s.Addr != 0 && s.Addr <= addr {
			l.sym = s
			return s.Name, s.Addr
		}
	}
	return "", 0
}

func lexicalBlockSynthesis(out io.Writer, en *EntryNode) {
	fmt.Fprintf(out, "<ul>\n")
	for i := range en.Childs {
		switch en.Childs[i].E.Tag {
		case dwarf.TagFormalParameter, dwarf.TagVariable:
			name, _ := en.Childs[i].E.Val(dwarf.AttrName).(string)
			fmt.Fprintf(out, "<li>%x %s</li>\n", en.Childs[i].E.Offset, name)
		case 0:
			// nothing to do
		case dwarf.TagLexDwarfBlock:
			fmt.Fprintf(out, "<li><input type='checkbox' id='lb%x' onclick='javascript:repaint()'></input>&nbsp;%x Lexical block\n", en.Childs[i].E.Offset, en.Childs[i].E.Offset)
			lexicalBlockSynthesis(out, en.Childs[i])
			fmt.Fprintf(out, "</li>\n")
		}
	}
	fmt.Fprintf(out, "</ul>\n")
}

func findScopes(en *EntryNode, pc uint64) []string {
	found := false
	for _, rng := range en.Ranges {
		if pc >= rng[0] && pc < rng[1] {
			found = true
		}
	}

	if !found {
		return nil
	}

	r := []string{fmt.Sprintf("lb%x", en.E.Offset)}

	for i := range en.Childs {
		r = append(r, findScopes(en.Childs[i], pc)...)
	}

	return r
}

func findScopesAndLoclists(en *EntryNode, pc uint64, loclistEntries []loclistEntry) []string {
	r := findScopes(en, pc)
	for _, lle := range loclistEntries {
		if pc >= lle.lowpc && pc < lle.highpc {
			r = append(r, fmt.Sprintf("ll%x", lle.seek))
		}
	}
	return r
}

var colors = []string{
	"rgb(245,245,245)",
	"rgb(220,220,220)",
	"rgb(255,250,240)",
	"rgb(253,245,230)",
	"rgb(240,240,230)",
	"rgb(250,235,215)",
	"rgb(238,223,204)",
	"rgb(205,192,176)",
	"rgb(240,248,255)",
	"rgb(230,230,250)",
	"rgb(211,211,211)",
	"rgb(30,144,255)",
	"rgb(0,191,255)",
	"rgb(135,206,250)",
	"rgb(135,206,250)",
	"rgb(250,250,210)",
	"rgb(255,255,224)",
	"rgb(255,255,0)",
	"rgb(222,184,135)",
	"rgb(245,245,220)",
	"rgb(245,222,179)",
	"rgb(244,164,96)",
	"rgb(210,180,140)",
	"rgb(210,105,30)",
	"rgb(255,165,0)",
	"rgb(255,140,0)",
	"rgb(255,127,80)",
	"rgb(255,105,180)",
	"rgb(255,20,147)",
	"rgb(255,192,203)",
	"rgb(238,130,238)",
	"rgb(221,160,221)",
	"rgb(218,112,214)",
	"rgb(186,85,211)",
	"rgb(216,191,216)",
}

func printColor(out io.Writer, name string, pi *int) {
	fmt.Fprintf(out, "%q: %q,\n", name, colors[*pi])
	*pi = (*pi + 1) % len(colors)

}

func printColors(out io.Writer, en *EntryNode, pi *int, loclistEntries []loclistEntry) []loclistEntry {
	for i := range en.Childs {
		switch en.Childs[i].E.Tag {
		case dwarf.TagFormalParameter, dwarf.TagVariable, 0:
			// nothing to do
		default:
			printColor(out, fmt.Sprintf("lb%x", en.Childs[i].E.Offset), pi)
			loclistEntries = printColors(out, en.Childs[i], pi, loclistEntries)
		}

		for j := range en.Childs[i].E.Field {
			field := en.Childs[i].E.Field[j]
			if field.Class != dwarf.ClassLocListPtr {
				continue
			}

			DebugLoc.Seek(int(field.Val.(int64)))

			var base uint64
			curange, _ := Dwarf.Ranges(findCompileUnit(en))
			if len(curange) > 0 {
				base = curange[0][0]
			}

			var lle loclistEntry
			for DebugLoc.Next(&lle) {
				if lle.BaseAddressSelection() {
					base = lle.highpc
				} else {
					lle.lowpc += base
					lle.highpc += base
					printColor(out, fmt.Sprintf("ll%x", lle.seek), pi)
					loclistEntries = append(loclistEntries, lle)
				}
			}
		}
	}
	return loclistEntries
}

type DisassembleFunc func(data []uint8, pc uint64, lookup symLookup) (text string, size uint64)

func disassemble(out io.Writer, en *EntryNode, ecu *dwarf.Entry) {
	startPC, endPC := en.Ranges[0][0], en.Ranges[0][1]
	lnrdr, err := Dwarf.LineReader(ecu)
	must(err)

	var lne dwarf.LineEntry
	lnevalid := lnrdr.SeekPC(startPC, &lne) == nil

	file := "???"
	line := 0
	isstmt := false
	prologueend := false

	fnname, _ := en.E.Val(dwarf.AttrName).(string)

	fmt.Fprintf(out, `<!DOCTYPE html>
<html>
	<head>
		<style>
			table td {
				padding-left: 10px;
				padding-right: 10px;
			}
		</style>
		<script>
			var colors = {
`)

	var i int
	loclistEntries := printColors(out, en, &i, nil)

	fmt.Fprintf(out, `
			};
			function repaint() {
				var tbl = document.getElementById('disasstable');
				for (var i = 0; i < tbl.rows.length; i++) {
					var row = tbl.rows[i];
					var color = "";
					for (var j = row.classList.length-1; j >= 0; j--) {
						console.log(row.classList[j]);
						var cb = window.parent.parent.frames[0].document.getElementById(row.classList[j])
						if (cb != null && cb.checked) {
							color = colors[row.classList[j]];
							break;
						}
					}
					if (color == "") {
						row.style['background-color'] = 'inherit';
					} else {
						row.style['background-color'] = color;
					}
				}
			}
		</script>
	</head>
	<body>
		<h3>Function %q</h3>
`, fnname)

	// print disassembly
	fmt.Fprintf(out, "<h3>Disassembly</h3>\n<tt><table id='disasstable'>\n")
	fmt.Fprintf(out, "<tr><td>Pos</td><td><a href='#flaghelp'>flags</a></td><td>PC</td><td>Bytes</td><td>Instruction</td></tr>\n")
	for pc := startPC; pc < endPC; {
		i := uint64(pc) - TextStart

		var lup lookupper

		text, size := DisassembleOne(TextData[i:], pc, lup.lookup)

		// find file:line
		for lnevalid && lne.Address < pc {
			lnevalid = lnrdr.Next(&lne) == nil
		}
		if lnevalid {
			if lne.Address == pc {
				file = lne.File.Name
				line = lne.Line
				isstmt = lne.IsStmt
				prologueend = lne.PrologueEnd
			} else {
				isstmt = false
				prologueend = false
			}
		} else {
			file = "?"
			line = 0
			isstmt = false
			prologueend = false
		}

		fmt.Fprintf(out, "<tr class=\"%s\">", strings.Join(findScopesAndLoclists(en, pc, loclistEntries), " "))

		flagstr := ""
		if isstmt {
			flagstr = "S"
		}
		if prologueend {
			flagstr += "P"
		}

		link := ""

		if lup.sym != nil && lup.sym.Off != en.E.Offset {
			link = fmt.Sprintf("&nbsp;&nbsp;<a href='/%x'>&gt;&gt;&gt;</a>", lup.sym.Off)
		}

		fmt.Fprintf(out, "<td>%s:%d</td><td>%s</td><td>%#x</td><td>%x</td><td>%s%s</td>\n", html.EscapeString(filepath.Base(file)), line, flagstr, pc, TextData[i:i+size], html.EscapeString(text), link)

		fmt.Fprintf(out, "</tr>\n")
		pc += size
	}
	fmt.Fprintf(out, "</table></tt>\n<a name='flaghelp'></a><h3>Flag Help</h3>S - statement<br>P - end of prologue<br></body>\n")
}

func disassembleOneAmd64(data []uint8, pc uint64, lookup symLookup) (text string, size uint64) {
	inst, err := x86asm.Decode(data, 64)
	size = uint64(inst.Len)
	if err != nil || size == 0 || inst.Op == 0 {
		return "?", 1
	}
	text = x86asm.GoSyntax(inst, pc, x86asm.SymLookup(lookup))
	return text, size
}

func disassembleOne386(data []uint8, pc uint64, lookup symLookup) (text string, size uint64) {
	inst, err := x86asm.Decode(data, 32)
	size = uint64(inst.Len)
	if err != nil || size == 0 || inst.Op == 0 {
		return "?", 1
	}
	text = x86asm.GoSyntax(inst, pc, x86asm.SymLookup(lookup))
	return text, size
}

func disassembleOneArm64(data []uint8, pc uint64, lookup symLookup) (text string, size uint64) {
	inst, err := arm64asm.Decode(data)
	if err != nil {
		return "?", 4
	}
	size = 4
	text = arm64asm.GoSyntax(inst, pc, lookup, nil)
	return text, size
}

func disassembleOnePpc64(data []uint8, pc uint64, lookup symLookup) (text string, size uint64) {
	inst, err := ppc64asm.Decode(data, binary.LittleEndian)
	if err != nil {
		return "?", 4
	}
	size = 4
	text = ppc64asm.GoSyntax(inst, pc, lookup)
	return text, size
}

func disassembleOneRiscv64(data []uint8, pc uint64, lookup symLookup) (text string, size uint64) {
	inst, err := riscv64asm.Decode(data)
	if err != nil {
		return "?", 4
	}
	size = 4
	text = riscv64asm.GoSyntax(inst, pc, lookup, nil)
	return text, size
	
}
