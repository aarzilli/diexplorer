package main

import (
	"debug/dwarf"
	"fmt"
	"html"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

func lookup(addr uint64) (string, uint64) {
	i := sort.Search(len(Symbols), func(i int) bool { return addr < Symbols[i].Addr })
	if i > 0 {
		s := Symbols[i-1]
		if s.Addr != 0 && s.Addr <= addr {
			return s.Name, s.Addr
		}
	}
	return "", 0
}

func findScopeEnterVariables(en *EntryNode, pc uint64) []string {
	r := []string{}

	if len(en.Ranges) <= 0 {
		return r
	}

	scopeStart := en.Ranges[0][0]

	for i := range en.Childs {
		switch en.Childs[i].E.Tag {
		case dwarf.TagVariable, dwarf.TagFormalParameter:
			varStartScope, _ := en.Childs[i].E.Val(dwarf.AttrStartScope).(int64)
			varStartScope += int64(scopeStart)
			if uint64(varStartScope) == pc {
				name, _ := en.Childs[i].E.Val(dwarf.AttrName).(string)
				r = append(r, fmt.Sprintf("%q %x", name, en.Childs[i].E.Offset))
			}
		case 0:
			// nothing to do
		default:
			r = append(r, findScopeEnterVariables(en.Childs[i], pc)...)
		}
	}
	return r
}

func lexicalBlockSynthesis(out io.Writer, en *EntryNode) {
	fmt.Fprintf(out, "<h3>Lexical Block synthesis</h3>\n")
	fmt.Fprintf(out, "<ul>\n")
	for i := range en.Childs {
		switch en.Childs[i].E.Tag {
		case dwarf.TagFormalParameter, dwarf.TagVariable:
			name, _ := en.Childs[i].E.Val(dwarf.AttrName).(string)
			fmt.Fprintf(out, "<li>%x %s</li>\n", en.Childs[i].E.Offset, name)
		case 0:
			// nothing to do
		default:
			fmt.Fprintf(out, "<li><input type='checkbox' id='lb%x' onclick='javascript:repaint()'></input>&nbsp;%x Lexical block\n", en.Childs[i].E.Offset, en.Childs[i].E.Offset)
			lexicalBlockSynthesis(out, en.Childs[i])
			fmt.Fprintf(out, "</li>\n")
		}
	}
	fmt.Fprintf(out, "</ul>\n")
}

type scopeStack []*EntryNode

func (s *scopeStack) Push(en *EntryNode) {
	*s = append(*s, en)
}

func (s *scopeStack) Pop() {
	*s = (*s)[:len(*s)-1]
}

func (s *scopeStack) EnterChild(pc uint64) bool {
	cur := (*s)[len(*s)-1]
	for i := range cur.Childs {
		for j := range cur.Childs[i].Ranges {
			if cur.Childs[i].Ranges[j][0] == pc {
				s.Push(cur.Childs[i])
				s.EnterChild(pc)
				return true
			}
		}
	}
	return false
}

func (s *scopeStack) ExitCurrent(pc uint64) bool {
	cur := (*s)[len(*s)-1]
	for i := range cur.Ranges {
		if cur.Ranges[i][1] == pc {
			s.Pop()
			s.ExitCurrent(pc)
			return true
		}
	}
	return false
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

func printColors(out io.Writer, en *EntryNode, pi *int) {
	for i := range en.Childs {
		switch en.Childs[i].E.Tag {
		case dwarf.TagFormalParameter, dwarf.TagVariable, 0:
			// nothing to do
		default:
			fmt.Fprintf(out, "\"lb%x\": %q,\n", en.Childs[i].E.Offset, colors[*pi])
			*pi = (*pi + 1) % len(colors)
			printColors(out, en.Childs[i], pi)
		}
	}

}

func disassemble(out io.Writer, en *EntryNode, ecu *dwarf.Entry) {
	startPC, endPC := en.Ranges[0][0], en.Ranges[0][1]
	lnrdr, err := Dwarf.LineReader(ecu)
	must(err)

	var lne dwarf.LineEntry
	lnevalid := lnrdr.SeekPC(startPC, &lne) == nil

	file := "???"
	line := 0

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
	printColors(out, en, &i)

	fmt.Fprintf(out, `
			};
			function repaint() {
				var tbl = document.getElementById('disasstable');
				for (var i = 0; i < tbl.rows.length; i++) {
					var row = tbl.rows[i];
					var color = "";
					for (var j = row.classList.length-1; j >= 0; j--) {
						console.log(row.classList[j]);
						var cb = document.getElementById(row.classList[j])
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

	// print lexical blocks synthesis
	lexicalBlockSynthesis(out, en)

	var scopeStack scopeStack
	scopeStack.Push(en)

	// print disassembly
	fmt.Fprintf(out, "<h3>Disassembly</h3>\n<tt><table id='disasstable'>\n")
	fmt.Fprintf(out, "<tr><td>Pos</td><td>PC</td><td>Bytes</td><td>Instruction</td><td>Start scope variables</td></tr>\n")
	for pc := startPC; pc < endPC; {
		i := uint64(pc) - TextStart

		// decode instruction
		inst, err := x86asm.Decode(TextData[i:], 64)
		size := uint64(inst.Len)
		var text string
		if err != nil || size == 0 || inst.Op == 0 {
			size = 1
			text = "?"
		} else {
			text = x86asm.GoSyntax(inst, pc, lookup)
		}

		// find file:line
		for lnevalid && lne.Address < pc {
			lnevalid = lnrdr.Next(&lne) == nil
		}
		if lnevalid {
			if lne.Address == pc {
				file = lne.File.Name
				line = lne.Line
			}
		} else {
			file = "?"
			line = 0
		}

		// find scopes starting or ending here
		if !scopeStack.EnterChild(pc) {
			scopeStack.ExitCurrent(pc)
		}

		// find variables that enter scope here
		vars := findScopeEnterVariables(en, pc)

		scopes := make([]string, 0, len(scopeStack))

		fmt.Fprintf(out, "<tr class=\"")
		for i := range scopeStack {
			fmt.Fprintf(out, " lb%x", scopeStack[i].E.Offset)
			scopes = append(scopes, fmt.Sprintf("%x", scopeStack[i].E.Offset))
		}
		fmt.Fprintf(out, "\">")

		fmt.Fprintf(out, "<td>%s:%d</td><td>%#x</td><td>%x</td><td>%s</td><td>%s</td>\n", html.EscapeString(filepath.Base(file)), line, pc, TextData[i:i+size], html.EscapeString(text), strings.Join(vars, " "))

		fmt.Fprintf(out, "</tr>\n")
		pc += size
	}
	scopeStack.Pop()
	fmt.Fprintf(out, "</table></tt>\n</body>\n")
	//TODO:
	// - add colorization of scopes
	// - remove disass argument shit from main
}
