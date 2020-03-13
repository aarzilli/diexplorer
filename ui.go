package main

import (
	"bytes"
	"debug/dwarf"
	"fmt"
	"html"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-delve/delve/pkg/dwarf/frame"
	"github.com/go-delve/delve/pkg/dwarf/op"
)

type HandleFunc func(w http.ResponseWriter, r *http.Request)

func WriteStackTrace(rerr interface{}, out io.Writer) {
	fmt.Fprintf(out, "Stack trace for: %s\n", rerr)
	for i := 1; ; i++ {
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		fmt.Fprintf(out, "    %s:%d\n", file, line)
	}
}

func handlerWrapper(hf HandleFunc) HandleFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rerr := recover(); rerr != nil {
				WriteStackTrace(rerr, os.Stderr)
				w.WriteHeader(500)
				w.Write([]byte(fmt.Sprintf("Internal Server Error %v", rerr)))
			}
		}()
		hf(w, r)
	}
}

var funcMap = template.FuncMap{
	"EntryNodeHeader": fmtEntryNodeHeader,
	"EntryNodeField": func(f *dwarf.Field) template.HTML {
		panic("EntryNodeField not replaced")
	},
	"FmtRange": fmtRange,
	"FmtFrameInstr": func(instr []byte) string {
		return fmtFrameInstr(instr, 0)
	},
	"FmtFDEInstr": func(fde *frame.FrameDescriptionEntry) string {
		return fmtFrameInstr(fde.Instructions, fde.Begin())
	},
	"IsFrameEntry": isFrameEntry,
}

func fmtEntryNodeHeader(e *dwarf.Entry) template.HTML {
	return template.HTML(fmt.Sprintf("<a name=\"%x\"><a href=\"/%x\">&lt;%x&gt;</a> <b>%s</b>", e.Offset, e.Offset, e.Offset, e.Tag.String()))
}

func fmtEntryNodeField(f *dwarf.Field, nodes []*EntryNode) template.HTML {
	switch f.Class {
	case dwarf.ClassReference:
		name := findReferenceName(f.Val.(dwarf.Offset), nodes)
		return template.HTML(fmt.Sprintf("<td>%s</td><td><a href=\"#%x\">&lt;%x&gt;</a> (%s)</td>", f.Attr.String(), f.Val.(dwarf.Offset), f.Val.(dwarf.Offset), html.EscapeString(name)))

	case dwarf.ClassAddress:
		return template.HTML(fmt.Sprintf("<td>%s</td><td>%#x</td>", f.Attr.String(), f.Val.(uint64)))

	case dwarf.ClassString:
		return template.HTML(fmt.Sprintf("<td>%s</td><td>%s</td>", f.Attr.String(), html.EscapeString(strconv.Quote(f.Val.(string)))))

	case dwarf.ClassExprLoc:
		block, _ := f.Val.([]byte)
		var out bytes.Buffer
		op.PrettyPrint(&out, block)
		return template.HTML(fmt.Sprintf("<td>%s</td><td>%s</td>", f.Attr.String(), html.EscapeString(out.String())))
	case dwarf.ClassLocListPtr:
		return template.HTML(fmt.Sprintf("<td>%s</td><td><pre>loclistptr = %#x (<a href='#' onclick='toggleLoclist2(this)'>toggle</a>)</pre><pre class='loclist' style='display: none'>%s</pre></td>", f.Attr.String(), f.Val.(int64), loclistPrint(f.Val.(int64), findCompileUnit(nodes[0]))))

	default:
		return template.HTML(fmt.Sprintf("<td>%s</td><td>%s</td>", f.Attr.String(), html.EscapeString(fmt.Sprint(f.Val))))
	}
}

func findReferenceName(off dwarf.Offset, nodes []*EntryNode) string {
	for _, node := range nodes {
		if node.E.Offset == off {
			r, _ := node.E.Val(dwarf.AttrName).(string)
			return r
		}
	}
	return ""
}

func fmtRange(f [2]uint64) template.HTML {
	return template.HTML(fmt.Sprintf("%x..%x", f[0], f[1]))
}

func isFrameEntry(f interface{}) bool {
	switch f.(type) {
	case *frame.FrameDescriptionEntry:
		return true
	case *frame.CommonInformationEntry:
		return false
	default:
		panic(fmt.Errorf("unknown type %T", f))
	}
}

func fmtFrameInstr(instr []byte, addr uint64) string {
	return PrettyPrintFrameInstr(instr, addr)
}

var tmpl = template.Must(template.New("all").Funcs(funcMap).Parse(`<!doctype html>
<html>
	<head>
		<style>
			.dwarftbl td {
				padding-left: 10px;
				padding-right: 10px;
				vertical-align: top;
			}
			.dwarftbl td pre {
				margin-top: 0px;
				margin-bottom: 0px;
			}
		</style>
		<script>
			function toggleLoclist2(e) {
				var el = e.parentElement.parentElement.getElementsByClassName("loclist")[0];
				if (el.style["display"] == "none") {
					el.style["display"] = "block";
				} else {
					el.style["display"] = "none";
				}
			}
		</script>
	</head>
	<body>
		{{with $first := (index . 0)}}
			{{if $first.IsFunction}}
				<a href="#frames">Debug Frame Entries</a><hr/>
			{{end}}
		{{end}}
		
		{{range .}}<tt>
			{{template "entryNode" .}}
		</tt><hr>{{end}}
		{{with $first := (index . 0)}}
			{{if $first.IsFunction}}
				<hr/>
				<h3><a name="frames"></a>Debug Frame Entries</h3>
				{{range $first.Frames}}
					<tt>{{if IsFrameEntry .}}
						{{template "frameDescriptionEntry" .}}
					{{else}}
						{{template "commonInformationEntry" .}}
					{{end}}</tt>
					<hr/>
				{{end}}
				
			{{end}}
		{{end}}
		
	</body>
</html>

{{define "entryNode"}}
	<div style="padding-left: 1em;">
		{{EntryNodeHeader .E}}<br>
		<table style="padding-left: 1em;" class='dwarftbl'>
		{{range .E.Field}}
			<tr>{{EntryNodeField .}}</tr>
		{{end}}
		</table>
		{{if .Ranges}}
			&nbsp;&nbsp;Ranges: 
			{{if .IsFunction}} 
			{{else}}
				(<input type='checkbox' id='lb{{.E.Offset | printf "%x" }}' onclick='javascript:window.parent.parent.frames[1].repaint()'></input>highlighted)
			{{end}}
			
			<br>
			
			{{range .Ranges}}
				&nbsp;&nbsp;&nbsp;&nbsp;{{FmtRange .}}<br>
			{{end}}
		{{end}}
		{{range .Childs}}
			{{template "entryNode" .}}
		{{end}}
	</div>
{{end}}

{{define "commonInformationEntry"}}
<table class='cietbl'>
<tr><td>Length</td><td>{{.Length}}</td></tr>
<tr><td>CIE Id</td><td>{{.CIE_id}}</td></tr>
<tr><td>Version</td><td>{{.Version}}</td></tr>
<tr><td>Augmentation</td><td>{{.Augmentation | printf "%q"}}</td></tr>
<tr><td>Code Alignment Factor</td><td>{{.CodeAlignmentFactor}}</td></tr>
<tr><td>Data Alignment Factor</td><td>{{.DataAlignmentFactor}}</td></tr>
<tr><td>Return Address Register</td><td>{{.ReturnAddressRegister}}</td></tr>
</table>
<pre>{{.InitialInstructions | FmtFrameInstr }}</pre>
{{end}}

{{define "frameDescriptionEntry"}}
<table class='fdetbl'>
<tr><td>Length</td><td>{{.Length}}</td></tr>
<tr><td>CIE</td><td>{{.CIE.CIE_id}}</td></tr>
<tr><td>Begin</td><td>{{.Begin | printf "%#x"}}</td></tr>
<tr><td>End</td><td>{{.End | printf "%#x"}}</td></tr>
</table>
<pre>{{. | FmtFDEInstr}}</pre>
{{end}}
`))

var framesetTmpl = template.Must(template.New("fn").Funcs(funcMap).Parse(`<!doctype html>
<!doctype html>

<frameset cols="50%,*">
	<frame src='/{{. | printf "%x" }}?std=1'>
	<frame src='/disassemble/{{. | printf "%x"}}'>
</frameset>
`))

func offset(r *http.Request) dwarf.Offset {
	v := strings.Split(r.URL.Path, "/")
	for _, x := range v {
		if len(x) != 0 {
			n, err := strconv.ParseUint(x, 16, 64)
			if err == nil {
				return dwarf.Offset(n)
			}
		}
	}
	return 0
}

func disassembleHandler(w http.ResponseWriter, r *http.Request) {
	off := offset(r)

	mu.Lock()
	defer mu.Unlock()

	rdr := Dwarf.Reader()
	rdr.Seek(off)
	entryNode, _ := toEntryNode(rdr)

	rdr.Seek(0)
	var cu *dwarf.Entry
	for {
		e, err := rdr.Next()
		must(err)
		if e == nil {
			break
		}
		if e.Tag == dwarf.TagCompileUnit {
			cu = e
		}
		if e.Offset == entryNode.E.Offset {
			break
		}
	}
	disassemble(w, entryNode, cu)
}

func rangesOverlap(a, b [2]uint64) bool {
	return a[0] <= b[1] && b[0] <= a[1]
}

func allHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	off := offset(r)
	root := off == 0

	mu.Lock()
	defer mu.Unlock()

	rdr := Dwarf.Reader()

	// Check if this is a subprogram to serve a different type of page
	if r.Form.Get("std") != "1" {
		rdr.Seek(off)
		rootEntry, _ := toEntryNode(rdr)
		if rootEntry != nil && rootEntry.E.Tag == dwarf.TagSubprogram {
			must(framesetTmpl.Execute(w, off))
			return
		}
	}

	nodes := []*EntryNode{}
	stack := []dwarf.Offset{off}
	seen := map[dwarf.Offset]bool{}

	for len(stack) > 0 {
		off := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[off] {
			continue
		}
		seen[off] = true

		rdr.Seek(off)
		entryNode, addOffs := toEntryNode(rdr)
		stack = append(stack, addOffs...)
		nodes = append(nodes, entryNode)
		if root {
			if e, _ := rdr.Next(); e != nil {
				stack = append(stack, e.Offset)
			}
		}
	}

	if allCompileUnits(nodes) && len(nodes) > 1 {
		if countNodes(nodes) > 10000 {
			for _, n := range nodes {
				n.Childs = nil
			}
		}
	}

	must(tmpl.Funcs(template.FuncMap{
		"EntryNodeField": func(f *dwarf.Field) template.HTML {
			return fmtEntryNodeField(f, nodes)
		}}).Execute(w, nodes))
}

func serve() {
	http.HandleFunc("/disassemble/", handlerWrapper(disassembleHandler))
	http.HandleFunc("/", handlerWrapper(allHandler))

	s := &http.Server{
		Handler:        http.DefaultServeMux,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	nl, _ := net.Listen("tcp", ListenAddr)
	port := ":" + strconv.Itoa(nl.Addr().(*net.TCPAddr).Port)
	fmt.Fprintf(os.Stderr, "Listening on: %s\n", port)

	url := "http://127.0.0.1" + port + "/"

	go func() {
		time.Sleep(1 * time.Second)
		if runtime.GOOS == "windows" {
			exec.Command("cmd.exe", "/C", "start "+url).Run()
			return
		}

		if runtime.GOOS == "darwin" {
			exec.Command("open", url).Run()
			return
		}

		exec.Command("xdg-open", url).Run()
	}()

	must(s.Serve(nl))
}
