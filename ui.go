package main

import (
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
}

func fmtEntryNodeHeader(e *dwarf.Entry) template.HTML {
	return template.HTML(fmt.Sprintf("<a name=\"%x\"><a href=\"/%x\">&lt;%x&gt;</a> <b>%s</b>", e.Offset, e.Offset, e.Offset, e.Tag.String()))
}

func fmtEntryNodeField(f *dwarf.Field, nodes []*EntryNode) template.HTML {
	//TODO: interpret location attribute
	switch f.Class {
	case dwarf.ClassReference:
		name := findReferenceName(f.Val.(dwarf.Offset), nodes)
		return template.HTML(fmt.Sprintf("<td>%s</td><td><a href=\"#%x\">&lt;%x&gt;</a> (%s)</td>", f.Attr.String(), f.Val.(dwarf.Offset), f.Val.(dwarf.Offset), html.EscapeString(name)))
	case dwarf.ClassAddress:
		return template.HTML(fmt.Sprintf("<td>%s</td><td>%#x</td>", f.Attr.String(), f.Val.(uint64)))
	case dwarf.ClassString:
		return template.HTML(fmt.Sprintf("<td>%s</td><td>%s</td>", f.Attr.String(), html.EscapeString(strconv.Quote(f.Val.(string)))))
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

var tmpl = template.Must(template.New("all").Funcs(funcMap).Parse(`<!doctype html>
<html>
	<head>
	</head>
	<body>
		{{range .}}<tt>
			{{template "entryNode" .}}
		</tt><hr>{{end}}
		{{with $first := (index . 0)}}
			{{if $first.IsFunction}}
				<a href='/{{$first.E.Offset | printf "%x"}}/disassemble'>Disassemble</a>
			{{end}}
		{{end}}
	</body>
</html>

{{define "entryNode"}}
	<div style="padding-left: 1em;">
		{{EntryNodeHeader .E}}<br>
		<table style="padding-left: 1em;">
		{{range .E.Field}}
			<tr>{{EntryNodeField .}}</tr>
		{{end}}
		</table>
		{{if .Ranges}}
			&nbsp;&nbsp;Ranges:<br>
			{{range .Ranges}}
				&nbsp;&nbsp;&nbsp;&nbsp;{{FmtRange .}}<br>
			{{end}}
		{{end}}
		{{range .Childs}}
			{{template "entryNode" .}}
		{{end}}
	</div>
{{end}}
`))

func allHandler(w http.ResponseWriter, r *http.Request) {
	var off dwarf.Offset
	v := strings.Split(r.URL.Path, "/")
	d := false
	for i, x := range v {
		if len(x) != 0 {
			n, err := strconv.ParseUint(x, 16, 64)
			if err != nil {
				return
			}
			off = dwarf.Offset(n)
			if i+1 < len(v) && v[i+1] == "disassemble" {
				d = true
				break
			}
		}
	}

	mu.Lock()
	defer mu.Unlock()

	rdr := Dwarf.Reader()

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
		if d {
			break
		}
	}

	if d {
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
			if e.Offset == nodes[0].E.Offset {
				break
			}
		}
		disassemble(w, nodes[0], cu)
		return
	}

	must(tmpl.Funcs(template.FuncMap{
		"EntryNodeField": func(f *dwarf.Field) template.HTML {
			return fmtEntryNodeField(f, nodes)
		}}).Execute(w, nodes))
}

func serve() {
	http.HandleFunc("/", handlerWrapper(allHandler))

	s := &http.Server{
		Handler:        http.DefaultServeMux,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	nl, _ := net.Listen("tcp", "127.0.0.1:0")
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
