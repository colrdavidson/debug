package main

import (
	"net"
	"fmt"
	"log"
	"strings"
	"strconv"
	"sync"
	"io/ioutil"
	"net/http"
	"encoding/json"
)

type File struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

type Register struct {
	Name string `json:"name"`
	Value string `json:"value"`
}

type PositionInfo struct {
	Address string `json:"address"`
	Line    string `json:"line"`
	File    string `json:"file"`
}

func run_command(dbg *DebugState, cmd string) (result string) {
	dbg.lock.Lock()
	_, err := dbg.conn.Write([]byte(cmd))
	if err != nil {
		log.Fatal("Failed to send file list cmd!")
	}

	data := make([]byte, 4096)
	size, err := dbg.conn.Read(data)
	if err != nil {
		log.Fatal("Failed to get file list!")
	}
	dbg.lock.Unlock()

	str_data := string(data[0:size])
	if len(str_data) < 5 {
		log.Fatal("Packet not large enough to be valid!\n")
	}

	if !strings.HasPrefix(str_data, "ok") {
		log.Fatal("Packet not happy\n")
	}

	str_data = str_data[3:]
	i := 0
	for ; i < len(str_data); i++ {
		if str_data[i] == ' ' {
			break
		}
	}
	if i == len(str_data) {
		log.Fatal("Packet length formatted weird\n")
	}

	num_str := str_data[0:i]
	data_len, err := strconv.Atoi(num_str)
	if err != nil {
		log.Fatal("Packet length formatted weird\n")
	}

	str_data = str_data[i+1:]
	if data_len != len(str_data) {
		log.Fatal("Packet length invalid?\n")
	}

	return str_data
}

func get_file(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	files, ok := r.URL.Query()["file"]
	if !ok {
		log.Fatal("Invalid file!")
	}

	file_name := files[0]

	file_str, err := ioutil.ReadFile(file_name)
	if err != nil {
		fmt.Fprintf(w, "Failed to open file!")
		return
	}

	f := &File{Name: file_name, Data: string(file_str)}
	json.NewEncoder(w).Encode(f)
}

func get_file_list(w http.ResponseWriter, r *http.Request, dbg *DebugState) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	str_data := run_command(dbg, "fs\n")

	type FilePath struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}

	type Data struct {
		Paths []FilePath `json:"paths"`
	}

	path_lines := strings.Split(str_data, "\n")
	paths := make([]FilePath, len(path_lines) - 1)
	for i, path := range path_lines {
		if len(path) == 0 {
			break
		}

		pdata := strings.Split(path, " ")
		if len(pdata) != 2 {
			break
		}

		paths[i].Path = pdata[0]
		paths[i].Name = pdata[1]
	}

	dt := &Data{Paths: paths}
	json.NewEncoder(w).Encode(dt)
}

func set_breakpoint(w http.ResponseWriter, r *http.Request, dbg *DebugState) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	files, ok := r.URL.Query()["file"]
	if !ok {
		log.Fatal("Invalid file!")
	}

	lines, ok := r.URL.Query()["line"]
	if !ok {
		log.Fatal("Invalid line!")
	}

	line_num, err := strconv.Atoi(lines[0])
	if err != nil {
		log.Fatal("Line is not a valid number!")
	}

	cmd := fmt.Sprintf("bl %d %s\n", line_num, files[0])
	_ = run_command(dbg, cmd)
}

func clear_breakpoint(w http.ResponseWriter, r *http.Request, dbg *DebugState) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	files, ok := r.URL.Query()["file"]
	if !ok {
		log.Fatal("Invalid file!")
	}

	lines, ok := r.URL.Query()["line"]
	if !ok {
		log.Fatal("Invalid line!")
	}

	line_num, err := strconv.Atoi(lines[0])
	if err != nil {
		log.Fatal("Line is not a valid number!")
	}

	cmd := fmt.Sprintf("dl %d %s\n", line_num, files[0])
	_ = run_command(dbg, cmd)
}

func get_registers(w http.ResponseWriter, r *http.Request, dbg *DebugState) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	str_data := run_command(dbg, "p\n")

	type Data struct {
		Registers []Register `json:"registers"`
	}

	register_lines := strings.Split(str_data, "\n")
	regs := make([]Register, len(register_lines) - 1)

	for i, register := range register_lines {
		rdata := strings.Split(register, ": ")
		if len(rdata) == 1 {
			break
		}

		regs[i].Name = rdata[0]
		regs[i].Value = rdata[1]
	}

	json.NewEncoder(w).Encode(regs)
}

func get_breakpoints(w http.ResponseWriter, r *http.Request, dbg *DebugState) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	str_data := run_command(dbg, "pb\n")
	fmt.Printf("breakpoints: [%s]\n", str_data)

	bp_lines := strings.Split(str_data, "\n")
	bps := make([]PositionInfo, len(bp_lines) - 1)

	for i, bp := range bp_lines {
		pos_chunks := strings.Split(bp, " ")
		if len(pos_chunks) == 0 || pos_chunks[0] == "" {
			break
		}

		if len(pos_chunks) == 3 {
			bps[i] = PositionInfo{Address: pos_chunks[0], Line: pos_chunks[1], File: pos_chunks[2]}
		} else if len(pos_chunks) == 1 {
			bps[i] = PositionInfo{Address: pos_chunks[0], Line: "(None)", File: "(None)"}
		} else {
			log.Fatal("why do I hate life?\n");
		}
	}

	json.NewEncoder(w).Encode(bps)
}

func get_current_position(w http.ResponseWriter, r *http.Request, dbg *DebugState) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	str_data := run_command(dbg, "pc\n")

	pos_chunks := strings.Split(str_data, " ")
	address := pos_chunks[0]
	line := "(None)"
	file := "(None)"
	if len(pos_chunks) == 3 {
		line = pos_chunks[0]
		file = pos_chunks[1]
	}

	pi := PositionInfo{Address: address, Line: line, File: file}
	json.NewEncoder(w).Encode(pi)
}

func step_into(w http.ResponseWriter, r *http.Request, dbg *DebugState) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = run_command(dbg, "si\n")
}

func single_step(w http.ResponseWriter, r *http.Request, dbg *DebugState) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = run_command(dbg, "sa\n")
}

func run_line(w http.ResponseWriter, r *http.Request, dbg *DebugState) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = run_command(dbg, "s\n")
}

func continue_program(w http.ResponseWriter, r *http.Request, dbg *DebugState) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = run_command(dbg, "c\n")
}

type DebugState struct {
	conn net.Conn
	lock sync.Mutex
}

func main() {
	port_str := ":8675"

	conn, err := net.Dial("tcp", "127.0.0.1:5000")
	if err != nil {
		log.Fatal("Failed to connect to debugger!")
	}

	dbg := &DebugState{conn: conn}

	fs := http.FileServer(http.Dir("./static"))
	http.HandleFunc("/get_file", get_file)
	http.HandleFunc("/set_breakpoint", func(w http.ResponseWriter, req *http.Request) { set_breakpoint(w, req, dbg) })
	http.HandleFunc("/clear_breakpoint", func(w http.ResponseWriter, req *http.Request) { clear_breakpoint(w, req, dbg) })
	http.HandleFunc("/get_registers", func(w http.ResponseWriter, req *http.Request) { get_registers(w, req, dbg) })
	http.HandleFunc("/single_step", func(w http.ResponseWriter, req *http.Request) { single_step(w, req, dbg) })
	http.HandleFunc("/step_into", func(w http.ResponseWriter, req *http.Request) { step_into(w, req, dbg) })
	http.HandleFunc("/run_line", func(w http.ResponseWriter, req *http.Request) { run_line(w, req, dbg) })
	http.HandleFunc("/cont", func(w http.ResponseWriter, req *http.Request) { continue_program(w, req, dbg) })
	http.HandleFunc("/get_file_list", func(w http.ResponseWriter, req *http.Request) { get_file_list(w, req, dbg) })
	http.HandleFunc("/breakpoints", func(w http.ResponseWriter, req *http.Request) { get_breakpoints(w, req, dbg) })
	http.HandleFunc("/current_position", func(w http.ResponseWriter, req *http.Request) { get_current_position(w, req, dbg) })
	http.Handle("/", fs)

	log.Printf("Listening on %s...\n", port_str)
	err = http.ListenAndServe(port_str, nil)
	if err != nil {
		log.Fatal(err)
	}
}
