package main

import (
	"net"
	"fmt"
	"log"
	"strings"
	"strconv"
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

func get_file_list(w http.ResponseWriter, r *http.Request, conn *net.Conn) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, err := (*conn).Write([]byte("fs\n"))
	if err != nil {
		log.Fatal("Failed to send file list cmd!")
	}

	data := make([]byte, 4096)
	size, err := (*conn).Read(data)
	if err != nil {
		log.Fatal("Failed to get file list!")
	}

	str_data := string(data[0:size])

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

func set_breakpoint(w http.ResponseWriter, r *http.Request, conn *net.Conn) {
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

	_, err = (*conn).Write([]byte(cmd))
	if err != nil {
		log.Fatal("Failed to send set_breakpoint cmd!")
	}
}

func clear_breakpoint(w http.ResponseWriter, r *http.Request, conn *net.Conn) {
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

	_, err = (*conn).Write([]byte(cmd))
	if err != nil {
		log.Fatal("Failed to send clear_breakpoint cmd!")
	}
}

func get_registers(w http.ResponseWriter, r *http.Request, conn *net.Conn) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, err := (*conn).Write([]byte("p\n"))
	if err != nil {
		log.Fatal("Failed to send register cmd!")
	}

	data := make([]byte, 4096)
	size, err := (*conn).Read(data)
	if err != nil {
		log.Fatal("Failed to get registers!")
	}

	str_data := string(data[0:size])

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

func step_program(w http.ResponseWriter, r *http.Request, conn *net.Conn) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, err := (*conn).Write([]byte("s\n"))
	if err != nil {
		log.Fatal("Failed to send step cmd!")
	}
}

func continue_program(w http.ResponseWriter, r *http.Request, conn *net.Conn) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, err := (*conn).Write([]byte("c\n"))
	if err != nil {
		log.Fatal("Failed to send continue cmd!")
	}
}

func main() {
	port_str := ":8675"

	conn, err := net.Dial("tcp", "127.0.0.1:5000")
	if err != nil {
		log.Fatal("Failed to connect to debugger!")
	}


	fs := http.FileServer(http.Dir("./static"))
	http.HandleFunc("/get_file", get_file)
	http.HandleFunc("/set_breakpoint", func(w http.ResponseWriter, req *http.Request) { set_breakpoint(w, req, &conn) })
	http.HandleFunc("/clear_breakpoint", func(w http.ResponseWriter, req *http.Request) { clear_breakpoint(w, req, &conn) })
	http.HandleFunc("/get_registers", func(w http.ResponseWriter, req *http.Request) { get_registers(w, req, &conn) })
	http.HandleFunc("/step_program", func(w http.ResponseWriter, req *http.Request) { step_program(w, req, &conn) })
	http.HandleFunc("/continue_program", func(w http.ResponseWriter, req *http.Request) { continue_program(w, req, &conn) })
	http.HandleFunc("/get_file_list", func(w http.ResponseWriter, req *http.Request) { get_file_list(w, req, &conn) })
	http.Handle("/", fs)

	log.Printf("Listening on %s...\n", port_str)
	err = http.ListenAndServe(port_str, nil)
	if err != nil {
		log.Fatal(err)
	}
}
