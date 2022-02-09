package main

import (
	"fmt"
	"log"
	"io/ioutil"
	"net/http"
	"encoding/json"
)

type File struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

func get_file(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	file_name := "../main.c"

	file_str, err := ioutil.ReadFile(file_name)
	if err != nil {
		fmt.Fprintf(w, "Failed to open file!")
		return
	}

	f := &File{Name: file_name, Data: string(file_str)}
	json.NewEncoder(w).Encode(f)
}

func set_breakpoint(w http.ResponseWriter, req *http.Request) {
}

func clear_breakpoint(w http.ResponseWriter, req *http.Request) {
}

func main() {
	port_str := ":8675"

	fs := http.FileServer(http.Dir("./static"))
	http.HandleFunc("/get_file", get_file)
	http.HandleFunc("/set_breakpoint", set_breakpoint)
	http.HandleFunc("/clear_breakpoint", clear_breakpoint)
	http.Handle("/", fs)

	log.Printf("Listening on %s...\n", port_str)
	err := http.ListenAndServe(port_str, nil)
	if err != nil {
		log.Fatal(err)
	}
}
