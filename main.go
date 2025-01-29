package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", Login).Methods("POST")
	r.HandleFunc("/home", Home).Methods("GET")
	r.HandleFunc("/refresh", Refresh).Methods("GET")

	log.Fatal(http.ListenAndServe(":8080", r))
}
