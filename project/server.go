package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

// GreetingHandler handles the greeting request
func GreetingHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello")
}

// FileUploadHandler handles file upload requests
func FileUploadHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 20) // 10 MB
	if err != nil {
		log.Printf("Error parsing form: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		log.Printf("Error retrieving file: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	log.Printf("Received File: %s", handler.Filename)

	// Save the uploaded file
	f, err := os.OpenFile("./uploads/"+handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		log.Printf("Error saving file: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	io.Copy(f, file)

	fmt.Fprintln(w, "File uploaded successfully")
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", GreetingHandler)
	mux.HandleFunc("/upload", FileUploadHandler)

	server := &http.Server{
		Addr:    ":9090",
		Handler: mux,
	}

	log.Println("Server listening on port 9090...")
	err := server.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
