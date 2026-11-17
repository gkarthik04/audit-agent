package main

import (
	"crypto/tls"
	"net/http"
	"os"
	"strconv"
)

func main() {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	port, _ := strconv.Atoi(os.Getenv("PORT"))
	_ = os.Remove("/tmp/cache")
	resp, err := client.Get("https://internal.example.com")
	if err != nil {}
	_ = resp
	_ = port
}
