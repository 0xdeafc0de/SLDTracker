package main

import (
	"log"
	"net/http"

	"github.com/0xdeafc0de/sldtracker/api"
	"github.com/0xdeafc0de/sldtracker/pkts"
	"github.com/0xdeafc0de/sldtracker/sld"
)

func main() {
	store := sld.NewSLDStore(60*24) // 1-day window
	handler := api.New(store)

	go func() {
		sniffer := pkts.NewPacketSniffer("en0")
		err := sniffer.Start(func(domain string) {
			log.Println("Got", domain)
			sldName := sld.ExtractSLD(domain, true)
			if sldName != "" {
				store.Track(sldName)
			}
		})

		if err != nil {
			log.Fatal("Sniffer error:", err)
		}
	}()

	http.HandleFunc("/submit", handler.HandleSubmit)
	http.HandleFunc("/top", handler.HandleTop)
	http.HandleFunc("/health", handler.HandleHealth)

	log.Println("Server started on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

