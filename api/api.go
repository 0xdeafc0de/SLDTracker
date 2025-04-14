package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/0xdeafc0de/sldtracker/sld"
)

type API struct {
	Store *sld.SLDStore
}

func New(store *sld.SLDStore) *API {
	return &API{Store: store}
}

func (a *API) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	fqdn := r.URL.Query().Get("fqdn")
	if fqdn == "" {
		http.Error(w, "fqdn param missing", http.StatusBadRequest)
		return
	}
	a.Store.Add(fqdn)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) HandleTop(w http.ResponseWriter, r *http.Request) {
	nStr := r.URL.Query().Get("n")
	n := 10
	if nStr != "" {
		if v, err := strconv.Atoi(nStr); err == nil {
			n = v
		}
	}
	top := a.Store.TopN(n)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(top)
}

func (a *API) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK " + time.Now().String()))
}

