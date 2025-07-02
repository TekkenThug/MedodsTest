package response

import (
	"encoding/json"
	"net/http"
)

func Send(res any, w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(res)
}
