package request

import (
	"medods/project/pkg/response"
	"net/http"
)

func HandleBody[T any](w *http.ResponseWriter, r *http.Request) (*T, error) {
	body, err := decode[T](r.Body)
	if err != nil {
		response.Send(err.Error(), *w, 400)
		return nil, err
	}
	
	return &body, nil
}
