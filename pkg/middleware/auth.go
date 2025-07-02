package middleware

import (
	"context"
	"medods/project/pkg/jwt"
	"net/http"
	"strings"
)

type key string

const (
	ContextGUIDKey key = "ContextGUIDKey"
)

func writeUnauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
}

func Auth(next http.Handler, secret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			writeUnauthorized(w)
			return
		}

		token := strings.TrimPrefix(header, "Bearer ")
		claims, err := jwt.NewJWT(secret).Parse(token)

		if err != nil {
			writeUnauthorized(w)
			return
		}

		ctx := context.WithValue(r.Context(), ContextGUIDKey, claims.GUID)
		req := r.WithContext(ctx)
		next.ServeHTTP(w, req)
	})
}
