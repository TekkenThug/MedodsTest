package main

import (
	"medods/project/configs"
	"medods/project/internal/auth"
	"medods/project/internal/token"
	"medods/project/internal/user"
	"medods/project/pkg/db"
	"medods/project/pkg/jwt"
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger"
	_ "medods/project/docs"
)

// @title Medods API
// @version 1.0
// @description Auth testing API

func App() http.Handler {
	conf := configs.LoadConfig()
	db := db.NewDb(conf)
	router := http.NewServeMux()

	// Repositories
	userRepository := user.NewRepository(db)
	tokenRepository := token.NewRepository(db)

	// Services
	authService := auth.NewService(&auth.ServiceDeps{
		UserRepository:  userRepository,
		TokenRepository: tokenRepository,
		Jwt:             jwt.NewJWT(conf.Auth.Secret),
	})

	// Handlers
	auth.NewHandler(router, &auth.Deps{Service: authService, Secret: conf.Auth.Secret})

	router.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	return router
}

func main() {
	app := App()

	server := http.Server{
		Addr:    ":8000",
		Handler: app,
	}
	server.ListenAndServe()
}
