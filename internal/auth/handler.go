package auth

import (
	"encoding/base64"
	"medods/project/pkg/jwt"
	"medods/project/pkg/middleware"
	"medods/project/pkg/request"
	"medods/project/pkg/response"
	"net/http"
	"time"
)

type Handler struct {
	Service *Service
}

type Deps struct {
	Service *Service
	Secret  string
}

const refreshCookieName = "refreshToken"

func NewHandler(router *http.ServeMux, deps *Deps) {
	handler := &Handler{
		Service: deps.Service,
	}

	router.Handle("GET /auth/login", handler.Login())
	router.Handle("POST /auth/refresh", handler.Refresh())
	router.Handle("GET /auth/me", middleware.Auth(handler.Me(), deps.Secret))
	router.Handle("POST /auth/logout", handler.Logout())
}

func setRefreshTokenInCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		HttpOnly: true,
		Value:    base64.StdEncoding.EncodeToString([]byte(token)),
		MaxAge:   int(time.Until(time.Now().Add(jwt.RefreshTime)).Seconds()),
		Path:     "/auth",
	})
}

func clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		HttpOnly: true,
		Value:    "",
		MaxAge:   -1,
		Path:     "/auth",
	})
}

func parseRefreshTokenFromCookie(req *http.Request) (string, error) {
	refreshCookie, err := req.Cookie(refreshCookieName)
	if err != nil {
		return "", err
	}

	refreshToken, err := base64.RawStdEncoding.DecodeString(refreshCookie.Value)
	if err != nil {
		return "", err
	}

	return string(refreshToken), nil
}

// Login godoc
// @Summary Аутентификация пользователя
// @Description Возвращает JWT-токен
// @Tags Auth
// @Accept json
// @Produce json
// @Param GUID query string true "User GUID"
// @Success 200 {object} TokenResponse
// @Failure 400 {string} string "Bad request"
// @Router /auth/login [get]
func (handler *Handler) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		guid := req.URL.Query().Get("GUID")

		if guid == "" {
			response.Send("Invalid GUID", w, http.StatusBadRequest)
			return
		}

		tokenPair, err := handler.Service.GetTokenPair(guid, req.UserAgent(), req.RemoteAddr)
		if err != nil {
			response.Send(err.Error(), w, http.StatusBadRequest)
			return
		}

		setRefreshTokenInCookie(w, tokenPair.Refresh)

		response.Send(&TokenResponse{
			Token: tokenPair.Access,
		}, w, http.StatusOK)
	}
}

// Refresh godoc
// @Summary Обновление токена
// @Description Возвращает новый JWT-токен
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body RefreshRequest true "Данные для обновления токена"
// @Success 200 {object} TokenResponse
// @Failure 400 {string} string "Bad request"
// @Router /auth/refresh [post]
func (handler *Handler) Refresh() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		refreshToken, err := parseRefreshTokenFromCookie(req)
		if err != nil {
			response.Send(err.Error(), w, http.StatusBadRequest)
			return
		}

		body, err := request.HandleBody[RefreshRequest](&w, req)
		if err != nil {
			response.Send(err.Error(), w, http.StatusBadRequest)
			return
		}

		tokenPair, err := handler.Service.RefreshTokens(body.AccessToken, refreshToken, req.UserAgent(), req.RemoteAddr)
		if err != nil {
			if err == ErrUserLoggedOut {
				clearRefreshCookie(w)
				response.Send(err.Error(), w, http.StatusUnauthorized)
				return
			}

			response.Send(err.Error(), w, http.StatusBadRequest)
			return
		}
		setRefreshTokenInCookie(w, tokenPair.Refresh)

		response.Send(&TokenResponse{
			Token: tokenPair.Access,
		}, w, 200)
	}
}

// Me godoc
// @Summary Получить данные текущего пользователя
// @Description Возвращает информацию о пользователе
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {object} MeResponse
// @Failure 401 {string} string "Unauthorized"
// @Security BearerAuth
// @Router /auth/me [get]
func (handler *Handler) Me() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		response.Send(&MeResponse{
			GUID: req.Context().Value(middleware.ContextGUIDKey).(string),
		}, w, 200)
	}
}

// Logout godoc
// @Summary Выход из системы
// @Description Деактивирует JWT-токен
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body LogoutRequest true "Данные для выхода"
// @Success 200 {string} string
// @Failure 400 {string} string
// @Router /auth/logout [post]
func (handler *Handler) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		refreshToken, err := parseRefreshTokenFromCookie(req)
		if err != nil {
			response.Send(err.Error(), w, http.StatusBadRequest)
			return
		}

		body, err := request.HandleBody[LogoutRequest](&w, req)
		if err != nil {
			response.Send(err.Error(), w, http.StatusBadRequest)
			return
		}

		err = handler.Service.Logout(body.AccessToken, refreshToken)
		if err != nil {
			response.Send(err.Error(), w, http.StatusBadRequest)
			return
		}

		clearRefreshCookie(w)
		response.Send("User successfully logout", w, http.StatusOK)
	}
}
