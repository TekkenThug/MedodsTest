package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"medods/project/internal/token"
	"medods/project/internal/user"
	"medods/project/pkg/jwt"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserLoggedOut = errors.New("user logged out")
)

type Service struct {
	UserRepository  *user.Repository
	TokenRepository *token.Repository
	Jwt             *jwt.JWT
}

type ServiceDeps struct {
	UserRepository  *user.Repository
	TokenRepository *token.Repository
	Jwt             *jwt.JWT
}

func NewService(deps *ServiceDeps) *Service {
	return &Service{
		UserRepository:  deps.UserRepository,
		TokenRepository: deps.TokenRepository,
		Jwt:             deps.Jwt,
	}
}

func (service *Service) GetTokenPair(guid string, userAgent string, ipAddr string) (*jwt.TokenPair, error) {
	user, err := service.UserRepository.GetByGUID(guid)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, errors.New("incorrect GUID")
	}

	token, _ := service.TokenRepository.GetByUserGUID(guid)
	if token != nil {
		return nil, errors.New("user already login")
	}

	tokens, err := service.Jwt.GenerateTokens(guid)
	if err != nil {
		return nil, err
	}

	err = service.SaveRefreshToken(tokens.Refresh, userAgent, ipAddr, guid)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

func (service *Service) SaveRefreshToken(refreshToken string, userAgent string, ipAddr string, guid string) error {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = service.TokenRepository.Create(&token.Token{
		Hash:      string(hashedToken),
		UserAgent: userAgent,
		Address:   ipAddr,
		UserId:    guid,
	})
	if err != nil {
		return err
	}

	return nil
}

func (service *Service) ValidateRefreshToken(accessToken string, refreshToken string) (*token.Token, error) {
	claims, err := service.Jwt.Parse(accessToken)
	if err != nil {
		return nil, err
	}

	token, err := service.TokenRepository.GetByUserGUID(claims.GUID)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(token.Hash), []byte(refreshToken))
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (service *Service) RefreshTokens(accessToken string, refreshToken string, userAgent string, ipAddr string) (*jwt.TokenPair, error) {
	token, err := service.ValidateRefreshToken(accessToken, refreshToken)
	if err != nil {
		return nil, err
	}

	if userAgent != token.UserAgent {
		service.TokenRepository.Delete(token.ID)
		return nil, ErrUserLoggedOut
	}

	if ipAddr != token.Address {
		go sendToWebhook(map[string]string{
			"title":  "foo",
			"body":   "bar",
			"userId": "1",
		})
	}

	err = service.TokenRepository.Delete(token.ID)
	if err != nil {
		return nil, err
	}

	tokenPair, err := service.GetTokenPair(token.UserId, userAgent, ipAddr)
	if err != nil {
		return nil, err
	}

	return tokenPair, nil
}

func (service *Service) Logout(accessToken string, refreshToken string) error {
	token, err := service.ValidateRefreshToken(accessToken, refreshToken)
	if err != nil {
		return err
	}
	service.TokenRepository.Delete(token.ID)
	return nil
}

func sendToWebhook(data map[string]string) {
	postBody, _ := json.Marshal(data)

	_, err := http.Post("https://jsonplaceholder.typicode.com/posts", "application/json", bytes.NewBuffer(postBody))
	if err != nil {
		log.Fatalf("Error in webhook: %v", err)
		return
	}

	log.Println("Success sending to webhook")
}
