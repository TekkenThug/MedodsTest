package jwt

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	GUID string `json:"guid"`
	jwt.RegisteredClaims
}

type JWT struct {
	secret string
}

type TokenPair struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

func NewJWT(secret string) *JWT {
	return &JWT{
		secret: secret,
	}
}

const RefreshTime = 7 * 24 * time.Hour

const DefaultRefreshLength = 12

func generateRefreshToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (obj *JWT) GenerateTokens(GUID string) (*TokenPair, error) {
	accessExpirationTime := time.Now().Add(5 * time.Minute)
	accessClaims := &Claims{
		GUID: GUID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessExpirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims).SignedString([]byte(obj.secret))
	if err != nil {
		return nil, err
	}

	refreshToken, err := generateRefreshToken(DefaultRefreshLength)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		Access:  accessToken,
		Refresh: refreshToken,
	}, nil
}

func (obj *JWT) Parse(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(obj.secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
