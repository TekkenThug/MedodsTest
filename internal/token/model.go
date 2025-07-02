package token

import (
	"gorm.io/gorm"
)

type Token struct {
	gorm.Model
	Hash      string
	UserAgent string
	Address   string
	UserId    string `json:"guid"`
}
