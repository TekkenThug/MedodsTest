package user

import (
	"medods/project/internal/token"
)

type User struct {
	GUID  string      `gorm:"primaryKey"`
	Token token.Token `gorm:"constraints:OnDelete:CASCADE;"`
}
