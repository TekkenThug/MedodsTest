package token

import "medods/project/pkg/db"

type Repository struct {
	Database *db.Db
}

func NewRepository(database *db.Db) *Repository {
	return &Repository{
		Database: database,
	}
}

func (repository *Repository) Create(token *Token) (*Token, error) {
	result := repository.Database.DB.Create(token)
	if result.Error != nil {
		return nil, result.Error
	}

	return token, nil
}

func (repository *Repository) GetByUserGUID(guid string) (*Token, error) {
	var token Token
	result := repository.Database.DB.First(&token, "user_id = ?", guid)
	if result.Error != nil {
		return nil, result.Error
	}

	return &token, nil
}

func (repository *Repository) Delete(id uint) error {
	result := repository.Database.DB.Unscoped().Delete(&Token{}, id)
	if result.Error != nil {
		return result.Error
	}

	return nil
}
