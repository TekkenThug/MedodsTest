package user

import "medods/project/pkg/db"

type Repository struct {
	Database *db.Db
}

func NewRepository(database *db.Db) *Repository {
	return &Repository{
		Database: database,
	}
}

func (repository *Repository) GetByGUID(guid string) (*User, error) {
	var user User
	result := repository.Database.DB.First(&user, "guid = ?", guid)
	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}
