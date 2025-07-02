package auth

type TokenResponse struct {
	Token string `json:"token"`
}

type RefreshRequest struct {
	AccessToken string `json:"access_token"`
}

type LogoutRequest struct {
	AccessToken string `json:"access_token"`
}
