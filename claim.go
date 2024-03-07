package keycloakgo

import (
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/guregu/null.v3"
)

type (
	// Claim keycloak jwt token
	Claim struct {
		clientID string
		jwt.MapClaims
		AuthorizedParty     string   `json:"azp"`
		Name                string   `json:"name"`
		Email               string   `json:"email"`
		EmailVerified       bool     `json:"email_verified"`
		PhoneNumber         string   `json:"phone_number"`
		PhoneNumberVerified bool     `json:"phone_number_verified"`
		Plan                string   `json:"plan"`
		Roles               []Role   `json:"roles"`
		LocalUserID         null.Int `json:"local_user_id"`
	}
	// Role user roles
	Role string
)

// Valid validate the jwt token
func (cl Claim) Valid() error {
	if cl.AuthorizedParty != cl.clientID {
		return ErrInvalidToken
	}
	return nil
}
