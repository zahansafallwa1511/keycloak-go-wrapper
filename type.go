package keycloakgo

// KeycloakUser keycloak create user
type KeycloakUser struct {
	ID          string
	LocalUserID string
	Name        string
	Email       string
	Attribute   map[string][]string
}

// KeycloakUserUpdate update keycloak user
type KeycloakUserUpdate struct {
	Name    *string
	Email   *string
	Enabled *bool
	Plan    *string
	Group   *string
}
