package keycloakgo

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/sirupsen/logrus"
)

// client errors
var (
	ErrInvalidToken   = errors.New("invalid token")
	ErrClientNotFound = errors.New("client not found")
	ErrUserNotFound   = errors.New("user not found")
)

const adminClientID = "admin-cli"

// Config configs for keycloak
type Config struct {
	Host          string `json:"host"`
	AdminUser     string `json:"admin_user"`
	AdminPassword string `json:"admin_password"`
	AdminRealm    string `json:"admin_realm"`
	AdminSecret   string `json:"admin_secret"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	ClientRealm   string `json:"client_realm"`
}

type keycloakClient struct {
	id       string
	clientID string
}

type adminClient struct {
	mu            sync.RWMutex
	admin         *gocloak.JWT
	accessExpiry  time.Time
	refreshExpiry time.Time
}

// Client keycloak client
type Client struct {
	cfg    Config
	ctx    context.Context
	kc     *gocloak.GoCloak
	ac     *adminClient
	client keycloakClient
	realm  string
	iss    string
	l      *logrus.Logger
}

// NewClient instantiate keycloak client
func NewClient(cfg Config, l *logrus.Logger) (*Client, error) {
	ctx := context.Background()
	kClient := gocloak.NewClient(cfg.Host)
	admin, err := kClient.Login(ctx, adminClientID, cfg.AdminSecret, cfg.AdminRealm, cfg.AdminUser, cfg.AdminPassword)
	if err != nil {
		l.Errorf("NewClient", err, "failed to log admin user in")
		return nil, err
	}
	clients, err := kClient.GetClients(ctx, admin.AccessToken, cfg.ClientRealm, gocloak.GetClientsParams{ClientID: &cfg.ClientID})
	if err != nil {
		return nil, err
	}
	if len(clients) == 0 {
		return nil, ErrClientNotFound
	}

	return &Client{
		cfg: cfg,
		ctx: ctx,
		kc:  kClient,
		ac: &adminClient{
			admin:         admin,
			accessExpiry:  time.Now().Add(time.Second * time.Duration(admin.ExpiresIn)),
			refreshExpiry: time.Now().Add(time.Second * time.Duration(admin.RefreshExpiresIn)),
		},
		client: keycloakClient{
			id:       *clients[0].ID,
			clientID: *clients[0].ClientID,
		},
		realm: cfg.ClientRealm,
		iss:   cfg.Host + "/auth/realms/" + cfg.ClientRealm,
		l:     l,
	}, nil
}

// RefreshAdmin validateAdmin this function will check for the admin AccessToken and RefreshToken and will update tokens as necessary
func (c *Client) RefreshAdmin() error {
	var admin *gocloak.JWT
	var err error

	c.ac.mu.Lock()
	defer c.ac.mu.Unlock()

	if time.Now().Before(c.ac.refreshExpiry) {
		admin, err = c.kc.RefreshToken(c.ctx, c.ac.admin.RefreshToken, adminClientID, c.cfg.AdminSecret, c.cfg.AdminRealm)
		if err != nil {
			c.l.Errorf("RefreshAdmin", err, "failed to refresh admin token")
			return err
		}
	} else {
		admin, err = c.kc.Login(c.ctx, adminClientID, c.cfg.AdminSecret, c.cfg.AdminRealm, c.cfg.AdminUser, c.cfg.AdminPassword)
		if err != nil {
			c.l.Errorf("RefreshAdmin", err, "failed to login admin")
			return err
		}
	}

	c.ac.admin = admin
	c.ac.accessExpiry = time.Now().Add(time.Second * time.Duration(admin.ExpiresIn))
	c.ac.refreshExpiry = time.Now().Add(time.Second * time.Duration(admin.RefreshExpiresIn))
	c.l.Info("RefreshAdmin: tokens are active")
	return nil
}

// AdminExpiresIn time left to expire the admin token
func (c *Client) AdminExpiresIn() time.Duration {
	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()

	return c.ac.accessExpiry.Sub(time.Now())
}

// CreateUser create kc user
func (c *Client) CreateUser(user *KeycloakUser, password string, temporary bool) error {
	roles := []gocloak.Role{}

	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()

	var err error
	user.ID, err = c.kc.CreateUser(c.ctx, c.ac.admin.AccessToken, c.realm, gocloak.User{
		Username:      &user.Email,
		Email:         &user.Email,
		EmailVerified: gocloak.BoolP(false),
		Enabled:       gocloak.BoolP(true),
		FirstName:     &user.Name,
		Attributes:    &user.Attribute,
		Credentials: &[]gocloak.CredentialRepresentation{
			{
				Temporary: gocloak.BoolP(temporary),
				Type:      gocloak.StringP("password"),
				Value:     &password,
			},
		},
	})
	if err != nil {
		c.l.Errorf("CreateUser: failed creating user: %s", user.Email)
		return err
	}

	err = c.kc.AddClientRoleToUser(c.ctx, c.ac.admin.AccessToken, c.realm, c.client.id, user.ID, roles)
	if err != nil {
		c.l.Errorf("CreateUser: failed adding role to user: %s", user.ID)
		return err
	}
	return nil
}

// Login keycloack account login
func (c *Client) Login(username, password string) (*gocloak.JWT, error) {
	// c.l.Started("Login")
	t, err := c.kc.Login(c.ctx, c.client.clientID, c.cfg.ClientSecret, c.realm, username, password)
	if err != nil {
		c.l.Errorf("Login", err, "failed login %s", username)
		return nil, err
	}
	return t, nil
}

// Refresh an active refreshToken
// only used for the clients
func (c *Client) Refresh(refreshToken string) (*gocloak.JWT, error) {
	// c.l.Started("Refresh")
	t, err := c.kc.RefreshToken(c.ctx, refreshToken, c.client.clientID, c.cfg.ClientSecret, c.realm)
	if err != nil {
		// c.l.Errorf("Refresh", err, "failed refresh")
		return nil, err
	}
	// c.l.Completed("Refresh")
	return t, nil
}

// Logout scope of this method is revoke user refresh token
func (c *Client) Logout(refreshToken string) error {
	err := c.kc.Logout(c.ctx, c.client.clientID, c.cfg.ClientSecret, c.realm, refreshToken)
	if err != nil {
		c.l.Errorf("Logout", err, "failed logout")
		return err
	}
	return nil
}

// CheckEnabled check if the user is enabled
func (c *Client) CheckEnabled(userID string) (bool, error) {
	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()

	user, err := c.kc.GetUserByID(c.ctx, c.ac.admin.AccessToken, c.realm, userID)
	if err != nil {
		c.l.Errorf("CheckEnabled", err, "failed to get user: %s", userID)
		return false, err
	}
	return *user.Enabled, nil
}

// UpdateUser update the keycloak user
func (c *Client) UpdateUser(userID string, user KeycloakUserUpdate) error {
	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()

	var attr map[string][]string
	if user.Plan != nil {
		u, err := c.kc.GetUserByID(c.ctx, c.ac.admin.AccessToken, c.realm, userID)
		if err != nil {
			c.l.Errorf("UpdateUser", err, "failed to get user: %s", userID)
			return err
		}
		attr = *u.Attributes
		attr["plan"] = []string{*user.Plan}
	}

	if user.Group != nil {
		u, err := c.kc.GetUserByID(c.ctx, c.ac.admin.AccessToken, c.realm, userID)
		if err != nil {
			c.l.Errorf("UpdateUser", err, "failed to get user: %s", userID)
			return err
		}

		grps := fmt.Sprintf("%s,%s", (*u.Attributes)["groups"][0], *user.Group)
		attr = *u.Attributes
		attr["groups"] = []string{grps}
	}

	err := c.kc.UpdateUser(c.ctx, c.ac.admin.AccessToken, c.realm, gocloak.User{
		ID:         &userID,
		FirstName:  user.Name,
		Email:      user.Email,
		Enabled:    user.Enabled,
		Attributes: &attr,
	})
	if err != nil {
		c.l.Errorf("UpdateUser", err, "failed to update user: %s", userID)
	}
	return err
}

// SetEmailVerified will be used to verify email
func (c *Client) SetEmailVerified(userID string) error {
	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()

	_, err := c.kc.GetUserByID(c.ctx, c.ac.admin.AccessToken, c.realm, userID)
	if err != nil {
		c.l.Errorf("SetEmailVerified", err, "failed to get user: %s", userID)
		return err
	}
	err = c.kc.UpdateUser(c.ctx, c.ac.admin.AccessToken, c.realm, gocloak.User{
		ID:            &userID,
		EmailVerified: gocloak.BoolP(true),
	})
	if err != nil {
		c.l.Errorf("SetEmailVerified", err, "failed to update email-verified with user_id: %s", userID)
	}
	return err
}

// GetUserByUsername get user details by username
func (c *Client) GetUserByUsername(username string) (*gocloak.User, error) {
	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()

	user, err := c.kc.GetUsers(c.ctx, c.ac.admin.AccessToken, c.realm, gocloak.GetUsersParams{Username: &username})
	if err != nil {
		c.l.Errorf("GetUserByUsername", err, "failed to get user by %s", username)
		return nil, err
	}
	if len(user) == 0 {
		c.l.Errorf("GetUserByUsername", err, "failed to get user by %s", username)
		return nil, ErrUserNotFound
	}
	return user[0], nil
}

// GetUserByPhoneNumber get user details by phone number
func (c *Client) GetUserByPhoneNumber(phone string) (*gocloak.User, error) {
	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()

	user, err := c.kc.GetUsers(c.ctx, c.ac.admin.AccessToken, c.realm, gocloak.GetUsersParams{Username: &phone})
	if err != nil {
		c.l.Errorf("GetUserByPhoneNumber", err, "failed to get user by %s", phone)
		return nil, err
	}
	if len(user) == 0 {
		c.l.Errorf("GetUserByPhoneNumber", err, "failed to get user by %s", phone)
		return nil, ErrUserNotFound
	}
	return user[0], nil
}

// ResetPassword reset password for users
func (c *Client) ResetPassword(userID, password string) error {
	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()
	err := c.kc.SetPassword(c.ctx, c.ac.admin.AccessToken, userID, c.realm, password, false)
	if err != nil {
		c.l.Errorf("ResetPassword", err, "failed to update password with user_id: %s", userID)
		return err
	}
	return nil
}

// VerifyToken verify the user token
func (c *Client) VerifyToken(accessToken string) (*Claim, error) {
	claim := &Claim{
		clientID: c.client.clientID,
	}

	_, err := c.kc.DecodeAccessTokenCustomClaims(c.ctx, accessToken, c.realm, claim)
	if err != nil {
		c.l.Errorf("VerifyToken", err, "failed decode token")
		return claim, err
	}

	if err := claim.Valid(); err != nil {
		c.l.Errorf("VerifyToken: %s\n", ErrInvalidToken, "validation failed")
		return claim, ErrInvalidToken
	}
	return claim, nil
}
