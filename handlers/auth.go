package handlers

import (
	"fmt"
	"go-jwt-auth/data"
	"go-jwt-auth/service"
	"go-jwt-auth/utils"

	"github.com/hashicorp/go-hclog"
)

type UserKey struct{}
type UserIDKey struct{}
type VerificationDataKey struct{}

type AuthHandler struct {
	logger      hclog.Logger
	configs     *utils.Configurations
	validator   *data.Validation
	repo        data.Repository
	authService service.Authentication
	mailService service.MailService
}

func NewAuthHandler(l hclog.Logger, c *utils.Configurations, v *data.Validation, r data.Repository, auth service.Authentication, mail service.MailService) *AuthHandler {
	return &AuthHandler{
		logger:      l,
		configs:     c,
		validator:   v,
		repo:        r,
		authService: auth,
		mailService: mail,
	}
}

type GenericResponse struct {
	Status  bool        `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type ValidataionError struct {
	Errors []string `json:"errors"`
}

type TokenResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Username     string `json:"username"`
}

type UsernameUpdate struct {
	Username string `json:"username"`
}

type CodeVerificationReq struct {
	Code string `json:"code"`
	Type string `json:"type"`
}

type PasswordResetReq struct {
	Password   string `json:"password"`
	PasswordRe string `json:"password_re"`
	Code       string `json:"code"`
}

var ErrUserAlreadyExists = fmt.Sprintf("User already exists with the given email")
var ErrUserNotFound = fmt.Sprintf("No user account exists with given email. Please sign in first")
var UserCreationFailed = fmt.Sprintf("Unable to create user.Please try again later")

var PgDuplicateKeyMsg = "duplicate key value violates unique constraint"
var PgNoRowsMsg = "no rows in result set"
