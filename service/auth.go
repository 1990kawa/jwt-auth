package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go-jwt-auth/data"
	"go-jwt-auth/utils"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/crypto/bcrypt"
)

type Authentication interface {
	Authenticate(reqUser *data.User, user *data.User) bool
	GenerateAccessToken(user *data.User) (string, error)
	GenerateRefreshToken(user *data.User) (string, error)
	GenerateCustomKey(userID string, password string) string
	ValidateAccessToken(token string) (string, error)
	ValidateRefreshToken(token string) (string, string, error)
}

type RefreshTokenClaims struct {
	UserID    string
	CustomKey string
	KeyType   string
	jwt.StandardClaims
}

type AccessTokenCustomClaims struct {
	UserID  string
	KeyType string
	jwt.StandardClaims
}

type AuthService struct {
	logger  hclog.Logger
	configs *utils.Configurations
}

func NewAuthService(logger hclog.Logger, configs *utils.Configurations) *AuthService {
	return &AuthService{logger, configs}
}

func (auth *AuthService) Authenticate(reqUser *data.User, user *data.User) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(reqUser.Password)); err != nil {
		auth.logger.Debug("password hashes are not same")
		return false
	}

	return true
}

func (auth *AuthService) GenerateRefreshToken(user *data.User) (string, error) {
	cusKey := auth.GenerateCustomKey(user.ID, user.TokenHash)
	tokenType := "refresh"

	claims := RefreshTokenClaims{
		user.ID,
		cusKey,
		tokenType,
		jwt.StandardClaims{
			Issuer: "bookite.auth.service",
		},
	}

	signBytes, err := ioutil.ReadFile(auth.configs.RefreshTokenPrivateKeyPath)
	if err != nil {
		auth.logger.Error("unable to read private key", "error", err)
		return "", errors.New("could not generate refresh token. please try again later")
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		auth.logger.Error("unable to parse private key", "error", err)
		return "", errors.New("could not generate refresh token. please try again later")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(signKey)
}

func (auth *AuthService) GenerateCustomKey(userID string, tokenHash string) string {
	h := hmac.New(sha256.New, []byte(tokenHash))
	h.Write([]byte(userID))
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}

func (auth *AuthService) GenerateAccessToken(user *data.User) (string, error) {
	userID := user.ID
	tokenType := "access"

	claims := AccessTokenCustomClaims{
		userID,
		tokenType,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * time.Duration(auth.configs.JwtExpiration)).Unix(),
			Issuer:    "bookiteeee.auth.service",
		},
	}

	signBytes, err := ioutil.ReadFile(auth.configs.AccessTokenPrivateKeyPath)
	if err != nil {
		auth.logger.Error("unable to read privatekey", "error", err)
		return "", errors.New("could not generate access token. please try again later")
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		auth.logger.Error("unable to parse private key", "error", err)
		return "", errors.New("could not generate access token. please try again later")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(signKey)
}

func (auth *AuthService) ValidateAccessToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			auth.logger.Error("Unexpected singing method in auth token")
			return nil, errors.New("Unexpexted signing method in auth token")
		}
		verifyBytes, err := ioutil.ReadFile(auth.configs.AccessTokenPublicKeyPath)
		if err != nil {
			auth.logger.Error("unable to read public key", "error", err)
			return nil, err
		}

		verifyKey, err := jwt.ParseRSAPrivateKeyFromPEM(verifyBytes)
		if err != nil {
			auth.logger.Error("unable to parse public key", "error", err)
			return nil, err
		}

		return verifyKey, nil
	})

	if err != nil {
		auth.logger.Error("unable to parse claims", "error", err)
		return "", err
	}

	claims, ok := token.Claims.(*AccessTokenCustomClaims)
	if !ok || !token.Valid || claims.UserID == "" || claims.KeyType != "access" {
		return "", errors.New("invalid token: authentication failed")
	}

	return claims.UserID, nil

}

func (auth *AuthService) ValidateRefreshToken(tokenString string) (string, string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			auth.logger.Error("Unexpected signing method in auth token")
			return nil, errors.New("Unexpected singing method in auth token")
		}

		verifyBytes, err := ioutil.ReadFile(auth.configs.RefreshTokenPublicKeyPath)
		if err != nil {
			auth.logger.Error("unable to read public key", "error", err)
			return nil, err
		}

		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
		if err != nil {
			auth.logger.Error("unable to parse public key", "error", err)
			return nil, err
		}

		return verifyKey, nil
	})

	if err != nil {
		auth.logger.Error("unable to parse claims", "error", err)
		return "", "", err
	}

	claims, ok := token.Claims.(*RefreshTokenClaims)
	auth.logger.Debug("ok", ok)
	if !ok || !token.Valid || claims.UserID == "" || claims.KeyType != "refresh" {
		auth.logger.Debug("could not extract claims from token")
		return "", "", errors.New("invalid token: authentication failed")
	}

	return claims.UserID, claims.CustomKey, nil
}
