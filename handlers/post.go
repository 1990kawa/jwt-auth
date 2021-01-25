package handlers

import (
	"context"
	"errors"
	"go-jwt-auth/data"
	"go-jwt-auth/service"
	"go-jwt-auth/utils"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (ah *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	user := r.Context().Value(UserKey{}).(data.User)

	hashedPass, err := ah.hashPassword(user.Password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: UserCreationFailed}, w)
		return
	}

	user.Password = hashedPass
	user.TokenHash = utils.GenerateRandomString(15)

	err = ah.repo.Create(context.Background(), &user)
	if err != nil {
		ah.logger.Error("unable to insert user to database", "error", err)
		errMsg := err.Error()
		if strings.Contains(errMsg, PgDuplicateKeyMsg) {
			w.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&GenericResponse{Status: false, Message: ErrUserAlreadyExists}, w)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			data.ToJSON(&GenericResponse{Status: false, Message: UserCreationFailed}, w)
		}

		return
	}

	from := "hoge@gmail.com"
	to := []string{user.Email}
	subject := "Email Verification for foo"
	mailType := service.MailConfirmation
	mailData := &service.MailData{
		Username: user.Username,
		Code:     utils.GenerateRandomString(8),
	}

	mailReq := ah.mailService.NewMail(from, to, subject, mailType, mailData)
	err = ah.mailService.SendMail(mailReq)
	if err != nil {
		ah.logger.Error("unable to send mail", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: UserCreationFailed}, w)
		return
	}

	verificationData := &data.VerificationData{
		Email:     user.Email,
		Code:      mailData.Code,
		Type:      data.MailConfirmation,
		ExpiresAt: time.Now().Add(time.Hour * time.Duration(ah.configs.MailVerifCodeExpiration)),
	}

	err = ah.repo.StoreVerificationData(context.Background(), verificationData)
	if err != nil {
		ah.logger.Error("unable to store mail", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: UserCreationFailed}, w)
		return
	}

	ah.logger.Debug("User created successfully")
	w.WriteHeader(http.StatusCreated)
	data.ToJSON(&GenericResponse{Status: true, Message: "Please Verify your email account"}, w)
}

func (ah *AuthHandler) hashPassword(password string) (string, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		ah.logger.Error("unable to hash password", "error", err)
		return "", err
	}
	return string(hashedPass), nil
}

func (ah *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	reqUser := r.Context().Value(UserKey{}).(data.User)

	user, err := ah.repo.GetUserByEmail(context.Background(), reqUser.Email)
	if err != nil {
		ah.logger.Error("error fetching the user", "error", err)
		errMsg := err.Error()
		if strings.Contains(errMsg, PgNoRowsMsg) {
			w.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&GenericResponse{Status: false, Message: ErrUserNotFound}, w)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			data.ToJSON(&GenericResponse{Status: false, Message: "Unable to retrieve user from database"}, w)
		}
		return
	}

	if !user.IsVerified {
		ah.logger.Error("unverified user")
		w.WriteHeader(http.StatusUnauthorized)
		data.ToJSON(&GenericResponse{Status: false, Message: "Please verify your mail address before login"}, w)
		return
	}

	if valid := ah.authService.Authenticate(&reqUser, user); !valid {
		ah.logger.Debug("Authentication of user failed")
		w.WriteHeader(http.StatusBadRequest)
		data.ToJSON(&GenericResponse{Status: false, Message: "Incorrect password"}, w)
		return
	}

	accessToken, err := ah.authService.GenerateAccessToken(user)
	if err != nil {
		ah.logger.Error("unable to generate access token", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: "Unable to login the user. Please try again"}, w)
		return
	}

	refreshToken, err := ah.authService.GenerateRefreshToken(user)
	if err != nil {
		ah.logger.Error("unable to generate refresh token", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: "Unable to login the user. Please try again"}, w)
		return
	}

	ah.logger.Debug("successfully generated token", "accesstoken", accessToken, "refreshtoken", refreshToken)
	w.WriteHeader(http.StatusOK)
	data.ToJSON(&GenericResponse{
		Status:  true,
		Message: "Successfully logged in",
		Data:    &AuthResponse{AccessToken: accessToken, RefreshToken: refreshToken, Username: user.Username},
	}, w)
}

func (ah *AuthHandler) VerifyMail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ah.logger.Debug("verifying the confimation code")
	verificationData := r.Context().Value(VerificationDataKey{}).(data.VerificationData)
	verificationData.Type = data.MailConfirmation

	actualVerificationData, err := ah.repo.GetVerificationData(context.Background(), verificationData.Email, verificationData.Type)
	if err != nil {
		ah.logger.Error("unable to fetch verification data", "error", err)

		if strings.Contains(err.Error(), PgNoRowsMsg) {
			w.WriteHeader(http.StatusNotAcceptable)
			data.ToJSON(&GenericResponse{Status: false, Message: ErrUserNotFound}, w)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: "Unable to verify mail. Please try again"}, w)
		return
	}

	valid, err := ah.verify(actualVerificationData, &verificationData)
	if !valid {
		w.WriteHeader(http.StatusNotAcceptable)
		data.ToJSON(&GenericResponse{Status: false, Message: err.Error()}, w)
		return
	}

	err = ah.repo.DeleteVerificationData(context.Background(), verificationData.Email, verificationData.Type)
	if err != nil {
		ah.logger.Error("unable to delete the verification data", "error", err)
	}

	ah.logger.Debug("user email verification succeeded")

	w.WriteHeader(http.StatusAccepted)
	data.ToJSON(&GenericResponse{Status: true, Message: "Mail Verification succeeded"}, w)
}

func (ah *AuthHandler) VerifyPasswordReset(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	ah.logger.Debug("verifing pasword reset code")
	verificationData := r.Context().Value(VerificationDataKey{}).(data.VerificationData)
	verificationData.Type = data.PassReset

	actualVerificationData, err := ah.repo.GetVerificationData(context.Background(), verificationData.Email, verificationData.Type)
	if err != nil {
		ah.logger.Error("unable to fetch verification data", "error", err)
		if strings.Contains(err.Error(), PgNoRowsMsg) {
			w.WriteHeader(http.StatusNotAcceptable)
			data.ToJSON(&GenericResponse{Status: false, Message: ErrUserNotFound}, w)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: "Unable to reset password. Please try again"}, w)
		return
	}

	valid, err := ah.verify(actualVerificationData, &verificationData)
	if !valid {
		w.WriteHeader(http.StatusNotAcceptable)
		data.ToJSON(&GenericResponse{Status: false, Message: err.Error()}, w)
		return
	}

	respData := struct {
		Code string
	}{
		Code: verificationData.Code,
	}

	ah.logger.Debug("password reset code verification succeeded")
	w.WriteHeader(http.StatusAccepted)
	data.ToJSON(&GenericResponse{Status: true, Message: "Password Reset code", Data: respData}, w)
}

func (ah *AuthHandler) verify(actualVerificationData *data.VerificationData, verificationData *data.VerificationData) (bool, error) {
	if actualVerificationData.ExpiresAt.Before(time.Now()) {
		ah.logger.Error("verification data provided is expired")
		err := ah.repo.DeleteVerificationData(context.Background(), actualVerificationData.Email, actualVerificationData.Type)
		ah.logger.Error("unable to delete verification data from db", "error", err)
		return false, errors.New("Confirmation code has expired. Please try")
	}

	if actualVerificationData.Code != verificationData.Code {
		ah.logger.Error("verification of mail failed. Invalid verification code")
		return false, errors.New("Verification code provided is Invalid")
	}

	return true, nil
}
