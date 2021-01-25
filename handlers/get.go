package handlers

import (
	"context"
	"go-jwt-auth/data"
	"go-jwt-auth/service"
	"go-jwt-auth/utils"
	"net/http"
	"time"
)

func (ah *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	user := r.Context().Value(UserKey{}).(data.User)
	accessToken, err := ah.authService.GenerateAccessToken(&user)
	if err != nil {
		ah.logger.Error("unable to generate access token", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: "Unable to generate access token. Please try again"}, w)
		return
	}

	w.WriteHeader(http.StatusOK)
	data.ToJSON(&GenericResponse{
		Status:  true,
		Message: "Successfully generated new access Token",
		Data:    &TokenResponse{AccessToken: accessToken},
	}, w)
}

func (ah *AuthHandler) Greet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID := r.Context().Value(UserIDKey{}).(string)
	w.WriteHeader(http.StatusOK)
	data.ToJSON(&GenericResponse{
		Status:  true,
		Message: "hello," + userID,
	}, w)
}

func (ah *AuthHandler) GeneratePassResetCode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID := r.Context().Value(UserIDKey{}).(string)
	user, err := ah.repo.GetUserByID(context.Background(), userID)
	if err != nil {
		ah.logger.Error("unable to get user to generate secret code for password reset", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: "Unable to send password reset code. Please try again"}, w)
		return
	}

	from := "hoge@gmail.com"
	to := []string{user.Email}
	subject := "Password Reset for Bookite"
	mailType := service.PassReset
	mailData := &service.MailData{
		Username: user.Username,
		Code:     utils.GenerateRandomString(8),
	}

	mailReq := ah.mailService.NewMail(from, to, subject, mailType, mailData)
	err = ah.mailService.SendMail(mailReq)
	if err != nil {
		ah.logger.Error("unable to send mail", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: "Unable to send password reset code. Please try again."}, w)
		return
	}

	verificationData := &data.VerificationData{
		Email:     user.Email,
		Code:      mailData.Code,
		Type:      data.PassReset,
		ExpiresAt: time.Now().Add(time.Minute * time.Duration(ah.configs.PassResetCodeExpiration)),
	}

	err = ah.repo.StoreVerificationData(context.Background(), verificationData)
	if err != nil {
		ah.logger.Error("unable to store password reset verification data", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: "Unable to send password reset code. Please try againg"}, w)
		return
	}

	ah.logger.Debug("successfully mailed password reset code")
	w.WriteHeader(http.StatusOK)
	data.ToJSON(&GenericResponse{Status: true, Message: "Please check your mail for password reset code"}, w)
}
