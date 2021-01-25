package handlers

import (
	"context"
	"go-jwt-auth/data"
	"go-jwt-auth/utils"
	"net/http"
)

func (ah *AuthHandler) UpdateUsername(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	user := &data.User{}
	err := data.FromJSON(user, r.Body)
	if err != nil {
		ah.logger.Error("unable to decode user json", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		data.ToJSON(&GenericResponse{Status: false, Message: err.Error()}, w)
		return
	}

	user.ID = r.Context().Value(UserIDKey{}).(string)
	ah.logger.Debug("updating username for user : ", user)

	err = ah.repo.UpdateUsername(context.Background(), user)
	if err != nil {
		ah.logger.Error("unable to update username", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: "Unable to update username. Please try again"}, w)
		return
	}

	w.WriteHeader(http.StatusOK)
	data.ToJSON(&GenericResponse{
		Status:  true,
		Message: "Succsssfully updated username",
		Data:    &UsernameUpdate{Username: user.Username},
	}, w)
}

func (ah *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	passResetReq := &PasswordResetReq{}
	err := data.FromJSON(passResetReq, r.Body)
	if err != nil {
		ah.logger.Error("unable to decode password reset requeset json", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		data.ToJSON(&GenericResponse{Status: false, Message: err.Error()}, w)
		return
	}

	userID := r.Context().Value(UserIDKey{}).(string)
	user, err := ah.repo.GetUserByID(context.Background(), userID)
	if err != nil {
		ah.logger.Error("unable to retrive the user from db", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: "Unable to reset password"}, w)
		return
	}

	verification, err := ah.repo.GetVerificationData(context.Background(), user.Email, data.PassReset)
	if err != nil {
		ah.logger.Error("unable to retrieve the verification data from db", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: "unable to reset password"}, w)
		return
	}

	if passResetReq.Password != passResetReq.PasswordRe {
		ah.logger.Error("password and password re-enter did not match")
		w.WriteHeader(http.StatusNotAcceptable)
		data.ToJSON(&GenericResponse{Status: false, Message: "password and re-entered password"}, w)
		return
	}

	hashedPass, err := ah.hashPassword(passResetReq.Password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: UserCreationFailed}, w)
		return
	}

	tokenHash := utils.GenerateRandomString(15)
	err = ah.repo.UpdatePassword(context.Background(), userID, hashedPass, tokenHash)
	if err != nil {
		ah.logger.Error("unable to update user password in db", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericResponse{Status: false, Message: "password and re-entered"}, w)
		return
	}

	err = ah.repo.DeleteVerificationData(context.Background(), verification.Email, verification.Type)
	if err != nil {
		ah.logger.Error("unable to delete the verification", "error", err)
	}

	w.WriteHeader(http.StatusOK)
	data.ToJSON(&GenericResponse{Status: true, Message: "Password reset Successfully"}, w)
}
