package handlers

import (
	"context"
	"errors"
	"go-jwt-auth/data"
	"net/http"
	"strings"
)

func (ah *AuthHandler) MiddlewareValidateUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ah.logger.Debug("user json", r.Body)
		user := &data.User{}

		err := data.FromJSON(user, r.Body)
		if err != nil {
			ah.logger.Error("deserialization of user json failed", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&GenericResponse{Status: false, Message: err.Error()}, w)
			return
		}

		ctx := context.WithValue(r.Context(), UserKey{}, *user)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func (ah *AuthHandler) MiddlewareValidateAccessToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ah.logger.Debug("validating access token")

		token, err := extractToken(r)
		if err != nil {
			ah.logger.Error("Token not privided or malformed")
			w.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&GenericResponse{Status: false, Message: "Authenrication failed. Token not privided or malformed"}, w)
			return
		}

		ah.logger.Debug("token presetn in header", token)

		userID, err := ah.authService.ValidateAccessToken(token)
		if err != nil {
			ah.logger.Error("token validate failed", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&GenericResponse{Status: false, Message: "authentication failed. Inalid token"}, w)
			return
		}

		ah.logger.Debug("access token validated")

		ctx := context.WithValue(r.Context(), UserIDKey{}, userID)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)

	})
}

func (ah *AuthHandler) MiddlewareValidateRefreshToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		ah.logger.Debug("validating refresh token")
		ah.logger.Debug("auth header", r.Header.Get("Authorization"))
		token, err := extractToken(r)
		if err != nil {
			ah.logger.Error("token not provided or malformed")
			w.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&GenericResponse{Status: false, Message: "Authentication failed. Token not provided or malformed"}, w)
			return
		}

		ah.logger.Debug("token present in header", token)

		userID, customKey, err := ah.authService.ValidateRefreshToken(token)
		if err != nil {
			ah.logger.Error("token validation failed", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&GenericResponse{Status: false, Message: "Authentication failed. Invalid token"}, w)
			return
		}
		ah.logger.Debug("refresh token validated")

		user, err := ah.repo.GetUserByID(context.Background(), userID)
		if err != nil {
			ah.logger.Error("invalid token: wrong userID while parsing", err)
			w.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&GenericResponse{Status: false, Message: "Unable to fetch"}, w)
			return
		}

		actualCustomKey := ah.authService.GenerateCustomKey(user.ID, user.TokenHash)
		if customKey != actualCustomKey {
			ah.logger.Debug("wrong token: authetincation failed")
			w.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&GenericResponse{Status: false, Message: "Authentication failed."}, w)
			return
		}

		ctx := context.WithValue(r.Context(), UserKey{}, *user)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func (ah *AuthHandler) MiddlewareValidateVerificationData(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ah.logger.Debug("validating verification data")

		verificationData := &data.VerificationData{}

		err := data.FromJSON(verificationData, r.Body)
		if err != nil {
			ah.logger.Error("deserialization of verification data failed", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&GenericResponse{Status: false, Message: err.Error()}, w)
			return
		}

		errs := ah.validator.Validate(verificationData)
		if len(errs) != 0 {
			ah.logger.Error("validation of verification data json failed", "error", errs)
			w.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&GenericResponse{Status: false, Message: strings.Join(errs.Errors(), ",")}, w)
			return
		}

		ctx := context.WithValue(r.Context(), VerificationDataKey{}, *verificationData)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func extractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	authHeaderContent := strings.Split(authHeader, " ")
	if len(authHeaderContent) != 2 {
		return "", errors.New("Token not provided or malformed")
	}

	return authHeaderContent[1], nil
}
