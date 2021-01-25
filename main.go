package main

import (
	"context"
	"go-jwt-auth/data"
	"go-jwt-auth/handlers"
	"go-jwt-auth/service"
	"go-jwt-auth/utils"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/hashicorp/go-hclog"
	"gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
)

const userSchema = `
		create table if not exists users (
			id 		   Varchar(36) not null,
			email 	   Varchar(100) not null unique,
			username   Varchar(225),
			password   Varchar(225) not null,
			tokenhash  Varchar(15) not null,
			isverified Boolean default false,
			createdat  Timestamp not null,
			updatedat  Timestamp not null,
			Primary Key (id)
		);
`
const verificationSchema = ` create table if not exists verifications (
			email 		Varchar(100) not null,
			code  		Varchar(10) not null,
			expiresat 	Timestamp not null,
			type        Varchar(10) not null,
			Primary Key (email),
			Constraint fk_user_email Foreign Key(email) References users(email)
				On Delete Cascade On Update Cascade
		)
`

func main() {
	logger := utils.NewLogger()

	configs := utils.NewConfigurations(logger)

	validator := data.NewValidation()

	db, err := data.NewConnection(configs, logger)
	if err != nil {
		logger.Error("unable to connect to db", "error", err)
		panic(err)
	}

	defer db.Close()

	db.MustExec(userSchema)
	db.MustExec(verificationSchema)

	repository := data.NewPostgresRepository(db, logger)
	authService := service.NewAuthService(logger, configs)
	mailService := service.NewSGMailService(logger, configs)

	uh := handlers.NewAuthHandler(logger, configs, validator, repository, authService, mailService)

	sm := mux.NewRouter()

	postR := sm.Methods(http.MethodPost).Subrouter()

	mailR := sm.PathPrefix("/verify").Methods(http.MethodPost).Subrouter()
	mailR.HandleFunc("/mail", uh.VerifyMail)
	mailR.HandleFunc("/password-reset", uh.VerifyPasswordReset)
	mailR.Use(uh.MiddlewareValidateVerificationData)

	postR.HandleFunc("/signup", uh.Signup)
	postR.HandleFunc("/login", uh.Login)
	postR.Use(uh.MiddlewareValidateUser)

	refToken := sm.PathPrefix("/refresh-token").Subrouter()
	refToken.HandleFunc("", uh.RefreshToken)
	refToken.Use(uh.MiddlewareValidateRefreshToken)

	getR := sm.Methods(http.MethodGet).Subrouter()
	getR.HandleFunc("/greet", uh.Greet)
	getR.HandleFunc("/get-password-reset-code", uh.GeneratePassResetCode)
	getR.Use(uh.MiddlewareValidateAccessToken)

	putR := sm.Methods(http.MethodPut).Subrouter()
	putR.HandleFunc("/update-username", uh.UpdateUsername)
	putR.HandleFunc("/reset-password", uh.ResetPassword)
	putR.Use(uh.MiddlewareValidateAccessToken)

	svr := http.Server{
		Addr:         configs.ServerAddress,
		Handler:      sm,
		ErrorLog:     logger.StandardLogger(&hclog.StandardLoggerOptions{}),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		logger.Info("starting the server at port", configs.ServerAddress)

		err := svr.ListenAndServe()
		if err != nil {
			logger.Error("could not start the server", "error", err)
			os.Exit(1)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, os.Kill)

	sig := <-c
	logger.Info("shutting down the server", "received signal", sig)

	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	svr.Shutdown(ctx)
}
