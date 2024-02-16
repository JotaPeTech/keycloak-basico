package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	clientID     = "" // incluir client id
	clientSecret = "" // incluir secret
)

func main() {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "http://localhost:8080/auth/realms/demo")

	if err != nil {
		log.Fatal(err)
	}

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:8081/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "roles"},
	}

	state := "securityPhrase"

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}
		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "failed to exchange token", http.StatusBadRequest)
			return
		}

		rawIdToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no id token", http.StatusBadRequest)
			return
		}

		resp :=
			struct {
				Oauth2Token *oauth2.Token
				RawIdToken  string
			}{
				oauth2Token,
				rawIdToken,
			}

		data, _ := json.MarshalIndent(resp, "", "	")
		w.Write(data)
	})

	log.Fatal(http.ListenAndServe(":8081", nil))
}
