package main

import (
	"context"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

const jwtClaimsKey contextKeyType = "jwtClaims"

type jwtClaims struct {
	OpaqueUserID string         `json:"opaque_user_id,omitempty"`
	UserID       string         `json:"user_id"`
	ChannelID    string         `json:"channel_id,omitempty"`
	Role         string         `json:"role"`
	Permissions  jwtPermissions `json:"pubsub_perms"`
	jwt.StandardClaims
}

type jwtPermissions struct {
	Send   []string `json:"send,omitempty"`
	Listen []string `json:"listen,omitempty"`
}

func setClaims(r *http.Request, claims *jwtClaims) *http.Request {
	ctx := context.WithValue(r.Context(), jwtClaimsKey, claims)
	return r.WithContext(ctx)
}

func getClaims(r *http.Request) *jwtClaims {
	if claims, ok := r.Context().Value(jwtClaimsKey).(*jwtClaims); ok {
		return claims
	}
	return &jwtClaims{} // empty default
}
