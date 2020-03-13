/**
 *    Copyright 2018 Amazon.com, Inc. or its affiliates
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

const (
	clientID            string = "<CLIENT_ID>"
	ownerID             string = "<EXTENSION_OWNER_ID>"
	authHeaderName      string = "Authorization"
	authHeaderPrefix    string = "Bearer "
	authHeaderPrefixLen int    = len(authHeaderPrefix)
	minLegalTokenLength int    = authHeaderPrefixLen + 5 // a.b.c for a jwt
)

type contextKeyType string

type service struct {
	parser    jwt.Parser
	secret    []byte
	nextPongs map[string]time.Time
	mutex     sync.Mutex
}

func main() {
	encodedSecret := flag.String("secret", "", "Extension secret used to validate and sign JWTs")
	flag.Parse()

	if encodedSecret == nil || *encodedSecret == "" {
		flag.Usage()
		return
	}

	secret, err := base64.StdEncoding.DecodeString(*encodedSecret)
	if err != nil {
		log.Fatalf("Could not parse secret: %v", err)
	}

	var s = newService(secret)
	var r = mux.NewRouter()
	r.HandleFunc("/api/ping", s.pingHandler).Methods("GET")
	r.Use(s.verifyJWT)

	log.Println("Starting server on https://localhost:8081/")
	log.Fatal(http.ListenAndServeTLS(":8081", "cert.pem", "key.pem", handlers.CORS(handlers.AllowedHeaders([]string{authHeaderName}))(r)))
}

// newService creates an instance of our service data that stores the secret and JWT parser
func newService(secret []byte) *service {
	return &service{
		parser:    jwt.Parser{ValidMethods: []string{"HS256"}},
		secret:    secret,
		nextPongs: make(map[string]time.Time),
	}
}

// pingHandler sends a "pong" message via PubSub to the channel specified in the incoming request's JWT
func (s *service) pingHandler(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	if claims.ChannelID != "" {
		log.Printf("Received ping\n")
		s.send(claims.ChannelID, "pong")
		w.Write([]byte(http.StatusText(http.StatusOK)))
		w.WriteHeader(http.StatusOK)
	} else {
		log.Println("Channel ID is missing in the request context")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}
}

func (s *service) getKey(*jwt.Token) (interface{}, error) {
	return s.secret, nil
}

// verifyJWT is middleware that confirms the validity of incoming requests
func (s *service) verifyJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string

		tokens, ok := r.Header[authHeaderName]
		if !ok {
			log.Println("Missing authorization header")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if len(tokens) != 1 {
			log.Println("Multiple authorization headers found")
			http.Error(w, "Multiple authorization headers found; only one header should be sent", http.StatusUnauthorized)
			return
		}

		token = tokens[0]
		if !strings.HasPrefix(token, authHeaderPrefix) || len(token) < minLegalTokenLength {
			log.Println("Malformed authorization header")
			http.Error(w, "Malformed authorization header", http.StatusUnauthorized)
			return
		}
		token = token[authHeaderPrefixLen:]

		parsedToken, err := s.parser.ParseWithClaims(token, &jwtClaims{}, s.getKey)

		if err != nil {
			log.Println(err)
			http.Error(w, "Could not parse authorization header", http.StatusUnauthorized)
			return
		}

		if claims, ok := parsedToken.Claims.(*jwtClaims); ok && parsedToken.Valid {
			next.ServeHTTP(w, setClaims(r, claims))
		} else {
			log.Println("Could not parse JWT claims")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
	})
}

// newJWT creates an EBS-signed JWT
func (s *service) newJWT(channelID string) string {
	var expiration = time.Now().Add(time.Minute * 3).Unix()

	claims := jwtClaims{
		UserID:    ownerID,
		ChannelID: channelID,
		Role:      "external",
		Permissions: jwtPermissions{
			Send: []string{"broadcast"},
		},
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Generated JWT: %s\n", tokenString)

	return tokenString
}

// check for PubSub cooldown on a channelID
func (s *service) inCooldown(channelID string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if next, found := s.nextPongs[channelID]; found && next.After(time.Now()) {
		return true
	}

	s.nextPongs[channelID] = time.Now().Add(time.Second)
	return false
}

// send extension PubSub message
func (s *service) send(channelID, message string) {
	if s.inCooldown(channelID) { // don't spam PubSub or you'll be rate limited
		return
	}

	data := struct {
		ContentType string   `json:"content_type"`
		Targets     []string `json:"targets"`
		Message     string   `json:"message"`
	}{
		"application/json",
		[]string{"broadcast"},
		message,
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(data)

	req, err := http.NewRequest("POST", fmt.Sprintf("https://api.twitch.tv/extensions/message/%v", channelID), b)
	if err != nil {
		log.Println(err)
	}

	req.Header.Set("Client-Id", clientID)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(authHeaderName, fmt.Sprintf("%s%v", authHeaderPrefix, s.newJWT(channelID)))

	log.Printf("Sending pong via PubSub for channel %s\n", channelID)
	res, err := http.DefaultClient.Do(req)
	if res != nil {
		defer res.Body.Close()
	}

	if err != nil {
		log.Println(err)
	}
}
