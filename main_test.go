package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func GetTestHandler() http.HandlerFunc {
	f := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(http.StatusText(http.StatusOK)))
	}
	return http.HandlerFunc(f)
}

func TestVerifyJWT(t *testing.T) {
	var s = newService([]byte("secret"))

	assert := assert.New(t)

	tests := []struct {
		authHeader   string
		expectedBody string
		expectedCode int
	}{
		{
			authHeader:   "Barer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzUxNDU3NjAsIm9wYXF1ZV91c2VyX2lkIjoiVVJJR1VjNTRrb2M0R2lodnJTYyIsInJvbGUiOiJicm9hZGNhc3RlciIsInB1YnN1Yl9wZXJtcyI6eyJsaXN0ZW4iOlsiYnJvYWRjYXN0IiwiZ2xvYmFsIl0sInNlbmQiOlsiYnJvYWRjYXN0Il19LCJjaGFubmVsX2lkIjoiMjY1NzM3OTMyIiwidXNlcl9pZCI6IjEyMzQ1Njc4OSIsImlhdCI6MTU0MzYwOTc2MH0.P5nAfTRGVbUaHMuIooJYiskq3HYRFigDnu9S0WbwSLU",
			expectedBody: "Malformed authorization header\n",
		},
		{
			authHeader:   "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzUxNDU3NjAsIm9wYXF1ZV91c2VyX2lkIjoiVVJJR1VjNTRrb2M0R2lodnJTYyIsInJvbGUiOiJicm9hZGNhc3RlciIsInB1YnN1Yl9wZXJtcyI6eyJsaXN0ZW4iOlsiYnJvYWRjYXN0IiwiZ2xvYmFsIl0sInNlbmQiOlsiYnJvYWRjYXN0Il19LCJjaGFubmVsX2lkIjoiMjY1NzM3OTMyIiwidXNlcl9pZCI6IjEyMzQ1Njc4OSIsImlhdCI6MTU0MzYwOTc2MH0.FR_LYxAwSl7H4mLAz6UaTeRurEKFBPU5MDhZOMoLQhs",
			expectedBody: "Could not parse authorization header\n",
		},
		{
			authHeader:   "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzUxNDU3NjAsIm9wYXF1ZV91c2VyX2lkIjoiVVJJR1VjNTRrb2M0R2lodnJTYyIsInJvbGUiOiJicm9hZGNhc3RlciIsInB1YnN1Yl9wZXJtcyI6eyJsaXN0ZW4iOlsiYnJvYWRjYXN0IiwiZ2xvYmFsIl0sInNlbmQiOlsiYnJvYWRjYXN0Il19LCJjaGFubmVsX2lkIjoiMjY1NzM3OTMyIiwidXNlcl9pZCI6IjEyMzQ1Njc4OSIsImlhdCI6MTU0MzYwOTc2MH0.P5nAfTRGVbUaHMuIooJYiskq3HYRFigDnu9S0WbwSLU",
			expectedBody: "OK",
		},
	}

	ts := httptest.NewServer(s.verifyJWT(GetTestHandler()))
	defer ts.Close()

	for _, tc := range tests {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%v/api/ping", ts.URL), nil)
		req.Header.Set("Authorization", tc.authHeader)
		res, err := http.DefaultClient.Do(req)

		assert.NoError(err)
		if res != nil {
			defer res.Body.Close()
		}

		body, err := ioutil.ReadAll(res.Body)
		assert.NoError(err)

		assert.Equal(tc.expectedBody, string(body))
	}
}
func TestNewJWT(t *testing.T) {
	var s = newService([]byte("secret"))

	assert := assert.New(t)

	token := s.newJWT("123456789")

	parsedToken, err := s.parser.ParseWithClaims(token, &jwtClaims{}, s.getKey)
	assert.NoError(err)

	claims := parsedToken.Claims.(*jwtClaims)
	assert.Equal(ownerID, claims.UserID)
	assert.Equal("123456789", claims.ChannelID)
	assert.Equal("external", claims.Role)
	assert.Equal([]string{"broadcast"}, claims.Permissions.Send)
}
