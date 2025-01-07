//
// Copyright (C) 2025 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package headers

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/di"
	mockClients "github.com/edgexfoundry/go-mod-core-contracts/v4/clients/interfaces/mocks"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/dtos"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/dtos/responses"
	edgexErr "github.com/edgexfoundry/go-mod-core-contracts/v4/errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

var (
	issuer             = "testIssuer"
	mockVerifyKey      = "mysecret"
	mockIncorrectKey   = "notmysecret"
	incorrectKeyIssuer = "incorrectKey"
	failedIssuer       = "failedIssuer"
	notFoundIssuer     = "notFoundIssuer"
)

func mockDic() *di.Container {
	acMock := &mockClients.AuthClient{}

	acMock.On("VerificationKeyByIssuer", context.Background(), issuer).
		Return(responses.NewKeyDataResponse("", "", http.StatusOK, dtos.KeyData{
			Issuer: issuer,
			Type:   "verification",
			Key:    mockVerifyKey,
		}), nil)
	acMock.On("VerificationKeyByIssuer", context.Background(), incorrectKeyIssuer).
		Return(responses.NewKeyDataResponse("", "", http.StatusOK, dtos.KeyData{
			Issuer: issuer,
			Type:   "verification",
			Key:    mockIncorrectKey,
		}), nil)
	acMock.On("VerificationKeyByIssuer", context.Background(), failedIssuer).
		Return(responses.KeyDataResponse{}, edgexErr.NewCommonEdgeX(edgexErr.KindServerError, "internal error", nil))
	acMock.On("VerificationKeyByIssuer", context.Background(), notFoundIssuer).
		Return(responses.KeyDataResponse{}, edgexErr.NewCommonEdgeX(edgexErr.KindEntityDoesNotExist, "verification key not found", nil))

	return di.NewContainer(di.ServiceConstructorMap{
		container.SecurityProxyAuthClientName: func(get di.Get) interface{} {
			return acMock
		},
		container.LoggingClientInterfaceName: func(get di.Get) interface{} {
			return logger.NewMockClient()
		},
	})
}

func TestVerifyJWT(t *testing.T) {
	dic := mockDic()

	alg := "HS256"

	validJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJleHAiOjE5MjQ0MDU3OTYsImlzcyI6IklPVGVjaFN5c3RlbSJ9.iM2f5eXTBdV3HEdfp5xVIsuo2mlsdOrC-EY0kvBTgg4"
	noIssuer := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJleHAiOjE5MjQ0MDU3OTZ9.OvQ2Ot2q8XpIaK9-hoStMVGdY8zW7fk62-FruNKQLhI"
	noExp := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJJT1RlY2hTeXN0ZW0ifQ.Ead-LdhSPISMhVADR6Dq5qv88QAC0RG-Fc7CGVbuo7k"
	expiredJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJJT1RlY2hTeXN0ZW0iLCJleHAiOjE3MDM0ODA5OTZ9.X14GAFL5-6z8qh3mo49h8OgANkE9JBSiltxxc5j_n40"
	invalidJWT := "invalid"
	invalidSignature := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpbmNvcnJlY3RLZXkiLCJleHAiOjE5MjQ0MDU3OTZ9.cczSNpaHtEgCP1_BTcs0A99UQReQCJgzA0Lld5FJt5w"

	tests := []struct {
		name          string
		token         string
		issuer        string
		errorExpected bool
		errType       edgexErr.ErrKind
	}{
		{"Valid JWT", validJWT, issuer, false, ""},
		{"Valid JWT - expired", expiredJWT, issuer, false, ""},
		{"Invalid JWT - no issuer", noIssuer, issuer, true, edgexErr.KindUnauthorized},
		{"Invalid JWT - no exp", noExp, issuer, true, edgexErr.KindUnauthorized},
		{"Invalid JWT - malformed", invalidJWT, issuer, true, edgexErr.KindUnauthorized},
		{"Invalid JWT - invalid signature", invalidSignature, incorrectKeyIssuer, true, edgexErr.KindUnauthorized},
		{"Invalid JWT - invalid signature", "", failedIssuer, true, edgexErr.KindServerError},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			err := VerifyJWT(testCase.token, testCase.issuer, alg, dic, ctx)
			if testCase.errorExpected {
				require.Error(t, err)
				require.Equal(t, testCase.errType, edgexErr.Kind(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseJWT(t *testing.T) {
	keyBytes, err := base64.StdEncoding.DecodeString(mockVerifyKey)
	require.NoError(t, err)

	jwtWithNoExp := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJJT1RlY2hTeXN0ZW0ifQ.Ead-LdhSPISMhVADR6Dq5qv88QAC0RG-Fc7CGVbuo7k"
	jwtWithExp := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5MjQ0MDU3OTYsImlzcyI6IklPVGVjaFN5c3RlbSJ9.lbVl9cRRcXx7tLhbJU_wGyHB-Qj_h4VOjs-t3MjRIQ4"
	jwtWithNoIssuer := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5MjQ0MDU3OTZ9.JexgnJ50U_DT6gZwYQ-RHZu864wH0ilkwaABC0y_GIo"

	tests := []struct {
		name          string
		token         string
		verifyKey     any
		parserOpts    []jwt.ParserOption
		errorExpected bool
	}{
		{"Valid JWT", jwtWithNoExp, keyBytes, nil, false},
		{"Valid JWT - with exp", jwtWithExp, keyBytes, []jwt.ParserOption{jwt.WithExpirationRequired()}, false},
		{"Invalid JWT - no exp", jwtWithNoExp, keyBytes, []jwt.ParserOption{jwt.WithExpirationRequired()}, true},
		{"Invalid JWT - no issuer", jwtWithNoIssuer, keyBytes, []jwt.ParserOption{jwt.WithExpirationRequired()}, true},
		{"Invalid JWT - invalid signature", jwtWithNoExp, []byte(mockIncorrectKey), nil, true},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			mockClaims := &jwt.MapClaims{}
			parseErr := ParseJWT(testCase.token, testCase.verifyKey, mockClaims, testCase.parserOpts...)
			if testCase.errorExpected {
				require.Error(t, parseErr)
			} else {
				require.NoError(t, parseErr)
			}
		})

	}
}
