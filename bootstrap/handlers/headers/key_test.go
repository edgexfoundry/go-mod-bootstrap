//
// Copyright (C) 2025 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package headers

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger/mocks"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestGetVerificationKey(t *testing.T) {
	dic := mockDic()

	expectedKeyBytes, err := base64.StdEncoding.DecodeString(mockVerifyKey)
	require.NoError(t, err)

	tests := []struct {
		name           string
		issuer         string
		keyInCache     bool
		expectedKey    any
		expectedError  bool
		expectedErrMsg string
	}{
		{"Key in Cache", "cachedIssuer", true, []byte(mockVerifyKey), false, ""},
		{"Key not in Cache", issuer, false, expectedKeyBytes, false, ""},
		{"Key not found", notFoundIssuer, false, expectedKeyBytes, true, fmt.Sprintf("verification key not found from proxy-auth service for JWT issuer '%s'", notFoundIssuer)},
		{"Key processed error", failedIssuer, false, expectedKeyBytes, true, fmt.Sprintf("failed to obtain the verification key from proxy-auth service for JWT issuer '%s'", failedIssuer)},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			keysCache = make(map[string]any)

			if testCase.keyInCache {
				keysCache[testCase.issuer] = []byte(mockVerifyKey)
			}

			key, err := GetVerificationKey(dic, testCase.issuer, "HS256", context.Background())
			if testCase.expectedError {
				require.Error(t, err)
				require.Equal(t, testCase.expectedErrMsg, err.Message())
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.expectedKey, key)
			}
		})
	}
}

func TestProcessVerificationKey(t *testing.T) {
	mockLogger := mocks.NewLoggingClient(t)
	mockKey := "testKey"

	edDSAKey := "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAeDQLRoLzKZkHvXgU5nKiT2fp0zHt5nmY8YZykC1g+zE=\n-----END PUBLIC KEY-----"
	block, _ := pem.Decode([]byte(edDSAKey))
	edDSAKeyBytes := block.Bytes

	invalidEdDSAKey := "-----BEGIN PUBLIC KEY-----\nINVALIDDATA\n-----END PUBLIC KEY-----"

	tests := []struct {
		name            string
		keyString       string
		alg             string
		expectedKey     any
		errorExpected   bool
		expectedErrKind errors.ErrKind
	}{
		{"Valid - HS256 alg", base64.StdEncoding.EncodeToString([]byte(mockKey)), jwt.SigningMethodHS256.Alg(), []byte(mockKey), false, ""},
		{"Valid - EdDSA alg", edDSAKey, jwt.SigningMethodEdDSA.Alg(), ed25519.PublicKey(edDSAKeyBytes), false, ""},
		{"Invalid - invalid EdDSA PEM Block", invalidEdDSAKey, jwt.SigningMethodEdDSA.Alg(), nil, true, errors.KindServerError},
		{"Invalid - unsupported signing algorithm", "anyKey", "UNSUPPORTED", nil, true, errors.KindContractInvalid},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := ProcessVerificationKey(test.keyString, test.alg, mockLogger)
			if test.errorExpected {
				require.Equal(t, test.expectedErrKind, errors.Kind(err))
			} else {
				require.Equal(t, test.expectedKey, key)
			}
		})
	}
}
