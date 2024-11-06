/*******************************************************************************
 * Copyright 2020-2023 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/

package secret

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/environment"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/config"
	mock2 "github.com/stretchr/testify/mock"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"

	"github.com/edgexfoundry/go-mod-secrets/v4/pkg"
	mocks2 "github.com/edgexfoundry/go-mod-secrets/v4/pkg/token/authtokenloader/mocks"
	runtimeTokenMock "github.com/edgexfoundry/go-mod-secrets/v4/pkg/token/runtimetokenprovider/mocks"
	"github.com/edgexfoundry/go-mod-secrets/v4/secrets"
	"github.com/edgexfoundry/go-mod-secrets/v4/secrets/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureProvider_GetSecrets(t *testing.T) {
	expected := map[string]string{"username": "admin", "password": "sam123!"}

	mock := &mocks.SecretClient{}
	mock.On("GetSecret", "redis", "username", "password").Return(expected, nil)
	mock.On("GetSecret", "redis").Return(expected, nil)
	notfound := []string{"username", "password"}
	mock.On("GetSecret", "missing", "username", "password").Return(nil, pkg.NewErrSecretsNotFound(notfound))

	tests := []struct {
		Name        string
		Path        string
		Keys        []string
		Config      TestConfig
		Client      secrets.SecretClient
		ExpectError bool
	}{
		{"Valid Secure", "redis", []string{"username", "password"}, TestConfig{}, mock, false},
		{"Invalid Secure", "missing", []string{"username", "password"}, TestConfig{}, mock, true},
		{"Invalid No Client", "redis", []string{"username", "password"}, TestConfig{}, nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {

			target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.MockLogger{}, nil, nil, "testService")
			target.SetClient(tc.Client)
			actual, err := target.GetSecret(tc.Path, tc.Keys...)
			if tc.ExpectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, expected, actual)
		})
	}
}

func TestSecureProvider_GetSecrets_Cached(t *testing.T) {
	expected := map[string]string{"username": "admin", "password": "sam123!"}

	mock := &mocks.SecretClient{}
	// Use the Once method so GetSecret can be changed below
	mock.On("GetSecret", "redis", "username", "password").Return(expected, nil).Once()

	target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.MockLogger{}, nil, nil, "testService")
	target.SetClient(mock)

	actual, err := target.GetSecret("redis", "username", "password")
	require.NoError(t, err)
	assert.Equal(t, expected, actual)

	// Now have mock return error if it is called which should not happen of secrets are cached
	mock.On("GetSecret", "redis", "username", "password").Return(nil, errors.New("no Cached"))
	actual, err = target.GetSecret("redis", "username", "password")
	require.NoError(t, err)
	assert.Equal(t, expected, actual)

	// Now check for error when not all requested keys not in cache.
	mock.On("GetSecret", "redis", "username", "password2").Return(nil, errors.New("no Cached"))
	_, err = target.GetSecret("redis", "username", "password2")
	require.Error(t, err)
}

func TestSecureProvider_GetSecrets_Cached_Invalidated(t *testing.T) {
	expected := map[string]string{"username": "admin", "password": "sam123!"}

	mock := &mocks.SecretClient{}
	// Use the Once method so GetSecret can be changed below
	mock.On("GetSecret", "redis", "username", "password").Return(expected, nil).Once()
	mock.On("StoreSecret", "redis", expected).Return(nil)

	target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.MockLogger{}, nil, nil, "testService")
	target.SetClient(mock)

	actual, err := target.GetSecret("redis", "username", "password")
	require.NoError(t, err)
	assert.Equal(t, expected, actual)

	// Invalidate the secrets cache by storing new secrets
	err = target.StoreSecret("redis", expected)
	require.NoError(t, err)

	// Now have mock return error is it is called which should now happen if the cache was properly invalidated by the above call to StoreSecret
	mock.On("GetSecret", "redis", "username", "password").Return(nil, errors.New("no Cached"))
	_, err = target.GetSecret("redis", "username", "password")
	require.Error(t, err)
}

func TestSecureProvider_StoreSecrets_Secure(t *testing.T) {
	input := map[string]string{"username": "admin", "password": "sam123!"}
	mock := &mocks.SecretClient{}
	mock.On("StoreSecret", "redis", input).Return(nil)
	mock.On("StoreSecret", "error", input).Return(errors.New("some error happened"))

	tests := []struct {
		Name        string
		Secure      string
		Path        string
		Client      secrets.SecretClient
		ExpectError bool
	}{
		{"Valid Secure", "true", "redis", mock, false},
		{"Invalid no client", "true", "redis", nil, true},
		{"Invalid internal error", "true", "error", mock, true},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.MockLogger{}, nil, nil, "testService")
			target.SetClient(tc.Client)

			err := target.StoreSecret(tc.Path, input)
			if tc.ExpectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestSecureProvider_SecretsLastUpdated(t *testing.T) {
	input := map[string]string{"username": "admin", "password": "sam123!"}
	mock := &mocks.SecretClient{}
	mock.On("StoreSecret", "redis", input).Return(nil)

	target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.MockLogger{}, nil, nil, "testService")
	target.SetClient(mock)

	previous := target.SecretsLastUpdated()
	time.Sleep(1 * time.Second)
	err := target.StoreSecret("redis", input)
	require.NoError(t, err)
	current := target.SecretsLastUpdated()
	assert.True(t, current.After(previous))
}

func TestSecureProvider_SecretsUpdated(t *testing.T) {
	target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.MockLogger{}, nil, nil, "testService")
	previous := target.SecretsLastUpdated()
	time.Sleep(1 * time.Second)
	target.SecretsUpdated()
	current := target.SecretsLastUpdated()
	// Since the SecureProvider does nothing for SecretsUpdated, LastUpdated shouldn't change
	assert.Equal(t, previous, current)
}

func TestSecureProvider_DefaultTokenExpiredCallback(t *testing.T) {
	goodTokenFile := "good-token.json"
	//nolint: gosec
	badTokenFile := "bad-token.json"
	sameTokenFile := "same-token.json"
	newToken := "new token"
	expiredToken := "expired token"

	mockTokenLoader := &mocks2.AuthTokenLoader{}
	mockTokenLoader.On("Load", goodTokenFile).Return(newToken, nil)
	mockTokenLoader.On("Load", sameTokenFile).Return(expiredToken, nil)
	mockTokenLoader.On("Load", badTokenFile).Return("", errors.New("not found"))

	tests := []struct {
		Name          string
		TokenFile     string
		ExpiredToken  string
		ExpectedToken string
		ExpectedRetry bool
	}{
		{"Valid", goodTokenFile, expiredToken, "new token", true},
		{"Bad File", badTokenFile, "", "", false},
		{"Same Token", sameTokenFile, expiredToken, expiredToken, false},
	}

	lc := logger.NewMockClient()
	envVars := environment.NewVariables(lc)
	secretStore, err := BuildSecretStoreConfig("unit-test", envVars, lc)
	require.NoError(t, err)

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			secretStore.TokenFile = tc.TokenFile
			target := NewSecureProvider(context.Background(), secretStore, lc, mockTokenLoader, nil, "testService")
			actualToken, actualRetry := target.DefaultTokenExpiredCallback(tc.ExpiredToken)
			assert.Equal(t, tc.ExpectedToken, actualToken)
			assert.Equal(t, tc.ExpectedRetry, actualRetry)
		})
	}
}

func TestSecureProvider_RuntimeTokenExpiredCallback(t *testing.T) {
	newToken := "new token"
	expiredToken := "expired token"
	okService := "testOkService"
	badService := "badService"

	mockRuntimeTokenProvider := &runtimeTokenMock.RuntimeTokenProvider{}
	mockRuntimeTokenProvider.On("GetRawToken", okService).Return(newToken, nil)
	mockRuntimeTokenProvider.On("GetRawToken", badService).Return("", errors.New("invalid service"))

	tests := []struct {
		Name          string
		TestService   string
		ExpiredToken  string
		ExpectedToken string
		ExpectedRetry bool
	}{
		{"Get token ok", okService, expiredToken, "new token", true},
		{"Get token failed", badService, "", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.MockLogger{}, nil, mockRuntimeTokenProvider, tc.TestService)
			actualToken, actualRetry := target.RuntimeTokenExpiredCallback(tc.ExpiredToken)
			assert.Equal(t, tc.ExpectedToken, actualToken)
			assert.Equal(t, tc.ExpectedRetry, actualRetry)
		})
	}
}

func TestSecureProvider_seedSecrets(t *testing.T) {
	allGood := `{"secrets": [{"secretName": "auth","imported": false,"secretData": [{"key": "user1","value": "password1"}]}]}`
	allGoodExpected := `{"secrets":[{"secretName":"auth","imported":true,"secretData":[]}]}`
	badJson := `{"secrets": [{"secretName": "","imported": false,"secretData": null}]}`

	tests := []struct {
		name          string
		secretsJson   string
		expectedJson  string
		mockError     bool
		expectedError string
	}{
		{"Valid", allGood, allGoodExpected, false, ""},
		{"Partial Valid", allGood, allGoodExpected, false, ""},
		{"Bad JSON", badJson, "", false, "seeding secrets failed unmarshaling JSON: ServiceSecrets.Secrets[0].SecretName field should not be empty string; ServiceSecrets.Secrets[0].SecretData field is required"},
		{"Store Error", allGood, "", true, "1 error occurred:\n\t* failed to store secret for 'auth': store failed\n\n"},
	}

	target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.MockLogger{}, nil, nil, "testService")

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			mock := &mocks.SecretClient{}

			if test.mockError {
				mock.On("StoreSecret", mock2.Anything, mock2.Anything).Return(errors.New("store failed")).Once()
			} else {
				mock.On("StoreSecret", mock2.Anything, mock2.Anything).Return(nil).Once()
			}

			target.SetClient(mock)

			actual, err := target.seedSecrets([]byte(test.secretsJson))
			if len(test.expectedError) > 0 {
				require.Error(t, err)
				assert.EqualError(t, err, test.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.expectedJson, string(actual))
		})
	}
}

func TestSecureProvider_HasSecrets(t *testing.T) {
	expected := map[string]string{"username": "admin", "password": "sam123!"}

	mock := &mocks.SecretClient{}
	errorMessage := "Received a '404' response from the secret store"
	mock.On("GetSecret", "redis", "username", "password").Return(expected, nil)
	mock.On("GetSecret", "redis").Return(expected, nil)
	mock.On("GetSecret", "missing").Return(nil, pkg.NewErrSecretNameNotFound(errorMessage))
	mock.On("GetSecret", "error").Return(nil, errors.New("no key"))

	tests := []struct {
		Name         string
		Path         string
		Client       secrets.SecretClient
		ExpectError  bool
		ExpectResult bool
	}{
		{"Valid - found", "redis", mock, false, true},
		{"Valid - not found", "missing", mock, false, false},
		{"Invalid No Client", "redis", nil, true, false},
		{"Invalid Error", "error", mock, true, false},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.MockLogger{}, nil, nil, "testService")
			target.SetClient(tc.Client)
			actual, err := target.HasSecret(tc.Path)

			if tc.ExpectError {
				require.Error(t, err)
				return
			}

			assert.Equal(t, tc.ExpectResult, actual)
			require.NoError(t, err)
		})
	}
}

func TestSecureProvider_ListSecretPathsSecrets(t *testing.T) {
	expectedKeys := []string{"username", "password", "config"}
	mock := &mocks.SecretClient{}
	mock.On("GetSecretNames").Return(expectedKeys, nil)

	tests := []struct {
		Name        string
		Config      TestConfig
		Client      secrets.SecretClient
		ExpectError bool
	}{
		{"Valid Secure", TestConfig{}, mock, false},
		{"Invalid No Client", TestConfig{}, nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.MockLogger{}, nil, nil, "testService")
			target.SetClient(tc.Client)
			actual, err := target.ListSecretNames()
			if tc.ExpectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, expectedKeys, actual)
		})
	}
}

func TestSecureProvider_SecretUpdatedAtPath(t *testing.T) {
	callbackCalled := false
	callback := func(secretName string) {
		callbackCalled = true
	}

	wildcardCalled := false
	wildcard := func(secretName string) {
		wildcardCalled = true
	}

	tests := []struct {
		Name             string
		Config           TestConfig
		SecretName       string
		Callback         func(secretName string)
		WildcardCallback func(secretName string)
	}{
		{"Valid With Callback", TestConfig{}, expectedSecretName, callback, nil},
		{"Valid No Callbacks", TestConfig{}, expectedSecretName, nil, nil},
		{"Valid Wildcard Only", TestConfig{}, expectedSecretName, nil, wildcard},
		{"Valid With Callback and Wildcard", TestConfig{}, expectedSecretName, callback, wildcard},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			callbackCalled = false
			wildcardCalled = false
			target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.NewMockClient(), nil, nil, "testService")

			if tc.Callback != nil {
				target.registeredSecretCallbacks[tc.SecretName] = tc.Callback
			}
			if tc.WildcardCallback != nil {
				target.registeredSecretCallbacks[WildcardName] = tc.WildcardCallback
			}

			target.SecretUpdatedAtSecretName(tc.SecretName)
			assert.Equal(t, tc.Callback != nil, callbackCalled)
			assert.Equal(t, tc.WildcardCallback != nil && tc.Callback == nil, wildcardCalled)
		})
	}
}

func TestSecureProvider_RegisterSecretUpdatedCallback(t *testing.T) {
	tests := []struct {
		Name     string
		Config   TestConfig
		Path     string
		Callback func(secretName string)
	}{
		{"Valid Secure", TestConfig{}, expectedSecretName, func(secretName string) {}},
		{"Valid No Callbacks", TestConfig{}, expectedSecretName, nil},
		{"Valid Wildcard", TestConfig{}, WildcardName, func(secretName string) {}},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.NewMockClient(), nil, nil, "testService")
			err := target.RegisterSecretUpdatedCallback(tc.Path, tc.Callback)
			assert.NoError(t, err)

			if tc.Callback != nil {
				assert.NotEmpty(t, target.registeredSecretCallbacks[tc.Path])
			} else {
				assert.Nil(t, target.registeredSecretCallbacks[tc.Path])
			}
		})
	}
}

func TestSecureProvider_DeregisterSecretUpdatedCallback(t *testing.T) {
	tests := []struct {
		Name     string
		Config   TestConfig
		Path     string
		Callback func(secretName string)
	}{
		{"Valid Secure", TestConfig{}, expectedSecretName, func(secretName string) {}},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.NewMockClient(), nil, nil, "testService")

			// Register a callback.
			err := target.RegisterSecretUpdatedCallback(tc.Path, tc.Callback)
			assert.NoError(t, err)

			// Deregister a callback.
			target.DeregisterSecretUpdatedCallback(tc.Path)
			assert.Empty(t, target.registeredSecretCallbacks)
		})
	}
}

func secretStoreConfig(t *testing.T) *config.SecretStoreInfo {
	lc := logger.NewMockClient()
	envVars := environment.NewVariables(lc)
	config, err := BuildSecretStoreConfig("unit-test", envVars, lc)
	require.NoError(t, err)
	return config
}

func TestSecureProvider_GetSelfJWT(t *testing.T) {
	appServiceKey := "app-test"
	serviceKey := "testService"
	sampleJWT := "eyJhbGciOiJFUzM4NCIsImtpZCI6IjE3NzdiMGNmLWEzMmMtYTc2YS05ZTI4LTZiMjcyYzYwYmYyMCJ9.eyJhdWQiOiJGN0Z3VXBjNnV6dDc0Y1JSRkZ2bXRLSWg1RyIsImVkZ2V4LXNlcnZpY2UiOiJjb3JlLWRhdGEiLCJleHAiOjE2NzAwNDIwMTUsImlhdCI6MTY3MDA0MTExNSwiaXNzIjoiL3YxL2lkZW50aXR5L29pZGMiLCJuYW1lc3BhY2UiOiJyb290Iiwic3ViIjoiM2ZhYzcwNmEtMmM4ZS01Yjc4LTI5N2EtOGU4NmIwMmJmZjg1In0.wos1twPPMEDUvNhTJIFe8dX6BmTzh3CutNjaW5PUrWG7KtsNexETRSxL2oIN0kJYomBT6RaHX6NtkOkO4Wf6J_hcSknQ64lVw4gwSCEoX2d_mlcKJArLx9skngF-W2VC"

	tests := []struct {
		Name                   string
		ServiceKey             string
		OverwriteAppServiceKey bool
	}{
		{"Valid - app service with app service key overwrite", appServiceKey, true},
		{"Valid - app service", appServiceKey, false},
		{"Valid - other service", serviceKey, false},
	}
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			mock := &mocks.SecretClient{}
			if tc.OverwriteAppServiceKey {
				_ = os.Setenv(EnvEdgeXUseCommonAppServiceSecretKey, "true")
				mock.On("GetSelfJWT", config.ServiceTypeApp).Return(sampleJWT, nil)
			} else {
				_ = os.Unsetenv(EnvEdgeXUseCommonAppServiceSecretKey)
				mock.On("GetSelfJWT", tc.ServiceKey).Return(sampleJWT, nil)
			}
			target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.MockLogger{}, nil, nil, tc.ServiceKey)
			target.SetClient(mock)

			actualToken, err := target.GetSelfJWT()
			require.NoError(t, err)
			require.Equal(t, sampleJWT, actualToken)
		})
	}
}

func TestSecureProvider_IsJWTValidTrue(t *testing.T) {
	nullJWT := "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.e30."
	mock := &mocks.SecretClient{}
	mock.On("IsJWTValid", nullJWT).Return(true, nil)

	target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.MockLogger{}, nil, nil, "testService")
	target.SetClient(mock)

	result, err := target.IsJWTValid(nullJWT)
	require.NoError(t, err)
	require.Equal(t, true, result)
}

func TestSecureProvider_IsJWTValidFalse(t *testing.T) {
	nullJWT := "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.e30."
	mock := &mocks.SecretClient{}
	mock.On("IsJWTValid", nullJWT).Return(false, nil)

	target := NewSecureProvider(context.Background(), secretStoreConfig(t), logger.MockLogger{}, nil, nil, "testService")
	target.SetClient(mock)

	result, err := target.IsJWTValid(nullJWT)
	require.NoError(t, err)
	require.Equal(t, false, result)
}
