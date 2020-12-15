/*******************************************************************************
 * Copyright 2020 Intel Inc.
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
	"errors"
	"testing"
	"time"

	bootstrapConfig "github.com/edgexfoundry/go-mod-bootstrap/config"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"github.com/edgexfoundry/go-mod-secrets/pkg"
	mocks2 "github.com/edgexfoundry/go-mod-secrets/pkg/token/authtokenloader/mocks"
	"github.com/edgexfoundry/go-mod-secrets/secrets"
	"github.com/edgexfoundry/go-mod-secrets/secrets/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureProvider_GetSecrets(t *testing.T) {
	expected := map[string]string{"username": "admin", "password": "sam123!"}

	mock := &mocks.SecretClient{}
	mock.On("GetSecrets", "redis", "username", "password").Return(expected, nil)
	mock.On("GetSecrets", "redis").Return(expected, nil)
	notfound := []string{"username", "password"}
	mock.On("GetSecrets", "missing", "username", "password").Return(nil, pkg.NewErrSecretsNotFound(notfound))

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
			target := NewSecureProvider(tc.Config, logger.MockLogger{}, nil)
			target.SetClient(tc.Client)
			actual, err := target.GetSecrets(tc.Path, tc.Keys...)
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
	// Use the Once method so GetSecrets can be changed below
	mock.On("GetSecrets", "redis", "username", "password").Return(expected, nil).Once()

	target := NewSecureProvider(nil, logger.MockLogger{}, nil)
	target.SetClient(mock)

	actual, err := target.GetSecrets("redis", "username", "password")
	require.NoError(t, err)
	assert.Equal(t, expected, actual)

	// Now have mock return error if it is called which should not happen of secrets are cached
	mock.On("GetSecrets", "redis", "username", "password").Return(nil, errors.New("No Cached"))
	actual, err = target.GetSecrets("redis", "username", "password")
	require.NoError(t, err)
	assert.Equal(t, expected, actual)

	// Now check for error when not all requested keys not in cache.
	mock.On("GetSecrets", "redis", "username", "password2").Return(nil, errors.New("No Cached"))
	actual, err = target.GetSecrets("redis", "username", "password2")
	require.Error(t, err)
}

func TestSecureProvider_GetSecrets_Cached_Invalidated(t *testing.T) {
	expected := map[string]string{"username": "admin", "password": "sam123!"}

	mock := &mocks.SecretClient{}
	// Use the Once method so GetSecrets can be changed below
	mock.On("GetSecrets", "redis", "username", "password").Return(expected, nil).Once()
	mock.On("StoreSecrets", "redis", expected).Return(nil)

	target := NewSecureProvider(nil, logger.MockLogger{}, nil)
	target.SetClient(mock)

	actual, err := target.GetSecrets("redis", "username", "password")
	require.NoError(t, err)
	assert.Equal(t, expected, actual)

	// Invalidate the secrets cache by storing new secrets
	err = target.StoreSecrets("redis", expected)
	require.NoError(t, err)

	// Now have mock return error is it is called which should now happen if the cache was properly invalidated by the above call to StoreSecrets
	mock.On("GetSecrets", "redis", "username", "password").Return(nil, errors.New("No Cached"))
	actual, err = target.GetSecrets("redis", "username", "password")
	require.Error(t, err)
}

func TestSecureProvider_StoreSecrets_Secure(t *testing.T) {
	input := map[string]string{"username": "admin", "password": "sam123!"}
	mock := &mocks.SecretClient{}
	mock.On("StoreSecrets", "redis", input).Return(nil)
	mock.On("StoreSecrets", "error", input).Return(errors.New("Some error happened"))

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
			target := NewSecureProvider(nil, logger.MockLogger{}, nil)
			target.SetClient(tc.Client)

			err := target.StoreSecrets(tc.Path, input)
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
	mock.On("StoreSecrets", "redis", input).Return(nil)

	target := NewSecureProvider(nil, logger.MockLogger{}, nil)
	target.SetClient(mock)

	previous := target.SecretsLastUpdated()
	time.Sleep(1 * time.Second)
	err := target.StoreSecrets("redis", input)
	require.NoError(t, err)
	current := target.SecretsLastUpdated()
	assert.True(t, current.After(previous))
}

func TestSecureProvider_SecretsUpdated(t *testing.T) {
	target := NewSecureProvider(nil, logger.MockLogger{}, nil)
	previous := target.SecretsLastUpdated()
	time.Sleep(1 * time.Second)
	target.SecretsUpdated()
	current := target.SecretsLastUpdated()
	// Since the SecureProvider does nothing for SecretsUpdated, LastUpdated shouldn't change
	assert.Equal(t, previous, current)
}

func TestSecureProvider_DefaultTokenExpiredCallback(t *testing.T) {
	goodTokenFile := "good-token.json"
	badTokenFile := "bad-token.json"
	sameTokenFile := "same-token.json"
	newToken := "new token"
	expiredToken := "expired token"

	mockTokenLoader := &mocks2.AuthTokenLoader{}
	mockTokenLoader.On("Load", goodTokenFile).Return(newToken, nil)
	mockTokenLoader.On("Load", sameTokenFile).Return(expiredToken, nil)
	mockTokenLoader.On("Load", badTokenFile).Return("", errors.New("Not Found"))

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

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			config := TestConfig{
				SecretStore: bootstrapConfig.SecretStoreInfo{
					TokenFile: tc.TokenFile,
				},
			}

			target := NewSecureProvider(config, logger.MockLogger{}, mockTokenLoader)
			actualToken, actualRetry := target.DefaultTokenExpiredCallback(tc.ExpiredToken)
			assert.Equal(t, tc.ExpectedToken, actualToken)
			assert.Equal(t, tc.ExpectedRetry, actualRetry)
		})
	}
}

type TestConfig struct {
	InsecureSecrets bootstrapConfig.InsecureSecrets
	SecretStore     bootstrapConfig.SecretStoreInfo
}

func (t TestConfig) UpdateFromRaw(_ interface{}) bool {
	panic("implement me")
}

func (t TestConfig) EmptyWritablePtr() interface{} {
	panic("implement me")
}

func (t TestConfig) UpdateWritableFromRaw(_ interface{}) bool {
	panic("implement me")
}

func (t TestConfig) GetBootstrap() bootstrapConfig.BootstrapConfiguration {
	return bootstrapConfig.BootstrapConfiguration{
		SecretStore: t.SecretStore,
	}
}

func (t TestConfig) GetLogLevel() string {
	panic("implement me")
}

func (t TestConfig) GetRegistryInfo() bootstrapConfig.RegistryInfo {
	panic("implement me")
}

func (t TestConfig) GetInsecureSecrets() bootstrapConfig.InsecureSecrets {
	return t.InsecureSecrets
}
