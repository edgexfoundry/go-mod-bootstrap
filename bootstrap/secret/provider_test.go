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
	"os"
	"testing"
	"time"

	bootstrapConfig "github.com/edgexfoundry/go-mod-bootstrap/config"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"github.com/edgexfoundry/go-mod-secrets/pkg"
	"github.com/edgexfoundry/go-mod-secrets/pkg/types"
	"github.com/edgexfoundry/go-mod-secrets/secrets"
	"github.com/edgexfoundry/go-mod-secrets/secrets/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvider_GetSecrets(t *testing.T) {
	expected := map[string]string{"username": "admin", "password": "sam123!"}

	mock := &mocks.SecretClient{}
	mock.On("GetSecrets", "redis", "username", "password").Return(expected, nil)
	mock.On("GetSecrets", "redis").Return(expected, nil)
	notfound := []string{"username", "password"}
	mock.On("GetSecrets", "missing", "username", "password").Return(nil, pkg.NewErrSecretsNotFound(notfound))

	configAllSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				Path:    "redis",
				Secrets: expected,
			},
		},
	}

	configMissingSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				Path: "redis",
			},
		},
	}

	tests := []struct {
		Name        string
		Secure      string
		Path        string
		Keys        []string
		Config      TestConfig
		Client      secrets.SecretClient
		ExpectError bool
	}{
		{"Valid Secure", "true", "redis", []string{"username", "password"}, TestConfig{}, mock, false},
		{"Invalid Secure", "true", "missing", []string{"username", "password"}, TestConfig{}, mock, true},
		{"Invalid No Client", "true", "redis", []string{"username", "password"}, TestConfig{}, nil, true},
		{"Valid Insecure", "false", "redis", []string{"username", "password"}, configAllSecrets, mock, false},
		{"Valid Insecure just path", "false", "redis", nil, configAllSecrets, mock, false},
		{"Invalid Insecure - No secrets", "false", "redis", []string{"username", "password"}, configMissingSecrets, mock, true},
		{"Invalid Insecure - Bad Path", "false", "bogus", []string{"username", "password"}, configAllSecrets, mock, true},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			os.Setenv(EnvSecretStore, tc.Secure)
			target := NewProviderWithDependents(tc.Client, tc.Config, logger.MockLogger{})
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

func TestProvider_GetSecrets_SecureCached(t *testing.T) {
	os.Setenv(EnvSecretStore, "true")
	expected := map[string]string{"username": "admin", "password": "sam123!"}

	mock := &mocks.SecretClient{}
	// Use the Once method so GetSecrets can be changed below
	mock.On("GetSecrets", "redis", "username", "password").Return(expected, nil).Once()

	target := NewProviderWithDependents(mock, nil, logger.MockLogger{})
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

func TestProvider_GetSecrets_SecureCached_Invalidated(t *testing.T) {
	os.Setenv(EnvSecretStore, "true")
	expected := map[string]string{"username": "admin", "password": "sam123!"}

	mock := &mocks.SecretClient{}
	// Use the Once method so GetSecrets can be changed below
	mock.On("GetSecrets", "redis", "username", "password").Return(expected, nil).Once()
	mock.On("StoreSecrets", "redis", expected).Return(nil)

	target := NewProviderWithDependents(mock, nil, logger.MockLogger{})
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

func TestProvider_StoreSecrets_Secure(t *testing.T) {
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
		{"Invalid Non-secure", "false", "redis", mock, true},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			os.Setenv(EnvSecretStore, tc.Secure)
			target := NewProviderWithDependents(tc.Client, nil, logger.MockLogger{})
			err := target.StoreSecrets(tc.Path, input)
			if tc.ExpectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestProvider_SecretsLastUpdated(t *testing.T) {
	os.Setenv(EnvSecretStore, "true")

	input := map[string]string{"username": "admin", "password": "sam123!"}
	mock := &mocks.SecretClient{}
	mock.On("StoreSecrets", "redis", input).Return(nil)

	target := NewProviderWithDependents(mock, nil, logger.MockLogger{})

	previous := target.SecretsLastUpdated()
	time.Sleep(1 * time.Second)
	err := target.StoreSecrets("redis", input)
	require.NoError(t, err)
	current := target.SecretsLastUpdated()
	assert.True(t, current.After(previous))
}

func TestProvider_InsecureSecretsUpdated(t *testing.T) {
	os.Setenv(EnvSecretStore, "false")
	target := NewProviderWithDependents(nil, nil, logger.MockLogger{})
	previous := target.SecretsLastUpdated()
	time.Sleep(1 * time.Second)
	target.InsecureSecretsUpdated()
	current := target.SecretsLastUpdated()
	assert.True(t, current.After(previous))
}

type TestConfig struct {
	InsecureSecrets bootstrapConfig.InsecureSecrets
	SecretStore     bootstrapConfig.SecretStoreInfo
}

func NewTestConfig(port int) TestConfig {
	return TestConfig{
		SecretStore: bootstrapConfig.SecretStoreInfo{
			Host:       "localhost",
			Port:       port,
			Protocol:   "http",
			ServerName: "localhost",
			TokenFile:  "token.json",
			Authentication: types.AuthenticationInfo{
				AuthType:  "Dummy-Token",
				AuthToken: "myToken",
			},
		},
	}
}

func (t TestConfig) UpdateFromRaw(rawConfig interface{}) bool {
	panic("implement me")
}

func (t TestConfig) EmptyWritablePtr() interface{} {
	panic("implement me")
}

func (t TestConfig) UpdateWritableFromRaw(rawWritable interface{}) bool {
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
