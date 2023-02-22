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
	"reflect"
	"sort"
	"testing"
	"time"

	bootstrapConfig "github.com/edgexfoundry/go-mod-bootstrap/v3/config"

	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var expectedSecretsKeys = []string{"redisdb", "kongdb"}

func TestInsecureProvider_GetSecrets(t *testing.T) {
	configAllSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				Path:    expectedPath,
				Secrets: expectedSecrets,
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
		Path        string
		Keys        []string
		Config      TestConfig
		ExpectError bool
	}{
		{"Valid", expectedPath, []string{"username", "password"}, configAllSecrets, false},
		{"Valid just path", expectedPath, nil, configAllSecrets, false},
		{"Invalid - No secrets", expectedPath, []string{"username", "password"}, configMissingSecrets, true},
		{"Invalid - Bad Path", "bogus", []string{"username", "password"}, configAllSecrets, true},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			target := NewInsecureProvider(tc.Config, logger.MockLogger{})
			actual, err := target.GetSecret(tc.Path, tc.Keys...)
			if tc.ExpectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, expectedSecrets, actual)
		})
	}
}

func TestInsecureProvider_StoreSecrets_Secure(t *testing.T) {
	target := NewInsecureProvider(nil, nil)
	err := target.StoreSecret("myPath", map[string]string{"Key": "value"})
	require.Error(t, err)
}

func TestInsecureProvider_SecretsUpdated_SecretsLastUpdated(t *testing.T) {
	target := NewInsecureProvider(nil, logger.MockLogger{})
	previous := target.SecretsLastUpdated()
	time.Sleep(1 * time.Second)
	target.SecretsUpdated()
	current := target.SecretsLastUpdated()
	assert.True(t, current.After(previous))
}

func TestInsecureProvider_GetAccessToken(t *testing.T) {
	target := NewInsecureProvider(nil, logger.MockLogger{})
	actualToken, err := target.GetAccessToken(TokenTypeConsul, "my-service-key")
	require.NoError(t, err)
	assert.Len(t, actualToken, 0)
}

func TestInsecureProvider_GetSelfJWT(t *testing.T) {
	target := NewInsecureProvider(nil, logger.MockLogger{})
	actualToken, err := target.GetSelfJWT()
	require.NoError(t, err)
	require.Equal(t, "", actualToken)
}

func TestInsecureProvider_IsJWTValid(t *testing.T) {
	nullJWT := "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.e30."
	target := NewInsecureProvider(nil, logger.MockLogger{})
	result, err := target.IsJWTValid(nullJWT)
	require.NoError(t, err)
	require.Equal(t, true, result)
}

func TestInsecureProvider_ListPaths(t *testing.T) {
	configAllSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"REDIS": {
				Path:    "redisdb",
				Secrets: expectedSecrets,
			},
			"KONG": {
				Path:    "kongdb",
				Secrets: expectedSecrets,
			},
		},
	}

	configMissingSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				Path: "redisdb",
			},
		},
	}

	tests := []struct {
		Name         string
		ExpectedKeys []string
		Config       TestConfig
		ExpectError  bool
	}{
		{"Valid", expectedSecretsKeys, configAllSecrets, false},
		{"Invalid - No secrets", []string{"redisdb"}, configMissingSecrets, false},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			target := NewInsecureProvider(tc.Config, logger.MockLogger{})
			actual, err := target.ListSecretPaths()
			if tc.ExpectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Sorting slices for comparison.
			sort.Strings(actual)
			sort.Strings(tc.ExpectedKeys)

			assert.True(t, reflect.DeepEqual(tc.ExpectedKeys, actual))
		})
	}
}

func TestInsecureProvider_HasSecrets(t *testing.T) {
	configAllSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				Path:    expectedPath,
				Secrets: expectedSecrets,
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

	configNoSecrets := TestConfig{}

	tests := []struct {
		Name          string
		Path          string
		Keys          []string
		Config        TestConfig
		ExpectError   bool
		ExpectResults bool
	}{
		{"Valid", expectedPath, []string{"username", "password"}, configAllSecrets, false, true},
		{"Valid just path", expectedPath, nil, configAllSecrets, false, true},
		{"Valid - No secrets", expectedPath, []string{"username", "password"}, configMissingSecrets, false, false},
		{"Valid - Bad Path", "bogus", []string{"username", "password"}, configAllSecrets, false, false},
		{"Invalid - No Config", "bogus", []string{"username", "password"}, configNoSecrets, true, false},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			target := NewInsecureProvider(tc.Config, logger.MockLogger{})
			actual, err := target.HasSecret(tc.Path)
			if tc.ExpectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.ExpectResults, actual)
		})
	}
}

func TestInsecureProvider_SecretUpdatedAtPath(t *testing.T) {
	configAllSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				Path:    expectedPath,
				Secrets: expectedSecrets,
			},
		},
	}

	callbackCalled := false
	callback := func(path string) {
		callbackCalled = true
	}

	tests := []struct {
		Name     string
		Path     string
		Callback func(path string)
		Config   TestConfig
	}{
		{"Valid", expectedPath, callback, configAllSecrets},
		{"Valid no callback", expectedPath, nil, configAllSecrets},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			callbackCalled = false
			target := NewInsecureProvider(tc.Config, logger.NewMockClient())

			if tc.Callback != nil {
				target.registeredSecretCallbacks[tc.Path] = tc.Callback
			}

			target.SecretUpdatedAtPath(tc.Path)
			assert.Equal(t, tc.Callback != nil, callbackCalled)
		})
	}
}

func TestInsecureProvider_RegisteredSecretUpdatedCallback(t *testing.T) {
	configAllSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				Path:    expectedPath,
				Secrets: expectedSecrets,
			},
		},
	}

	tests := []struct {
		Name     string
		Path     string
		Callback func(path string)
		Config   TestConfig
	}{
		{"Valid", expectedPath, func(path string) {}, configAllSecrets},
		{"Valid no callback", expectedPath, nil, configAllSecrets},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			target := NewInsecureProvider(tc.Config, logger.MockLogger{})
			err := target.RegisteredSecretUpdatedCallback(tc.Path, tc.Callback)
			assert.NoError(t, err)

			if tc.Callback != nil {
				assert.NotEmpty(t, target.registeredSecretCallbacks[tc.Path])
			} else {
				assert.Nil(t, target.registeredSecretCallbacks[tc.Path])
			}
		})
	}
}

func TestInsecureProvider_DeregisterSecretUpdatedCallback(t *testing.T) {
	configAllSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				Path:    expectedPath,
				Secrets: expectedSecrets,
			},
		},
	}

	tests := []struct {
		Name     string
		Path     string
		Callback func(path string)
		Config   TestConfig
	}{
		{"Valid", expectedPath, func(path string) {}, configAllSecrets},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			target := NewInsecureProvider(tc.Config, logger.MockLogger{})
			err := target.RegisteredSecretUpdatedCallback(tc.Path, tc.Callback)
			assert.NoError(t, err)

			// Deregister a secret path.
			target.DeregisterSecretUpdatedCallback(tc.Path)
			assert.Empty(t, target.registeredSecretCallbacks)
		})
	}
}

type TestConfig struct {
	InsecureSecrets bootstrapConfig.InsecureSecrets
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
	return bootstrapConfig.BootstrapConfiguration{}
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

func (t TestConfig) GetTelemetryInfo() *bootstrapConfig.TelemetryInfo {
	panic("implement me")
}
