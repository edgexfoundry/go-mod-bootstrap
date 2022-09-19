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
	"testing"
	"time"

	bootstrapConfig "github.com/edgexfoundry/go-mod-bootstrap/v2/config"

	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"

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
			assert.Equal(t, tc.ExpectedKeys, actual)
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
