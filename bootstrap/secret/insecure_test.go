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

func TestInsecureProvider_GetSecrets(t *testing.T) {
	expected := map[string]string{"username": "admin", "password": "sam123!"}

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
		Path        string
		Keys        []string
		Config      TestConfig
		ExpectError bool
	}{
		{"Valid", "redis", []string{"username", "password"}, configAllSecrets, false},
		{"Valid just path", "redis", nil, configAllSecrets, false},
		{"Invalid - No secrets", "redis", []string{"username", "password"}, configMissingSecrets, true},
		{"Invalid - Bad Path", "bogus", []string{"username", "password"}, configAllSecrets, true},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			target := NewInsecureProvider(tc.Config, logger.MockLogger{})
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

func TestInsecureProvider_StoreSecrets_Secure(t *testing.T) {
	target := NewInsecureProvider(nil, nil)
	err := target.StoreSecrets("myPath", map[string]string{"Key": "value"})
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
