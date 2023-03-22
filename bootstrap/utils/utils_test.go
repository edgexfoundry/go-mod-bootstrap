/*******************************************************************************
 * Copyright 2023 Intel Corp.
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

package utils

import (
	"encoding/json"
	"testing"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ConfigurationMockStruct struct {
	Writable WritableInfo
	Registry config.RegistryInfo
	Trigger  TriggerInfo
}

type WritableInfo struct {
	LogLevel        string
	StoreAndForward StoreAndForwardInfo
}

type StoreAndForwardInfo struct {
	Enabled       bool
	RetryInterval string
	MaxRetryCount int
}

type TriggerInfo struct {
	Type string
}

func TestMergeMaps(t *testing.T) {
	destMap := map[string]any{
		"Writable": WritableInfo{
			StoreAndForward: StoreAndForwardInfo{
				Enabled:       false,
				RetryInterval: "5m",
				MaxRetryCount: 10,
			},
		},
		"Registry": config.RegistryInfo{
			Host: "localhost",
			Port: 8500,
			Type: "consul",
		},
		"Trigger": TriggerInfo{},
	}
	srcMap := map[string]any{
		"Writable": WritableInfo{
			StoreAndForward: StoreAndForwardInfo{
				Enabled:       false,
				RetryInterval: "5m",
				MaxRetryCount: 10,
			},
		},
		"Trigger": TriggerInfo{
			Type: "edgex-messagebus",
		},
	}

	MergeMaps(destMap, srcMap)

	for key, value := range destMap {
		if key == "StoreAndForwardInfo" || key == "Trigger" {
			assert.NotEmpty(t, value)
		}
	}
}

func TestMergeConfigs(t *testing.T) {
	// create the service config
	serviceConfig := ConfigurationMockStruct{
		Writable: WritableInfo{
			LogLevel: "INFO",
		},
		Registry: config.RegistryInfo{
			Host: "localhost",
			Port: 8500,
			Type: "consul",
		},
	}
	require.NotEmpty(t, serviceConfig.Writable.LogLevel)
	require.NotEmpty(t, serviceConfig.Registry.Host)
	require.NotZero(t, serviceConfig.Registry.Port)
	require.NotEmpty(t, serviceConfig.Registry.Type)

	// create the app config
	appConfig := ConfigurationMockStruct{
		Writable: WritableInfo{
			StoreAndForward: StoreAndForwardInfo{
				Enabled:       true,
				RetryInterval: "5m",
				MaxRetryCount: 10,
			},
		},
		Trigger: TriggerInfo{
			Type: "edgex-messagebus",
		},
	}
	require.True(t, appConfig.Writable.StoreAndForward.Enabled)
	require.NotEmpty(t, appConfig.Writable.StoreAndForward.RetryInterval)
	require.NotZero(t, appConfig.Writable.StoreAndForward.MaxRetryCount)
	require.NotEmpty(t, appConfig.Trigger.Type)

	// merge the configs
	err := MergeValues(&serviceConfig, &appConfig)
	require.NoError(t, err)

	// verify values
	assert.True(t, serviceConfig.Writable.StoreAndForward.Enabled)
	assert.NotEmpty(t, serviceConfig.Writable.StoreAndForward.RetryInterval)
	assert.NotZero(t, serviceConfig.Writable.StoreAndForward.MaxRetryCount)
	assert.NotEmpty(t, serviceConfig.Trigger.Type)
}

func TestRemoveZeroValues(t *testing.T) {
	config := ConfigurationMockStruct{
		Registry: config.RegistryInfo{
			Host: "localhost",
			Port: 8500,
		},
	}

	jbytes, err := json.Marshal(config)
	require.NoError(t, err)
	configMap := map[string]any{}
	err = json.Unmarshal(jbytes, &configMap)
	require.NoError(t, err)

	assert.Len(t, configMap, 3)
	assert.Len(t, configMap["Registry"], 3)
	RemoveZeroValues(configMap)

	assert.Len(t, configMap, 1)
	assert.Len(t, configMap["Registry"], 2)
	regMap := configMap["Registry"].(map[string]interface{})
	assert.NotEmpty(t, regMap["Host"])
	assert.NotZero(t, regMap["Port"])
}
