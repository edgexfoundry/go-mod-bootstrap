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
	"fmt"
	"strings"
	"testing"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/config"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ConfigurationMockStruct struct {
	Writable WritableInfo
	Clients  map[string]config.ClientInfo
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
	expectedTriggerType := "edgex-messagebus"
	expectedCoreMetadataHost := "localhost"

	initialConfig := ConfigurationMockStruct{
		Writable: WritableInfo{
			StoreAndForward: StoreAndForwardInfo{
				Enabled:       false,
				RetryInterval: "5m",
				MaxRetryCount: 10,
			},
		},
		Clients: map[string]config.ClientInfo{
			"core-metadata": config.ClientInfo{
				Host:     "edgex-core-metadata",
				Port:     56981,
				Protocol: "http",
			},
		},
		Registry: config.RegistryInfo{
			Host: "localhost",
			Port: 59890,
			Type: "keeper",
		},
		Trigger: TriggerInfo{},
	}
	destMap := map[string]any{}
	err := ConvertToMap(initialConfig, &destMap)
	require.NoError(t, err)

	srcMap := map[string]any{
		"Writable": map[string]any{
			"StoreAndForward": map[string]any{
				"Enabled": true,
			},
		},
		"Trigger": map[string]any{
			"Type": expectedTriggerType,
		},
		"Clients": map[string]any{
			"core-metadata": map[string]any{
				"Host": "localhost",
			},
		},
	}

	MergeMaps(destMap, srcMap)

	actualConfig := ConfigurationMockStruct{}
	err = ConvertFromMap(destMap, &actualConfig)
	require.NoError(t, err)

	assert.True(t, actualConfig.Writable.StoreAndForward.Enabled)
	assert.Equal(t, expectedTriggerType, actualConfig.Trigger.Type)
	assert.Equal(t, expectedCoreMetadataHost, actualConfig.Clients["core-metadata"].Host)

	assert.Equal(t, initialConfig.Clients["core-metadata"].Port, actualConfig.Clients["core-metadata"].Port)
	assert.Equal(t, initialConfig.Clients["core-metadata"].Protocol, actualConfig.Clients["core-metadata"].Protocol)
	assert.Equal(t, initialConfig.Writable.StoreAndForward.RetryInterval, actualConfig.Writable.StoreAndForward.RetryInterval)
	assert.Equal(t, initialConfig.Writable.StoreAndForward.MaxRetryCount, actualConfig.Writable.StoreAndForward.MaxRetryCount)
	assert.Equal(t, initialConfig.Registry.Host, actualConfig.Registry.Host)
	assert.Equal(t, initialConfig.Registry.Port, actualConfig.Registry.Port)
	assert.Equal(t, initialConfig.Registry.Type, actualConfig.Registry.Type)
}

func TestMergeValues(t *testing.T) {
	// create the service config
	serviceConfig := ConfigurationMockStruct{
		Writable: WritableInfo{
			LogLevel: "INFO",
		},
		Registry: config.RegistryInfo{
			Host: "localhost",
			Port: 59890,
			Type: "keeper",
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
				RetryInterval: "",
				MaxRetryCount: 10,
			},
		},
		Trigger: TriggerInfo{
			Type: "edgex-messagebus",
		},
	}
	require.True(t, appConfig.Writable.StoreAndForward.Enabled)
	require.Empty(t, appConfig.Writable.StoreAndForward.RetryInterval)
	require.NotZero(t, appConfig.Writable.StoreAndForward.MaxRetryCount)
	require.NotEmpty(t, appConfig.Trigger.Type)

	// merge the configs
	err := MergeValues(&serviceConfig, &appConfig)
	require.NoError(t, err)

	// verify values
	assert.True(t, serviceConfig.Writable.StoreAndForward.Enabled)
	assert.Empty(t, serviceConfig.Writable.StoreAndForward.RetryInterval)
	assert.NotZero(t, serviceConfig.Writable.StoreAndForward.MaxRetryCount)
	assert.NotEmpty(t, serviceConfig.Trigger.Type)
}

func TestRemoveUnusedSettings(t *testing.T) {
	testConfig := ConfigurationMockStruct{
		Writable: WritableInfo{
			StoreAndForward: StoreAndForwardInfo{
				Enabled:       true,
				RetryInterval: "",
				MaxRetryCount: 10,
			},
		},
		Trigger: TriggerInfo{
			Type: "edgex-messagebus",
		},
	}

	keys := map[string]any{
		common.ConfigStemAll + "/app-something/Writable/StoreAndForward/Enabled":       nil,
		common.ConfigStemAll + "/app-something/Writable/StoreAndForward/RetryInterval": nil,
		common.ConfigStemAll + "/app-something/Writable/StoreAndForward/MaxRetryCount": nil,
		common.ConfigStemAll + "/app-something/Trigger/Type":                           nil,
	}

	actual, err := RemoveUnusedSettings(testConfig, common.ConfigStemAll+"/app-something", keys)

	require.NoError(t, err)
	require.NotNil(t, actual)
	assertMapSettingValueExists(t, actual, "Writable/StoreAndForward/MaxRetryCount")
	assertMapSettingValueExists(t, actual, "Writable/StoreAndForward/RetryInterval")
	assertMapSettingValueExists(t, actual, "Writable/StoreAndForward/Enabled")
	assertMapSettingValueExists(t, actual, "Trigger/Type")
	assertMapSettingValueNotExist(t, actual, "Writable/LogLevel")
	assertMapSettingValueNotExist(t, actual, "Registry/Host")
	assertMapSettingValueNotExist(t, actual, "Registry/Port")
	assertMapSettingValueNotExist(t, actual, "Registry/Type")
}

func assertMapSettingValueExists(t *testing.T, actual map[string]any, actualPath string) bool {
	keys := strings.Split(actualPath, PathSep)
	target := actual
	for _, key := range keys {
		value, exists := target[key]
		if !exists {
			return assert.Fail(t, fmt.Sprintf("Setting value at %s does not exist", actualPath))
		}

		sub, ok := value.(map[string]any)
		if ok {
			target = sub
			continue
		}
	}

	return true
}

func assertMapSettingValueNotExist(t *testing.T, actual map[string]any, actualPath string) bool {
	keys := strings.Split(actualPath, PathSep)
	target := actual
	for _, key := range keys {
		value, exists := target[key]
		if !exists {
			return true
		}

		sub, ok := value.(map[string]any)
		if ok {
			target = sub
			continue
		}

		return assert.Fail(t, fmt.Sprintf("Setting value at %s exists", actualPath))
	}

	return true
}

func TestDeepCopy(t *testing.T) {
	// create some nested data
	orig := ConfigurationMockStruct{
		Writable: WritableInfo{
			LogLevel: "INFO",
		},
		Registry: config.RegistryInfo{
			Host: "localhost",
			Port: 59890,
			Type: "keeper",
		},
		Clients: map[string]config.ClientInfo{
			"a": {
				Host:          "localhost",
				Port:          9000,
				Protocol:      "tcp",
				UseMessageBus: false,
			},
			"b": {
				Host:          "localhost",
				Port:          9001,
				Protocol:      "udp",
				UseMessageBus: false,
			},
			"c": {
				Host:          "localhost",
				Port:          9002,
				Protocol:      "tcp",
				UseMessageBus: true,
			},
		},
	}

	var clone ConfigurationMockStruct
	err := DeepCopy(orig, &clone)
	require.NoError(t, err)

	// sanity check
	assert.Equal(t, orig, clone)

	// make sure that changes to the clone do not affect the original
	clone.Writable.LogLevel = "DEBUG"
	delete(clone.Clients, "b")
	assert.NotEqual(t, orig, clone)

}
