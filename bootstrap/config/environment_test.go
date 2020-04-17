/*******************************************************************************
 * Copyright 2019 Dell Inc.
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

package config

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/edgexfoundry/go-mod-secrets/pkg/providers/vault"
	"github.com/stretchr/testify/require"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/logging"
	"github.com/edgexfoundry/go-mod-bootstrap/config"

	"github.com/edgexfoundry/go-mod-configuration/pkg/types"

	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"

	"github.com/stretchr/testify/assert"
)

const (
	goodUrlValue         = "consul.http://localhost:8500"
	goodRegistryUrlValue = "consul://localhost:8500"

	badUrlValue = "Not a url"

	expectedTypeValue     = "consul"
	expectedHostValue     = "localhost"
	expectedPortValue     = 8500
	expectedProtocolValue = "http"

	defaultHostValue     = "defaultHost"
	defaultPortValue     = 987654321
	defaultTypeValue     = "defaultType"
	defaultProtocolValue = "defaultProtocol"

	defaultStartupDuration  = 30
	defaultStartupInterval  = 1
	envStartupDuration      = "333"
	envStartupInterval      = "111"
	expectedStartupDuration = 333
	expectedStartupInterval = 111
)

func initializeTest() (types.ServiceConfig, config.StartupInfo, logger.LoggingClient) {
	os.Clearenv()
	providerConfig := types.ServiceConfig{
		Host:     defaultHostValue,
		Port:     defaultPortValue,
		Type:     defaultTypeValue,
		Protocol: defaultProtocolValue,
	}
	startupInfo := config.StartupInfo{
		Duration: defaultStartupDuration,
		Interval: defaultStartupInterval,
	}

	return providerConfig, startupInfo, logging.FactoryToStdout("unit-test")
}

func TestOverrideConfigProviderInfo(t *testing.T) {
	providerConfig, _, lc := initializeTest()

	err := os.Setenv(envKeyConfigUrl, goodUrlValue)
	require.NoError(t, err)

	env := NewEnvironment()
	providerConfig, err = env.OverrideConfigProviderInfo(lc, providerConfig)

	assert.NoError(t, err, "Unexpected error")
	assert.Equal(t, providerConfig.Host, expectedHostValue)
	assert.Equal(t, providerConfig.Port, expectedPortValue)
	assert.Equal(t, providerConfig.Type, expectedTypeValue)
	assert.Equal(t, providerConfig.Protocol, expectedProtocolValue)
}

// TODO: Remove once -registry is back to a bool in release V2.0.0
func TestOverrideConfigProviderInfo_RegistryUrl(t *testing.T) {
	providerConfig, _, lc := initializeTest()

	err := os.Setenv(envKeyRegistryUrl, goodRegistryUrlValue)
	require.NoError(t, err)

	env := NewEnvironment()
	providerConfig, err = env.OverrideConfigProviderInfo(lc, providerConfig)

	require.NoError(t, err, "Unexpected error")
	assert.Equal(t, providerConfig.Host, expectedHostValue)
	assert.Equal(t, providerConfig.Port, expectedPortValue)
	assert.Equal(t, providerConfig.Type, expectedTypeValue)
	assert.Equal(t, providerConfig.Protocol, expectedProtocolValue)
}

func TestOverrideConfigProviderInfo_NoEnvVariables(t *testing.T) {
	providerConfig, _, lc := initializeTest()

	env := NewEnvironment()
	providerConfig, err := env.OverrideConfigProviderInfo(lc, providerConfig)

	assert.NoError(t, err, "Unexpected error")
	assert.Equal(t, providerConfig.Host, defaultHostValue)
	assert.Equal(t, providerConfig.Port, defaultPortValue)
	assert.Equal(t, providerConfig.Type, defaultTypeValue)
	assert.Equal(t, providerConfig.Protocol, defaultProtocolValue)
}

func TestOverrideConfigProviderInfo_ConfigProviderInfoError(t *testing.T) {
	providerConfig, _, lc := initializeTest()

	err := os.Setenv(envKeyConfigUrl, badUrlValue)
	require.NoError(t, err)

	env := NewEnvironment()
	_, err = env.OverrideConfigProviderInfo(lc, providerConfig)

	assert.Error(t, err, "Expected an error")
}

// TODO: Remove once -registry is back to a bool in release V2.0.0
func TestGetRegistryProviderInfoOverride(t *testing.T) {
	_, _, lc := initializeTest()

	err := os.Setenv(envKeyRegistryUrl, goodRegistryUrlValue)
	require.NoError(t, err)
	env := NewEnvironment()
	actual := env.GetRegistryProviderInfoOverride(lc)
	assert.Equal(t, goodRegistryUrlValue, actual)
}

func TestOverrideStartupInfo(t *testing.T) {
	_, startupInfo, lc := initializeTest()

	err := os.Setenv(envKeyStartupDuration, envStartupDuration)
	require.NoError(t, err)

	err = os.Setenv(envKeyStartupInterval, envStartupInterval)
	require.NoError(t, err)

	env := NewEnvironment()
	startupInfo = env.OverrideStartupInfo(lc, startupInfo)

	assert.Equal(t, startupInfo.Duration, expectedStartupDuration)
	assert.Equal(t, startupInfo.Interval, expectedStartupInterval)
}

func TestOverrideStartupInfoV1(t *testing.T) {
	_, startupInfo, lc := initializeTest()

	err := os.Setenv(envV1KeyStartupDuration, envStartupDuration)
	require.NoError(t, err)

	err = os.Setenv(envV1KeyStartupInterval, envStartupInterval)
	require.NoError(t, err)

	env := NewEnvironment()
	startupInfo = env.OverrideStartupInfo(lc, startupInfo)

	assert.Equal(t, startupInfo.Duration, expectedStartupDuration)
	assert.Equal(t, startupInfo.Interval, expectedStartupInterval)
}

func TestOverrideStartupInfo_NoEnvVariables(t *testing.T) {
	_, startupInfo, lc := initializeTest()

	env := NewEnvironment()
	startupInfo = env.OverrideStartupInfo(lc, startupInfo)

	assert.Equal(t, startupInfo.Duration, defaultStartupDuration)
	assert.Equal(t, startupInfo.Interval, defaultStartupInterval)
}

func TestConvertToType(t *testing.T) {
	tests := []struct {
		Name          string
		Value         string
		OldValue      interface{}
		ExpectedValue interface{}
		ExpectedError string
	}{
		{Name: "String", Value: "This is string", OldValue: "string", ExpectedValue: "This is string"},
		{Name: "Valid String slice", Value: " val1 , val2 ", OldValue: []string{}, ExpectedValue: []interface{}{"val1", "val2"}},
		{Name: "Invalid slice type", Value: "", OldValue: []int{}, ExpectedError: "'[]int' is not supported"},
		{Name: "Valid bool", Value: "true", OldValue: true, ExpectedValue: true},
		{Name: "Invalid bool", Value: "bad bool", OldValue: false, ExpectedError: "invalid syntax"},
		{Name: "Valid int", Value: "234", OldValue: 0, ExpectedValue: 234},
		{Name: "Invalid int", Value: "one", OldValue: 0, ExpectedError: "invalid syntax"},
		{Name: "Valid int8", Value: "123", OldValue: int8(0), ExpectedValue: int8(123)},
		{Name: "Invalid int8", Value: "897", OldValue: int8(0), ExpectedError: "value out of range"},
		{Name: "Valid int16", Value: "897", OldValue: int16(0), ExpectedValue: int16(897)},
		{Name: "Invalid int16", Value: "89756789", OldValue: int16(0), ExpectedError: "value out of range"},
		{Name: "Valid int32", Value: "89756789", OldValue: int32(0), ExpectedValue: int32(89756789)},
		{Name: "Invalid int32", Value: "89756789324414221", OldValue: int32(0), ExpectedError: "value out of range"},
		{Name: "Valid int64", Value: "89756789324414221", OldValue: int64(0), ExpectedValue: int64(89756789324414221)},
		{Name: "Invalid int64", Value: "one", OldValue: int64(0), ExpectedError: "invalid syntax"},
		{Name: "Valid uint", Value: "234", OldValue: uint(0), ExpectedValue: uint(234)},
		{Name: "Invalid uint", Value: "one", OldValue: uint(0), ExpectedError: "invalid syntax"},
		{Name: "Valid uint8", Value: "123", OldValue: uint8(0), ExpectedValue: uint8(123)},
		{Name: "Invalid uint8", Value: "897", OldValue: uint8(0), ExpectedError: "value out of range"},
		{Name: "Valid uint16", Value: "897", OldValue: uint16(0), ExpectedValue: uint16(897)},
		{Name: "Invalid uint16", Value: "89756789", OldValue: uint16(0), ExpectedError: "value out of range"},
		{Name: "Valid uint32", Value: "89756789", OldValue: uint32(0), ExpectedValue: uint32(89756789)},
		{Name: "Invalid uint32", Value: "89756789324414221", OldValue: uint32(0), ExpectedError: "value out of range"},
		{Name: "Valid uint64", Value: "89756789324414221", OldValue: uint64(0), ExpectedValue: uint64(89756789324414221)},
		{Name: "Invalid uint64", Value: "one", OldValue: uint64(0), ExpectedError: "invalid syntax"},
		{Name: "Valid float32", Value: "895.89", OldValue: float32(0), ExpectedValue: float32(895.89)},
		{Name: "Invalid float32", Value: "one", OldValue: float32(0), ExpectedError: "invalid syntax"},
		{Name: "Valid float64", Value: "89756789324414221.5689", OldValue: float64(0), ExpectedValue: 89756789324414221.5689},
		{Name: "Invalid float64", Value: "one", OldValue: float64(0), ExpectedError: "invalid syntax"},
		{Name: "Invalid Value Type", Value: "anything", OldValue: make(chan int), ExpectedError: "type of 'chan int' is not supported"},
	}

	env := Environment{}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			actual, err := env.convertToType(test.OldValue, test.Value)
			if len(test.ExpectedError) > 0 {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedError)
				return // test complete
			}

			require.NoError(t, err)
			assert.Equal(t, test.ExpectedValue, actual)
		})
	}
}

func TestOverrideConfigurationExactCase(t *testing.T) {
	_, _, lc := initializeTest()

	serviceConfig := struct {
		Registry    config.RegistryInfo
		List        []string
		FloatVal    float32
		SecretStore config.SecretStoreInfo
	}{
		Registry: config.RegistryInfo{
			Host: "localhost",
			Port: 8500,
			Type: "consul",
		},
		List:     []string{"val1"},
		FloatVal: float32(11.11),
		SecretStore: config.SecretStoreInfo{
			Authentication: vault.AuthenticationInfo{
				AuthType: "none",
			},
		},
	}

	expectedOverrideCount := 5
	expectedHost := "edgex-core-consul"
	expectedPort := 98500
	expectedList := []string{"joe", "mary", "bob"}
	expectedFloatVal := float32(24.234)
	expectedAuthType := "secure"

	_ = os.Setenv("Registry_Host", expectedHost)
	_ = os.Setenv("Registry_Port", strconv.Itoa(expectedPort))
	_ = os.Setenv("List", " joe,mary  ,  bob  ")
	strVal := fmt.Sprintf("%v", expectedFloatVal)
	_ = os.Setenv("FloatVal", strVal)
	_ = os.Setenv("SecretStore_Authentication_AuthType", expectedAuthType)

	env := NewEnvironment()
	actualCount, err := env.OverrideConfiguration(lc, &serviceConfig)

	require.NoError(t, err)
	assert.Equal(t, expectedOverrideCount, actualCount)
	assert.Equal(t, expectedHost, serviceConfig.Registry.Host)
	assert.Equal(t, expectedPort, serviceConfig.Registry.Port)
	assert.Equal(t, expectedList, serviceConfig.List)
	assert.Equal(t, expectedFloatVal, serviceConfig.FloatVal)
	assert.Equal(t, expectedAuthType, serviceConfig.SecretStore.Authentication.AuthType)
}

func TestOverrideConfigurationUppercase(t *testing.T) {
	_, _, lc := initializeTest()

	expectedOverrideCount := 4
	expectedHost := "edgex-core-consul"
	expectedList := []string{"joe", "mary", "bob"}
	expectedFloatVal := float32(24.234)
	expectedAuthType := "secure"
	expectedAuthToken := "token"

	serviceConfig := struct {
		Registry    config.RegistryInfo
		List        []string
		FloatVal    float32
		SecretStore config.SecretStoreInfo
	}{
		Registry: config.RegistryInfo{
			Host: "localhost",
			Port: 8500,
			Type: "consul",
		},
		List:     []string{"val1"},
		FloatVal: float32(11.11),
		SecretStore: config.SecretStoreInfo{
			Authentication: vault.AuthenticationInfo{
				AuthType:  "none",
				AuthToken: expectedAuthToken,
			},
		},
	}

	_ = os.Setenv("REGISTRY_HOST", expectedHost)
	_ = os.Setenv("LIST", " joe,mary  ,  bob  ")
	strVal := fmt.Sprintf("%v", expectedFloatVal)
	_ = os.Setenv("FLOATVAL", strVal)
	_ = os.Setenv("SECRETSTORE_AUTHENTICATION_AUTHTYPE", expectedAuthType)
	// Lowercase will not match, so value will not change
	_ = os.Setenv("secretstore_authentication_authtoken", "NoToken")

	env := NewEnvironment()
	actualCount, err := env.OverrideConfiguration(lc, &serviceConfig)

	require.NoError(t, err)
	assert.Equal(t, expectedOverrideCount, actualCount)
	assert.Equal(t, expectedHost, serviceConfig.Registry.Host)
	assert.Equal(t, expectedList, serviceConfig.List)
	assert.Equal(t, expectedFloatVal, serviceConfig.FloatVal)
	assert.Equal(t, expectedAuthType, serviceConfig.SecretStore.Authentication.AuthType)
	assert.Equal(t, expectedAuthToken, serviceConfig.SecretStore.Authentication.AuthToken)
}
