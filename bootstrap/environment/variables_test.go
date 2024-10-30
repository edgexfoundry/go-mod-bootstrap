/*******************************************************************************
 * Copyright 2019 Dell Inc.
 * Copyright 2023 Intel Inc.
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

package environment

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	loggerMocks "github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger/mocks"
	"github.com/stretchr/testify/mock"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/config"

	"github.com/edgexfoundry/go-mod-configuration/v4/pkg/types"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	goodUrlValue = "keeper.http://localhost:59890"
	badUrlValue  = "Not a url"

	expectedTypeValue     = "keeper"
	expectedHostValue     = "localhost"
	expectedPortValue     = 59890
	expectedProtocolValue = "http"

	defaultHostValue     = "defaultHost"
	defaultPortValue     = 987654321
	defaultTypeValue     = "defaultType"
	defaultProtocolValue = "defaultProtocol"
)

func initializeTest() (types.ServiceConfig, logger.LoggingClient) {
	os.Clearenv()
	providerConfig := types.ServiceConfig{
		Host:     defaultHostValue,
		Port:     defaultPortValue,
		Type:     defaultTypeValue,
		Protocol: defaultProtocolValue,
	}

	return providerConfig, logger.NewMockClient()
}

func TestOverrideConfigProviderInfo(t *testing.T) {
	providerConfig, lc := initializeTest()

	err := os.Setenv(envKeyConfigUrl, goodUrlValue)
	require.NoError(t, err)

	env := NewVariables(lc)
	providerConfig, err = env.OverrideConfigProviderInfo(providerConfig)

	assert.NoError(t, err, "Unexpected error")
	assert.Equal(t, providerConfig.Host, expectedHostValue)
	assert.Equal(t, providerConfig.Port, expectedPortValue)
	assert.Equal(t, providerConfig.Type, expectedTypeValue)
	assert.Equal(t, providerConfig.Protocol, expectedProtocolValue)
}

func TestOverrideConfigProviderInfo_none(t *testing.T) {
	providerConfig, lc := initializeTest()

	err := os.Setenv(envKeyConfigUrl, noConfigProviderValue)
	require.NoError(t, err)

	env := NewVariables(lc)
	providerConfig, err = env.OverrideConfigProviderInfo(providerConfig)

	assert.NoError(t, err)
	assert.Empty(t, providerConfig.Host)
	assert.Empty(t, providerConfig.Port)
	assert.Empty(t, providerConfig.Type)
	assert.Empty(t, providerConfig.Protocol)
}

func TestOverrideConfigProviderInfo_NoEnvVariables(t *testing.T) {
	providerConfig, lc := initializeTest()

	env := NewVariables(lc)
	providerConfig, err := env.OverrideConfigProviderInfo(providerConfig)

	assert.NoError(t, err, "Unexpected error")
	assert.Equal(t, providerConfig.Host, defaultHostValue)
	assert.Equal(t, providerConfig.Port, defaultPortValue)
	assert.Equal(t, providerConfig.Type, defaultTypeValue)
	assert.Equal(t, providerConfig.Protocol, defaultProtocolValue)
}

func TestOverrideConfigProviderInfo_ConfigProviderInfoError(t *testing.T) {
	providerConfig, lc := initializeTest()

	err := os.Setenv(envKeyConfigUrl, badUrlValue)
	require.NoError(t, err)

	env := NewVariables(lc)
	_, err = env.OverrideConfigProviderInfo(providerConfig)

	assert.Error(t, err, "Expected an error")
}

func TestGetStartupInfo(t *testing.T) {
	testCases := []struct {
		TestName         string
		DurationEnvName  string
		ExpectedDuration int
		IntervalEnvName  string
		ExpectedInterval int
	}{
		{"V2 Envs", envKeyStartupDuration, 120, envKeyStartupInterval, 30},
		{"No Envs", "", bootTimeoutSecondsDefault, "", bootRetrySecondsDefault},
	}

	for _, test := range testCases {
		t.Run(test.TestName, func(t *testing.T) {
			os.Clearenv()

			if len(test.DurationEnvName) > 0 {
				err := os.Setenv(test.DurationEnvName, strconv.Itoa(test.ExpectedDuration))
				require.NoError(t, err)
			}

			if len(test.IntervalEnvName) > 0 {
				err := os.Setenv(test.IntervalEnvName, strconv.Itoa(test.ExpectedInterval))
				require.NoError(t, err)
			}

			actual := GetStartupInfo("unit-test")
			assert.Equal(t, test.ExpectedDuration, actual.Duration)
			assert.Equal(t, test.ExpectedInterval, actual.Interval)
		})
	}
}

func TestGetConfigDir(t *testing.T) {
	_, lc := initializeTest()

	testCases := []struct {
		TestName     string
		EnvName      string
		PassedInName string
		ExpectedName string
	}{
		{"With Env Var", envKeyConfigDir, "res", "myres"},
		{"With No Env Var", "", "res", "res"},
		{"With No Env Var and no passed in", "", "", defaultConfigDirValue},
	}

	for _, test := range testCases {
		t.Run(test.TestName, func(t *testing.T) {
			os.Clearenv()

			if len(test.EnvName) > 0 {
				err := os.Setenv(test.EnvName, test.ExpectedName)
				require.NoError(t, err)
			}

			actual := GetConfigDir(lc, test.PassedInName)
			assert.Equal(t, test.ExpectedName, actual)
		})
	}
}

func TestGetRemoteServiceHosts(t *testing.T) {
	_, lc := initializeTest()

	testCases := []struct {
		TestName string
		EnvName  string
		EnvValue string
		PassedIn []string
		Expected []string
	}{
		{"With Env Var", envKeyRemoteServiceHosts, "1,2,3", nil, []string{"1", "2", "3"}},
		{"With No Env Var and passed in", "", "", []string{"1", "2", "3"}, []string{"1", "2", "3"}},
		{"With No Env Var and no passed in", "", "", nil, nil},
	}

	for _, test := range testCases {
		t.Run(test.TestName, func(t *testing.T) {
			os.Clearenv()

			if len(test.EnvName) > 0 {
				err := os.Setenv(test.EnvName, test.EnvValue)
				require.NoError(t, err)
			}

			actual := GetRemoteServiceHosts(lc, test.PassedIn)
			assert.Equal(t, test.Expected, actual)
		})
	}
}

func TestGetProfileDir(t *testing.T) {
	_, lc := initializeTest()

	testCases := []struct {
		TestName     string
		EnvName      string
		EnvValue     string
		PassedInName string
		ExpectedName string
	}{
		{"With V2 Env Var", envKeyProfile, "myProfileV2", "sample", "myProfileV2/"},
		{"With No Env Var", "", "", "sample", "sample/"},
		{"With No Env Var and no passed in", "", "", "", ""},
	}

	for _, test := range testCases {
		t.Run(test.TestName, func(t *testing.T) {
			os.Clearenv()

			if len(test.EnvName) > 0 {
				err := os.Setenv(test.EnvName, test.EnvValue)
				require.NoError(t, err)
			}

			actual := GetProfileDir(lc, test.PassedInName)
			assert.Equal(t, test.ExpectedName, actual)
		})
	}
}

func TestGetConfigFileName(t *testing.T) {
	_, lc := initializeTest()

	testCases := []struct {
		TestName     string
		EnvName      string
		PassedInName string
		ExpectedName string
	}{
		{"With Env Var", envKeyConfigFile, "configuration.toml", "config.toml"},
		{"With No Env Var", "", "configuration.toml", "configuration.toml"},
		{"With No Env Var and no passed in", "", "", ""},
	}

	for _, test := range testCases {
		t.Run(test.TestName, func(t *testing.T) {
			os.Clearenv()

			if len(test.EnvName) > 0 {
				err := os.Setenv(test.EnvName, test.ExpectedName)
				require.NoError(t, err)
			}

			actual := GetConfigFileName(lc, test.PassedInName)
			assert.Equal(t, test.ExpectedName, actual)
		})
	}
}

func TestGetCommonConfigFileName(t *testing.T) {
	_, lc := initializeTest()

	testCases := []struct {
		TestName     string
		EnvName      string
		PassedInName string
		ExpectedName string
	}{
		{"With Env Var", envKeyCommonConfig, "configuration.yaml", "config.yaml"},
		{"With No Env Var", "", "configuration.yaml", "configuration.yaml"},
		{"With No Env Var and no passed in", "", "", ""},
	}

	for _, test := range testCases {
		t.Run(test.TestName, func(t *testing.T) {
			os.Clearenv()

			if len(test.EnvName) > 0 {
				err := os.Setenv(test.EnvName, test.ExpectedName)
				require.NoError(t, err)
			}

			actual := GetCommonConfigFileName(lc, test.PassedInName)
			assert.Equal(t, test.ExpectedName, actual)
		})
	}
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

	env := Variables{}
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
	_, lc := initializeTest()

	serviceConfig := struct {
		Registry config.RegistryInfo
		List     []string
		FloatVal float32
	}{
		Registry: config.RegistryInfo{
			Host: "localhost",
			Port: 59890,
			Type: "keeper",
		},
		List:     []string{"val1"},
		FloatVal: float32(11.11),
	}

	// only all upper case environment variable names now, so none of these overrides should have worked.
	expectedOverrideCount := 0

	expectedHost := "edgex-core-keeper"
	expectedPort := 59890
	expectedFloatVal := float32(24.234)
	expectedAuthType := "secure"

	_ = os.Setenv("Registry_Host", expectedHost)
	_ = os.Setenv("Registry_Port", strconv.Itoa(expectedPort))
	_ = os.Setenv("List", " joe,mary  ,  bob  ")
	strVal := fmt.Sprintf("%v", expectedFloatVal)
	_ = os.Setenv("FloatVal", strVal)
	_ = os.Setenv("SecretStore_Authentication_AuthType", expectedAuthType)

	env := NewVariables(lc)
	actualCount, err := env.OverrideConfiguration(&serviceConfig)
	require.NoError(t, err)

	assert.Equal(t, expectedOverrideCount, actualCount)
}

func TestOverrideConfigurationUppercase(t *testing.T) {
	_, lc := initializeTest()

	expectedOverrideCount := 4
	expectedRegistryHost := "edgex-core-keeper"
	expectedCoreDataHost := "edgex-core-data"
	expectedList := []string{"joe", "mary", "bob"}
	expectedFloatVal := float32(24.234)

	coreDataClientKey := "edgex-core-data"

	serviceConfig := struct {
		Registry config.RegistryInfo
		List     []string
		FloatVal float32
		Clients  map[string]config.ClientInfo
	}{
		Registry: config.RegistryInfo{
			Host: "localhost",
			Port: 59890,
			Type: "keeper",
		},
		List:     []string{"val1"},
		FloatVal: float32(11.11),
		Clients: map[string]config.ClientInfo{
			coreDataClientKey: {
				Host:     "localhost",
				Port:     49080,
				Protocol: "http",
			},
		},
	}

	_ = os.Setenv("REGISTRY_HOST", expectedRegistryHost)
	_ = os.Setenv("CLIENTS_EDGEX_CORE_DATA_HOST", expectedCoreDataHost)
	_ = os.Setenv("LIST", " joe,mary  ,  bob  ")
	strVal := fmt.Sprintf("%v", expectedFloatVal)
	_ = os.Setenv("FLOATVAL", strVal)
	// Lowercase will not match, so value will not change
	_ = os.Setenv("secretstore_authentication_authtoken", "NoToken")

	env := NewVariables(lc)
	actualCount, err := env.OverrideConfiguration(&serviceConfig)

	require.NoError(t, err)
	assert.Equal(t, expectedOverrideCount, actualCount)
	assert.Equal(t, expectedRegistryHost, serviceConfig.Registry.Host)
	assert.Equal(t, expectedCoreDataHost, serviceConfig.Clients[coreDataClientKey].Host)
	assert.Equal(t, expectedList, serviceConfig.List)
	assert.Equal(t, expectedFloatVal, serviceConfig.FloatVal)
}

func TestOverrideConfigurationWithBlankValue(t *testing.T) {
	_, lc := initializeTest()

	expectedOverrideCount := 1
	expectedHost := ""

	serviceConfig := struct {
		Registry config.RegistryInfo
		List     []string
		FloatVal float32
	}{
		Registry: config.RegistryInfo{
			Host: "localhost",
			Port: 59890,
			Type: "keeper",
		},
		List:     []string{"val1"},
		FloatVal: float32(11.11),
	}

	_ = os.Setenv("REGISTRY_HOST", expectedHost)

	env := NewVariables(lc)
	actualCount, err := env.OverrideConfiguration(&serviceConfig)

	require.NoError(t, err)
	assert.Equal(t, expectedOverrideCount, actualCount)
	assert.Equal(t, expectedHost, serviceConfig.Registry.Host)
}

func TestOverrideSecretStoreInfo(t *testing.T) {
	_, lc := initializeTest()

	expectedOverrideCount := 3
	expectedAuthToken := "123456=789"
	expectedHost := "edgex-secret-store"
	expectedPort := 8200

	wrapper := struct {
		SecretStore config.SecretStoreInfo
	}{
		SecretStore: config.NewSecretStoreInfo("unit-test"),
	}

	_ = os.Setenv("SECRETSTORE_AUTHENTICATION_AUTHTOKEN", expectedAuthToken)
	_ = os.Setenv("SECRETSTORE_HOST", expectedHost)
	_ = os.Setenv("SECRETSTORE_PORT", fmt.Sprintf("%d", expectedPort))

	env := NewVariables(lc)

	actualCount, err := env.OverrideConfiguration(&wrapper)

	require.NoError(t, err)
	assert.Equal(t, expectedOverrideCount, actualCount)
	assert.Equal(t, expectedAuthToken, wrapper.SecretStore.Authentication.AuthToken)
	assert.Equal(t, expectedHost, wrapper.SecretStore.Host)
	assert.Equal(t, expectedPort, wrapper.SecretStore.Port)
}

func TestLogEnvironmentOverride(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		value    string
		redacted bool
	}{
		{
			name:     "basic variable - not redacted",
			path:     "Writable.LogLevel",
			value:    "DEBUG",
			redacted: false,
		},
		{
			name:     "insecure secret value - redacted",
			path:     "Writable.InsecureSecrets.credentials001.Secrets.password",
			value:    "HelloWorld!",
			redacted: true,
		},
		{
			name:     "insecure secret value - redacted 2",
			path:     "Writable.InsecureSecrets.credentials001.Secrets.username",
			value:    "admin",
			redacted: true,
		},
		{
			name:     "insecure secret name - not redacted",
			path:     "Writable.InsecureSecrets.credentials001.secretName",
			value:    "credentials001",
			redacted: false,
		},
	}

	mockLogger := &loggerMocks.LoggingClient{}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			key := strings.ReplaceAll(strings.ToUpper(test.path), ".", "_")

			// specifically expect the method to be called with the values we pass in plus the format string
			// and any value (can be redacted or not)
			mockLogger.On("Infof", mock.AnythingOfType("string"),
				test.path, key, mock.AnythingOfType("string")).Return().Once()

			logEnvironmentOverride(mockLogger, test.path, key, test.value)

			mockLogger.AssertExpectations(t)
			if test.redacted {
				// make sure it was called with the redacted placeholder string.
				mockLogger.AssertCalled(t, "Infof", mock.AnythingOfType("string"), test.path, key, redactedStr)
			} else {
				// make sure the original value was logged.
				mockLogger.AssertCalled(t, "Infof", mock.AnythingOfType("string"), test.path, key, test.value)
			}
		})
	}
}

func TestOverrideConfigMapValues(t *testing.T) {
	flatMap := map[string]any{
		"top":             "top value",
		"some/value":      "my string",
		"some/thing/here": 123,
		"my/other/value":  12.89,
	}

	nonFlatMap := map[string]any{
		"top": "top value",
		"some": map[string]any{
			"value": "my string",
			"thing": map[string]any{
				"here": 123,
			},
		},
		"my": map[string]any{
			"other": map[string]any{
				"value": 12.89,
			},
		},
	}

	tests := []struct {
		Name      string
		ConfigMap map[string]any
	}{
		{"Flat Map", flatMap},
		{"Non Flat Map", nonFlatMap},
	}

	expectedCount := 4
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			defer os.Clearenv()
			os.Setenv("TOP", "new top value")
			os.Setenv("SOME_VALUE", "your string")
			os.Setenv("SOME_THING_HERE", "321")
			os.Setenv("MY_OTHER_VALUE", "89.12")

			mockLogger := &loggerMocks.LoggingClient{}
			mockLogger.On("Infof", mock.Anything, "top", "TOP", "new top value")
			mockLogger.On("Infof", mock.Anything, "some/value", "SOME_VALUE", "your string")
			mockLogger.On("Infof", mock.Anything, "some/thing/here", "SOME_THING_HERE", "321")
			mockLogger.On("Infof", mock.Anything, "my/other/value", "MY_OTHER_VALUE", "89.12")
			target := NewVariables(mockLogger)

			actualCount, err := target.OverrideConfigMapValues(test.ConfigMap)
			require.NoError(t, err)
			assert.Equal(t, expectedCount, actualCount)
			mockLogger.AssertExpectations(t)
		})
	}
}

func TestGetRequestTimeout(t *testing.T) {
	_, lc := initializeTest()

	testCases := []struct {
		TestName        string
		EnvTimeout      string
		ExpectedTimeout time.Duration
	}{
		{"With Env Var", envKeyFileURITimeout, 15 * time.Second},
		{"With No Env Var", "", 15 * time.Second},
	}

	for _, test := range testCases {
		t.Run(test.TestName, func(t *testing.T) {
			os.Clearenv()

			if len(test.EnvTimeout) > 0 {
				err := os.Setenv(test.EnvTimeout, test.ExpectedTimeout.String())
				require.NoError(t, err)
			}

			actual := GetURIRequestTimeout(lc)
			assert.Equal(t, test.ExpectedTimeout, actual)
		})
	}
}
