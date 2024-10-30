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
	"fmt"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/di"
	"github.com/stretchr/testify/mock"
	"math"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"

	bootstrapConfig "github.com/edgexfoundry/go-mod-bootstrap/v4/config"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configurationMocks "github.com/edgexfoundry/go-mod-configuration/v4/configuration/mocks"
)

// mockObjects holds the various mocks needed for running these tests
type mockObjects struct {
	dic          *di.Container
	lc           logger.LoggingClient
	configClient *configurationMocks.Client
}

// newMockObjects creates a full mockObjects with all values
func newMockObjects() mockObjects {
	configClient := new(configurationMocks.Client)
	lc := logger.NewMockClient()

	return mockObjects{
		dic: di.NewContainer(di.ServiceConstructorMap{
			container.ConfigClientInterfaceName: func(get di.Get) interface{} {
				return configClient
			},
			container.LoggingClientInterfaceName: func(get di.Get) interface{} {
				return lc
			},
		}),
		lc:           lc,
		configClient: configClient,
	}
}

// newMockObjectsNoConfigClient creates a new mockObjects, but without the config client
func newMockObjectsNoConfigClient() mockObjects {
	lc := logger.NewMockClient()

	return mockObjects{
		dic: di.NewContainer(di.ServiceConstructorMap{
			container.LoggingClientInterfaceName: func(get di.Get) interface{} {
				return lc
			},
		}),
		lc: lc,
	}
}

var expectedSecretsKeys = []string{"redisdb", "kongdb"}

func TestInsecureProvider_GetSecrets(t *testing.T) {
	configAllSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				SecretName: expectedSecretName,
				SecretData: expectedSecrets,
			},
		},
	}

	configMissingSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				SecretName: "redis",
			},
		},
	}

	tests := []struct {
		Name        string
		SecretName  string
		Keys        []string
		Config      TestConfig
		ExpectError bool
	}{
		{"Valid", expectedSecretName, []string{"username", "password"}, configAllSecrets, false},
		{"Valid just secretName", expectedSecretName, nil, configAllSecrets, false},
		{"Invalid - No secrets", expectedSecretName, []string{"username", "password"}, configMissingSecrets, true},
		{"Invalid - Bad SecretName", "bogus", []string{"username", "password"}, configAllSecrets, true},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			testMocks := newMockObjects()
			target := NewInsecureProvider(tc.Config, testMocks.lc, testMocks.dic)
			actual, err := target.GetSecret(tc.SecretName, tc.Keys...)
			if tc.ExpectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, expectedSecrets, actual)
		})
	}
}

// TestInsecureProvider_StoreSecrets tests that the proper actions are performed when StoreSecrets
// is called with specific data
func TestInsecureProvider_StoreSecrets(t *testing.T) {
	secretName := "test-secret-name"
	key1 := UsernameKey
	value1 := "my-username"
	key2 := PasswordKey
	value2 := "my-password"

	testMocks := newMockObjects()

	// make sure the secret name is stored exactly once
	testMocks.configClient.On("PutConfigurationValue",
		config.GetInsecureSecretNameFullPath(secretName),
		[]uint8(secretName)). // need to use uint8 because byte is just an alias
		Return(nil).
		Once()

	// make sure the proper key1/value1 pair is stored exactly once
	testMocks.configClient.On("PutConfigurationValue",
		config.GetInsecureSecretDataFullPath(secretName, key1),
		[]uint8(value1)). // need to use uint8 because byte is just an alias
		Return(nil).
		Once()

	// make sure the proper key2/value2 pair is stored exactly once
	testMocks.configClient.On("PutConfigurationValue",
		config.GetInsecureSecretDataFullPath(secretName, key2),
		[]uint8(value2)). // need to use uint8 because byte is just an alias
		Return(nil).
		Once()

	target := NewInsecureProvider(nil, testMocks.lc, testMocks.dic)
	err := target.StoreSecret(secretName, map[string]string{
		key1: value1,
		key2: value2,
	})
	require.NoError(t, err)

	testMocks.configClient.AssertExpectations(t)
}

// TestInsecureProvider_StoreSecrets_NoConfigClient tests what happens when there is no ConfigClient present
func TestInsecureProvider_StoreSecrets_NoConfigClient(t *testing.T) {
	testMocks := newMockObjectsNoConfigClient()

	target := NewInsecureProvider(nil, testMocks.lc, testMocks.dic)
	err := target.StoreSecret("testSecretName", map[string]string{
		UsernameKey: "user",
		PasswordKey: "pass",
	})
	// expect an error because Config Client is not available
	require.Error(t, err)
}

// TestInsecureProvider_StoreSecrets_Error tests what happens when an error is returned at various stages in the
// StoreSecrets method
func TestInsecureProvider_StoreSecrets_Error(t *testing.T) {
	totalCalls := 5
	// note: internally, put value is called 1 time for secretName and 1 additional time for each key/value pair
	// failing on first call, means failed to set secretName, and failing on calls 2-5 means failing to store key/values
	for failAtCall := 1; failAtCall <= totalCalls+1; failAtCall++ {
		t.Run(strconv.Itoa(failAtCall), func(t *testing.T) {
			testMocks := newMockObjects()
			callNumber := 0

			mockCall := testMocks.configClient.On("PutConfigurationValue",
				mock.AnythingOfType("string"),
				mock.AnythingOfType("[]uint8")). // need to use uint8 because byte is just an alias
				// expect to be called at either the failAtCall, or totalCalls if failAtCall is > totalCalls
				Times(int(math.Min(float64(failAtCall), float64(totalCalls))))

			mockCall.Run(func(args mock.Arguments) {
				callNumber += 1
				if callNumber < failAtCall {
					mockCall.Return(nil)
				} else {
					mockCall.Return(fmt.Errorf("returning error on call numbner %d", failAtCall))
				}
			})

			target := NewInsecureProvider(nil, testMocks.lc, testMocks.dic)
			err := target.StoreSecret("testSecretName", map[string]string{
				UsernameKey: "user",
				PasswordKey: "pass",
				"extraKey":  "value",
				"evenMore":  "less",
			})
			testMocks.configClient.AssertExpectations(t)

			if failAtCall < 6 {
				// expect an error because Config Client returned an error at some point
				require.Error(t, err)
			} else {
				// expect no error because all calls should have succeeded
				require.NoError(t, err)
			}
		})
	}
}

func TestInsecureProvider_SecretsUpdated_SecretsLastUpdated(t *testing.T) {
	testMocks := newMockObjects()
	target := NewInsecureProvider(nil, testMocks.lc, testMocks.dic)
	previous := target.SecretsLastUpdated()
	time.Sleep(1 * time.Second)
	target.SecretsUpdated()
	current := target.SecretsLastUpdated()
	assert.True(t, current.After(previous))
}

func TestInsecureProvider_GetSelfJWT(t *testing.T) {
	testMocks := newMockObjects()
	target := NewInsecureProvider(nil, testMocks.lc, testMocks.dic)
	actualToken, err := target.GetSelfJWT()
	require.NoError(t, err)
	require.Equal(t, "", actualToken)
}

func TestInsecureProvider_IsJWTValid(t *testing.T) {
	nullJWT := "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.e30."
	testMocks := newMockObjects()
	target := NewInsecureProvider(nil, testMocks.lc, testMocks.dic)
	result, err := target.IsJWTValid(nullJWT)
	require.NoError(t, err)
	require.Equal(t, true, result)
}

func TestInsecureProvider_ListPaths(t *testing.T) {
	configAllSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"REDIS": {
				SecretName: "redisdb",
				SecretData: expectedSecrets,
			},
			"KONG": {
				SecretName: "kongdb",
				SecretData: expectedSecrets,
			},
		},
	}

	configMissingSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				SecretName: "redisdb",
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
			testMocks := newMockObjects()
			target := NewInsecureProvider(tc.Config, testMocks.lc, testMocks.dic)
			actual, err := target.ListSecretNames()
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
				SecretName: expectedSecretName,
				SecretData: expectedSecrets,
			},
		},
	}

	configMissingSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				SecretName: "redis",
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
		{"Valid", expectedSecretName, []string{"username", "password"}, configAllSecrets, false, true},
		{"Valid just secretName", expectedSecretName, nil, configAllSecrets, false, true},
		{"Valid - No secrets", expectedSecretName, []string{"username", "password"}, configMissingSecrets, false, false},
		{"Valid - Bad SecretName", "bogus", []string{"username", "password"}, configAllSecrets, false, false},
		{"Invalid - No Config", "bogus", []string{"username", "password"}, configNoSecrets, true, false},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			testMocks := newMockObjects()
			target := NewInsecureProvider(tc.Config, testMocks.lc, testMocks.dic)
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
				SecretName: expectedSecretName,
				SecretData: expectedSecrets,
			},
		},
	}

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
		{"Valid With Callback", configAllSecrets, expectedSecretName, callback, nil},
		{"Valid No Callbacks", configAllSecrets, expectedSecretName, nil, nil},
		{"Valid Wildcard Only", configAllSecrets, expectedSecretName, nil, wildcard},
		{"Valid With Callback and Wildcard", configAllSecrets, expectedSecretName, callback, wildcard},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			callbackCalled = false
			wildcardCalled = false
			testMocks := newMockObjects()
			target := NewInsecureProvider(tc.Config, testMocks.lc, testMocks.dic)

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

func TestInsecureProvider_RegisterSecretUpdatedCallback(t *testing.T) {
	configAllSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				SecretName: expectedSecretName,
				SecretData: expectedSecrets,
			},
		},
	}

	tests := []struct {
		Name       string
		Config     TestConfig
		SecretName string
		Callback   func(secretName string)
	}{
		{"Valid", configAllSecrets, expectedSecretName, func(secretName string) {}},
		{"Valid no callback", configAllSecrets, expectedSecretName, nil},
		{"Valid Wildcard", configAllSecrets, WildcardName, func(secretName string) {}},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			testMocks := newMockObjects()
			target := NewInsecureProvider(tc.Config, testMocks.lc, testMocks.dic)
			err := target.RegisterSecretUpdatedCallback(tc.SecretName, tc.Callback)
			assert.NoError(t, err)

			if tc.Callback != nil {
				assert.NotEmpty(t, target.registeredSecretCallbacks[tc.SecretName])
			} else {
				assert.Nil(t, target.registeredSecretCallbacks[tc.SecretName])
			}
		})
	}
}

func TestInsecureProvider_DeregisterSecretUpdatedCallback(t *testing.T) {
	configAllSecrets := TestConfig{
		InsecureSecrets: map[string]bootstrapConfig.InsecureSecretsInfo{
			"DB": {
				SecretName: expectedSecretName,
				SecretData: expectedSecrets,
			},
		},
	}

	tests := []struct {
		Name       string
		Config     TestConfig
		SecretName string
		Callback   func(secretName string)
	}{
		{"Valid", configAllSecrets, expectedSecretName, func(secretName string) {}},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			testMocks := newMockObjects()
			target := NewInsecureProvider(tc.Config, testMocks.lc, testMocks.dic)
			err := target.RegisterSecretUpdatedCallback(tc.SecretName, tc.Callback)
			assert.NoError(t, err)

			// Deregister a secret callback.
			target.DeregisterSecretUpdatedCallback(tc.SecretName)
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

func (t TestConfig) GetWritablePtr() any {
	panic("implement me")
}
