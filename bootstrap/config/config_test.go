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
package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/environment"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/flags"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/di"
	"github.com/edgexfoundry/go-mod-configuration/v4/configuration"
	"github.com/edgexfoundry/go-mod-configuration/v4/configuration/mocks"
	"github.com/edgexfoundry/go-mod-configuration/v4/pkg/types"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	expectedUsername   = "admin"
	expectedPassword   = "password"
	expectedSecretName = "redisdb"
	UsernameKey        = "username"
	PasswordKey        = "password"
)

func TestGetSecretNamesChanged(t *testing.T) {
	prevVals := config.InsecureSecrets{
		"DB": config.InsecureSecretsInfo{
			SecretName: expectedSecretName,
			SecretData: map[string]string{
				UsernameKey: "edgex",
				PasswordKey: expectedPassword,
			}}}

	curVals := config.InsecureSecrets{
		"DB": config.InsecureSecretsInfo{
			SecretName: expectedSecretName,
			SecretData: map[string]string{
				UsernameKey: expectedUsername,
				PasswordKey: expectedPassword,
			}}}

	tests := []struct {
		Name         string
		UpdatedPaths []string
		curVals      config.InsecureSecrets
		prevVals     config.InsecureSecrets
	}{
		{"Valid - No updates", nil, curVals, curVals},
		{"Valid - Secret update", []string{expectedSecretName}, prevVals, curVals},
		{"Valid - New Secret", []string{expectedSecretName}, prevVals, config.InsecureSecrets{
			"DB": config.InsecureSecretsInfo{
				SecretName: expectedSecretName,
				SecretData: map[string]string{
					UsernameKey: expectedUsername,
					PasswordKey: expectedPassword,
					"attempts":  "1",
				}}}},
		{"Valid - Deleted Secret", []string{expectedSecretName}, prevVals, config.InsecureSecrets{
			"DB": config.InsecureSecretsInfo{
				SecretName: expectedSecretName,
				SecretData: map[string]string{
					UsernameKey: expectedUsername,
				}}}},
		{"Valid - Path update", []string{"redisdb", "message-bus"}, curVals,
			config.InsecureSecrets{
				"DB": config.InsecureSecretsInfo{
					SecretName: "message-bus",
					SecretData: map[string]string{
						UsernameKey: expectedUsername,
						PasswordKey: expectedPassword,
					}}}},
		{"Valid - Path delete", []string{expectedSecretName}, config.InsecureSecrets{
			"DB": config.InsecureSecretsInfo{}}, prevVals},
		{"Valid - No updates, unsorted keys", nil, curVals, config.InsecureSecrets{
			"DB": config.InsecureSecretsInfo{
				SecretName: expectedSecretName,
				SecretData: map[string]string{
					PasswordKey: expectedPassword,
					UsernameKey: expectedUsername,
				}}}},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			updatedSecretNames := getSecretNamesChanged(tc.prevVals, tc.curVals)
			assert.Equal(t, tc.UpdatedPaths, updatedSecretNames)
		})
	}
}

func TestLoadCommonConfig(t *testing.T) {
	// set up configs for use in tests
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

	deviceConfig := ConfigurationMockStruct{
		Writable: WritableInfo{
			Telemetry: config.TelemetryInfo{
				Metrics: map[string]bool{"EventsSent": true, "ReadingsSent": true},
			},
		},
	}
	// set up errors for tests
	testErr := errors.New("test error")
	configProviderErr := "configuration provider is not available"
	loadErr := "common config is not loaded"
	getConfigErr := fmt.Sprintf("failed to load the common configuration for %s: %s", allServicesKey, testErr.Error())

	tests := []struct {
		Name                 string
		serviceConfig        *ConfigurationMockStruct
		serviceType          string
		serviceTypeConfig    *ConfigurationMockStruct
		providerClientErr    error
		isAlive              bool
		isCommonConfigReady  []byte
		commonConfigReadyErr error
		getConfigErr         error
		expectedErr          string
	}{
		{"Valid - core service", &serviceConfig, config.ServiceTypeOther, nil,
			nil, true, []byte("true"), nil, nil, ""},
		{"Valid - app service", &serviceConfig, config.ServiceTypeApp, &appConfig,
			nil, true, []byte("true"), nil, nil, ""},
		{"Valid - device service", &serviceConfig, config.ServiceTypeDevice, &deviceConfig,
			nil, true, []byte("true"), nil, nil, ""},
		{"Invalid - config provider not alive", &serviceConfig, config.ServiceTypeOther, nil,
			nil, false, []byte("false"), nil, nil, configProviderErr},
		{"Invalid - common config not ready", &serviceConfig, config.ServiceTypeOther, nil,
			nil, true, []byte("false"), nil, nil, loadErr},
		{"Invalid - common config ready parameter invalid", &serviceConfig, config.ServiceTypeOther, nil,
			nil, true, []byte("bogus"), nil, nil, loadErr},
		{"Invalid - common config not ready error", &serviceConfig, config.ServiceTypeOther, nil,
			nil, true, []byte("false"), testErr, nil, loadErr},
		{"Valid - core service", &serviceConfig, config.ServiceTypeOther, nil,
			nil, true, []byte("true"), nil, testErr, getConfigErr},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			// create parameters for the processor
			f := flags.New()
			f.Parse(nil)
			mockLogger := logger.MockLogger{}
			env := environment.NewVariables(mockLogger)
			timer := startup.NewTimer(5, 1)
			ctx, cancel := context.WithCancel(context.Background())

			wg := sync.WaitGroup{}
			dic := di.NewContainer(di.ServiceConstructorMap{
				container.LoggingClientInterfaceName: func(get di.Get) interface{} { return mockLogger },
			})
			// create the processor
			proc := NewProcessor(f, env, timer, ctx, &wg, nil, dic)
			// set up mocks
			providerClientMock := &mocks.Client{}
			providerClientCreator := func(logger.LoggingClient,
				string,
				string,
				types.ServiceConfig) (configuration.Client, error) {
				return providerClientMock, tc.providerClientErr
			}
			providerClientMock.On("IsAlive").Return(tc.isAlive)
			serviceConfigMock := ConfigurationMockStruct{}
			if tc.isAlive {
				providerClientMock.On("GetConfigurationValueByFullPath", common.ConfigStemAll+"/core-common-config-bootstrapper/IsCommonConfigReady").Return(tc.isCommonConfigReady, tc.commonConfigReadyErr)
			}
			ccReady, err := strconv.ParseBool(string(tc.isCommonConfigReady))
			if err == nil && ccReady {
				providerClientMock.On("GetConfiguration", &serviceConfigMock).Return(tc.serviceConfig, tc.getConfigErr).Once()
			}
			if tc.serviceType == config.ServiceTypeApp || tc.serviceType == config.ServiceTypeDevice {
				providerClientMock.On("GetConfiguration", &serviceConfigMock).Return(tc.serviceTypeConfig, tc.getConfigErr).Once()
				var configKeys []string
				switch tc.serviceType {
				case config.ServiceTypeApp:
					configKeys = []string{
						common.ConfigStemAll + "/core-common-config-bootstrapper/app-services/Writable/StoreAndForward/Enabled",
						common.ConfigStemAll + "/core-common-config-bootstrapper/app-services/Writable/StoreAndForward/RetryInterval",
						common.ConfigStemAll + "/core-common-config-bootstrapper/app-services/Writable/StoreAndForward/MaxRetryCount",
					}
				case config.ServiceTypeDevice:
					configKeys = []string{
						common.ConfigStemAll + "/core-common-config-bootstrapper/device-services/Writable/Telemetry/Metrics/EventsSent",
						common.ConfigStemAll + "/core-common-config-bootstrapper/device-services/Writable/Telemetry/Metrics/ReadingsSent",
					}
				}

				providerClientMock.On("GetConfigurationKeys", mock.Anything).Return(configKeys, nil).Once()
			}
			// call load common config
			err = proc.loadCommonConfig(common.ConfigStemAll, &ProviderInfo{}, &serviceConfigMock, tc.serviceType, providerClientCreator)
			// make assertions
			providerClientMock.AssertExpectations(t)
			require.NotNil(t, cancel)
			if tc.expectedErr == "" {
				assert.NoError(t, err)
				assert.NotNil(t, serviceConfigMock.Writable.LogLevel)
				switch tc.serviceType {
				case config.ServiceTypeApp:
					assert.True(t, serviceConfigMock.Writable.StoreAndForward.Enabled)
					assert.NotEmpty(t, serviceConfigMock.Writable.StoreAndForward.RetryInterval)
					assert.NotZero(t, serviceConfigMock.Writable.StoreAndForward.MaxRetryCount)
				case config.ServiceTypeDevice:
					assert.True(t, serviceConfigMock.Writable.Telemetry.Metrics["EventsSent"])
					assert.True(t, serviceConfigMock.Writable.Telemetry.Metrics["ReadingsSent"])
				}
				return
			}
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

func TestLoadCommonConfigFromFile(t *testing.T) {
	tests := []struct {
		Name          string
		config        string
		serviceConfig *ConfigurationMockStruct
		serviceType   string
		expectedErr   string
	}{
		{"Valid - core service", path.Join(".", "testdata", "configuration.yaml"), &ConfigurationMockStruct{}, config.ServiceTypeOther, ""},
		{"Valid - app service", path.Join(".", "testdata", "configuration.yaml"), &ConfigurationMockStruct{}, config.ServiceTypeApp, ""},
		{"Valid - device service", path.Join(".", "testdata", "configuration.yaml"), &ConfigurationMockStruct{}, config.ServiceTypeDevice, ""},
		{"Invalid - bad config file", path.Join(".", "testdata", "bad_config.yaml"), &ConfigurationMockStruct{}, config.ServiceTypeOther, "no such file or directory"},
		{"Invalid - missing all service", path.Join(".", "testdata", "bogus.yaml"), &ConfigurationMockStruct{}, config.ServiceTypeOther, "could not find all-services section in common config"},
		{"Invalid - missing app service", path.Join(".", "testdata", "all-service-config.yaml"), &ConfigurationMockStruct{}, config.ServiceTypeApp, fmt.Sprintf("could not find %s section in common config", appServicesKey)},
		{"Invalid - missing device service", path.Join(".", "testdata", "all-service-config.yaml"), &ConfigurationMockStruct{}, config.ServiceTypeDevice, fmt.Sprintf("could not find %s section in common config", deviceServicesKey)},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			// create parameters for the processor
			f := flags.New()
			f.Parse(nil)
			mockLogger := logger.MockLogger{}
			env := environment.NewVariables(mockLogger)
			timer := startup.NewTimer(5, 1)
			ctx, cancel := context.WithCancel(context.Background())

			wg := sync.WaitGroup{}
			dic := di.NewContainer(di.ServiceConstructorMap{
				container.LoggingClientInterfaceName: func(get di.Get) interface{} { return mockLogger },
			})
			// create the processor
			proc := NewProcessor(f, env, timer, ctx, &wg, nil, dic)

			// call load common config
			err := proc.loadCommonConfigFromFile(tc.config, tc.serviceConfig, tc.serviceType)
			// make assertions
			require.NotNil(t, cancel)
			if tc.expectedErr == "" {
				assert.NoError(t, err)
				assert.NotEmpty(t, tc.serviceConfig)
				return
			}
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

func TestFindChangedKey(t *testing.T) {
	previousConfig := ConfigurationMockStruct{
		Writable: WritableInfo{
			Telemetry: config.TelemetryInfo{
				Interval: "30s",
			},
		},
	}

	previousWritable := previousConfig.GetWritablePtr()

	noUpdatesWritable := previousConfig.GetWritablePtr()

	updatedConfigNeyKey := ConfigurationMockStruct{
		Writable: WritableInfo{
			Telemetry: config.TelemetryInfo{
				Interval: "30s",
				Metrics:  map[string]bool{"NewKey": true},
			},
		},
	}
	updatedWritableNewKey := updatedConfigNeyKey.GetWritablePtr()

	valueChangedConfig := previousConfig
	valueChangedConfig.Writable.Telemetry.Interval = "45s"

	valueChangedConfigWritable := valueChangedConfig.GetWritablePtr()

	tests := []struct {
		Name          string
		previous      any
		updated       any
		expectedFound bool
		expectedKey   string
	}{
		{"happy path - Value changed", previousWritable, valueChangedConfigWritable, true, "Telemetry/Interval"},
		{"happy path - new key in map", previousWritable, updatedWritableNewKey, true, "Telemetry/Metrics/NewKey"},
		{"happy path - key removed from map", updatedWritableNewKey, previousWritable, true, "Telemetry/Metrics"},
		{"happy path - No Updates", previousWritable, noUpdatesWritable, false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			f := flags.New()
			f.Parse(nil)
			mockLogger := logger.MockLogger{}
			env := environment.NewVariables(mockLogger)
			timer := startup.NewTimer(5, 1)
			ctx, cancel := context.WithCancel(context.Background())
			wg := sync.WaitGroup{}
			dic := di.NewContainer(di.ServiceConstructorMap{
				container.LoggingClientInterfaceName: func(get di.Get) interface{} { return mockLogger },
			})

			// create the processor
			proc := NewProcessor(f, env, timer, ctx, &wg, nil, dic)
			// set up mocks
			actualKey, actualFound := proc.findChangedKey(tc.previous, tc.updated)
			assert.Equal(t, tc.expectedFound, actualFound)
			assert.Equal(t, tc.expectedKey, actualKey)
			require.NotNil(t, cancel)
		})
	}
}

func TestGetConfigFileLocation(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		profile    string
		path       string
		secretName string
		expected   string
	}{
		{
			name:     "valid - file",
			dir:      "myRes",
			profile:  "myProfile",
			path:     "myFile.yaml",
			expected: filepath.Join("myRes", "myProfile", "myFile.yaml"),
		},
		{
			name:     "valid - file absolute path",
			dir:      "/myRes",
			profile:  "myProfile",
			path:     "myFile.yaml",
			expected: "/myRes/myProfile/myFile.yaml",
		},
		{
			name:     "valid - file relative path",
			dir:      "../../myRes",
			profile:  "myProfile",
			path:     "myFile.yaml",
			expected: "../../myRes/myProfile/myFile.yaml",
		},
		{
			name:     "valid - url",
			dir:      "",
			profile:  "",
			path:     "https://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/testdata/configuration.yaml",
			expected: "https://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/testdata/configuration.yaml",
		},
		{
			name:     "invalid - url",
			dir:      "",
			profile:  "",
			path:     "{test:\"test\"}",
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.secretName, func(t *testing.T) {
			lc := logger.NewMockClient()
			flags := flags.New()

			defer os.Clearenv()
			os.Setenv("EDGEX_CONFIG_DIR", test.dir)
			os.Setenv("EDGEX_PROFILE", test.profile)
			os.Setenv("EDGEX_CONFIG_FILE", test.path)

			actual := GetConfigFileLocation(lc, flags)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestGetInsecureSecretNameFullPath(t *testing.T) {
	tests := []struct {
		secretName string
		expected   string
	}{
		{
			secretName: "credentials001",
			expected:   writableKey + "/" + insecureSecretsKey + "/credentials001/" + secretNameKey,
		},
		{
			secretName: "my-secret",
			expected:   writableKey + "/" + insecureSecretsKey + "/my-secret/" + secretNameKey,
		},
	}
	for _, test := range tests {
		t.Run(test.secretName, func(t *testing.T) {
			actual := GetInsecureSecretNameFullPath(test.secretName)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestGetInsecureSecretDataFullPath(t *testing.T) {
	tests := []struct {
		secretName string
		key        string
		expected   string
	}{
		{
			secretName: "credentials001",
			key:        "username",
			expected:   writableKey + "/" + insecureSecretsKey + "/credentials001/" + secretDataKey + "/username",
		},
		{
			secretName: "credentials001",
			key:        "password",
			expected:   writableKey + "/" + insecureSecretsKey + "/credentials001/" + secretDataKey + "/password",
		},
		{
			secretName: "my-secret",
			key:        "password",
			expected:   writableKey + "/" + insecureSecretsKey + "/my-secret/" + secretDataKey + "/password",
		},
	}
	for _, test := range tests {
		t.Run(test.secretName+"_"+test.key, func(t *testing.T) {
			actual := GetInsecureSecretDataFullPath(test.secretName, test.key)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestProcessorApplyRemoteHosts(t *testing.T) {
	mockStruct := ConfigurationMockStruct{
		Registry:   config.RegistryInfo{},
		Service:    config.ServiceInfo{},
		MessageBus: config.MessageBusInfo{},
		Clients: config.ClientsCollection{
			"core-metadata": {},
		},
		Database: config.Database{},
		Config:   config.ConfigProviderInfo{},
	}

	localIP := "1.2.3.4"
	remoteIP := "5.6.7.8"
	srvBindIP := "localhost"
	hosts := []string{localIP, remoteIP, srvBindIP}
	err := applyRemoteHosts(hosts, &mockStruct)
	require.NoError(t, err)

	assert.Equal(t, localIP, mockStruct.Service.Host)
	assert.Equal(t, srvBindIP, mockStruct.Service.ServerBindAddr)
	assert.Equal(t, remoteIP, mockStruct.Clients["core-metadata"].Host)
	assert.Equal(t, remoteIP, mockStruct.Database.Host)
	assert.Equal(t, remoteIP, mockStruct.MessageBus.Host)
	assert.Equal(t, remoteIP, mockStruct.Registry.Host)
	assert.Equal(t, remoteIP, mockStruct.Config.Host)

	hosts = []string{localIP, remoteIP}
	err = applyRemoteHosts(hosts, &mockStruct)
	require.Error(t, err)
}
