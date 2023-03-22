/*******************************************************************************
 * Copyright 2022 Intel Corp.
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
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/utils"
	"github.com/stretchr/testify/mock"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/environment"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/flags"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/di"
	"github.com/edgexfoundry/go-mod-configuration/v3/configuration"
	"github.com/edgexfoundry/go-mod-configuration/v3/configuration/mocks"
	"github.com/edgexfoundry/go-mod-configuration/v3/pkg/types"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/common"
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
	getAccessToken := func() (string, error) {
		return "", nil
	}
	// set up configs for use in tests
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
				types.GetAccessTokenCallback,
				types.ServiceConfig) (configuration.Client, error) {
				return providerClientMock, tc.providerClientErr
			}
			providerClientMock.On("IsAlive").Return(tc.isAlive)
			serviceConfigMock := ConfigurationMockStruct{}
			if tc.isAlive {
				providerClientMock.On("GetConfigurationValueByFullPath", "edgex/v3/core-common-config-bootstrapper/IsCommonConfigReady").Return(tc.isCommonConfigReady, tc.commonConfigReadyErr)
			}
			ccReady, err := strconv.ParseBool(string(tc.isCommonConfigReady))
			if err == nil && ccReady {
				providerClientMock.On("GetConfiguration", &serviceConfigMock).Return(tc.serviceConfig, tc.getConfigErr).Once()
			}
			if tc.serviceType == config.ServiceTypeApp || tc.serviceType == config.ServiceTypeDevice {
				providerClientMock.On("GetConfiguration", &serviceConfigMock).Return(tc.serviceTypeConfig, tc.getConfigErr).Once()
			}
			// call load common config
			err = proc.loadCommonConfig(common.ConfigStemAll, getAccessToken, &ProviderInfo{}, &serviceConfigMock, tc.serviceType, providerClientCreator)
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
	utils.RemoveZeroValues(configMap)

	assert.Len(t, configMap, 1)
	assert.Len(t, configMap["Registry"], 2)
	regMap := configMap["Registry"].(map[string]interface{})
	assert.NotEmpty(t, regMap["Host"])
	assert.NotZero(t, regMap["Port"])
}

func TestIsPrivateConfig(t *testing.T) {
	commonConfig := ConfigurationMockStruct{
		Writable: WritableInfo{
			Telemetry: config.TelemetryInfo{
				Interval: "30s",
			},
		},
	}
	commonWritable := commonConfig.GetWritablePtr()

	updatedCommonConfig := ConfigurationMockStruct{
		Writable: WritableInfo{
			Telemetry: config.TelemetryInfo{
				Interval: "10s",
			},
		},
	}
	updatedCommonWritable := updatedCommonConfig.GetWritablePtr()

	updatedCommonKeyConfig := ConfigurationMockStruct{
		Writable: WritableInfo{
			Telemetry: config.TelemetryInfo{
				Interval: "30s",
				Metrics:  map[string]bool{"NewKey": true},
			},
		},
	}
	updatedCommonKeyWritable := updatedCommonKeyConfig.GetWritablePtr()

	tests := []struct {
		Name        string
		previous    any
		updated     any
		privateKeys []string
		expectedOut bool
	}{
		{"happy path - updated key in common", commonWritable, updatedCommonWritable, []string{strings.Join([]string{writableKey, "Telemetry", "Metrics", "bogus"}, "/")}, false},
		{"happy path - new key in common", commonWritable, updatedCommonKeyWritable, nil, false},
		{"happy path - remove in common", updatedCommonKeyWritable, commonWritable, nil, false},
		{"happy path - updated override privateKeys", commonWritable, updatedCommonWritable, []string{strings.Join([]string{writableKey, "Telemetry", "Interval"}, "/")}, true},
		// new key in common - already exists in privateKeys
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
			providerClientMock := &mocks.Client{}
			providerClientMock.On("GetConfigurationKeys", mock.Anything, mock.Anything).Return(tc.privateKeys, nil)

			// create the processor
			proc := NewProcessor(f, env, timer, ctx, &wg, nil, dic)
			// set up mocks
			result := proc.isPrivateOverride(tc.previous, tc.updated, providerClientMock)
			require.Equal(t, tc.expectedOut, result)
			providerClientMock.AssertExpectations(t)
			require.NotNil(t, cancel)
		})
	}
}
