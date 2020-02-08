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
	"os"
	"testing"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/logging"
	"github.com/edgexfoundry/go-mod-bootstrap/config"

	"github.com/edgexfoundry/go-mod-configuration/pkg/types"

	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"

	"github.com/stretchr/testify/assert"
)

const (
	goodUrlValue = "consul.http://localhost:8500"
	badUrlValue  = "Not a url"

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

func TestEnvVariableUpdatesConfigProviderInfo(t *testing.T) {
	providerConfig, _, lc := initializeTest()

	if err := os.Setenv(envKeyUrl, goodUrlValue); err != nil {
		t.Fail()
	}

	providerConfig, err := OverrideConfigProviderInfoFromEnvironment(lc, providerConfig)

	assert.NoError(t, err, "Unexpected error")
	assert.Equal(t, providerConfig.Host, expectedHostValue)
	assert.Equal(t, providerConfig.Port, expectedPortValue)
	assert.Equal(t, providerConfig.Type, expectedTypeValue)
	assert.Equal(t, providerConfig.Protocol, expectedProtocolValue)
}

func TestNoEnvVariableDoesNotUpdateConfigProviderInfo(t *testing.T) {
	providerConfig, _, lc := initializeTest()

	providerConfig, err := OverrideConfigProviderInfoFromEnvironment(lc, providerConfig)

	assert.NoError(t, err, "Unexpected error")
	assert.Equal(t, providerConfig.Host, defaultHostValue)
	assert.Equal(t, providerConfig.Port, defaultPortValue)
	assert.Equal(t, providerConfig.Type, defaultTypeValue)
	assert.Equal(t, providerConfig.Protocol, defaultProtocolValue)
}

func TestEnvVariableUpdateConfigProviderInfoError(t *testing.T) {
	providerConfig, _, lc := initializeTest()

	if err := os.Setenv(envKeyUrl, badUrlValue); err != nil {
		t.Fail()
	}

	_, err := OverrideConfigProviderInfoFromEnvironment(lc, providerConfig)

	assert.Error(t, err, "Expected an error")
}

func TestEnvVariableUpdatesStartupInfo(t *testing.T) {
	_, startupInfo, lc := initializeTest()

	if err := os.Setenv(envKeyStartupDuration, envStartupDuration); err != nil {
		t.Fail()
	}
	if err := os.Setenv(envKeyStartupInterval, envStartupInterval); err != nil {
		t.Fail()
	}

	startupInfo = OverrideStartupInfoFromEnvironment(lc, startupInfo)

	assert.Equal(t, startupInfo.Duration, expectedStartupDuration)
	assert.Equal(t, startupInfo.Interval, expectedStartupInterval)
}

func TestNoEnvVariableDoesNotUpdateSetupInfo(t *testing.T) {
	_, startupInfo, lc := initializeTest()

	startupInfo = OverrideStartupInfoFromEnvironment(lc, startupInfo)

	assert.Equal(t, startupInfo.Duration, defaultStartupDuration)
	assert.Equal(t, startupInfo.Interval, defaultStartupInterval)
}
