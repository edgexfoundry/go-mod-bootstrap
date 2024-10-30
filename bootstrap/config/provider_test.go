/*******************************************************************************
 * Copyright 2020 Intel Corp.
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/environment"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
)

const (
	envKeyConfigUrl = "EDGEX_CONFIG_PROVIDER"
	goodUrlValue    = "keeper.http://localhost:59890"
	badUrlValue     = "Not a url"

	expectedTypeValue     = "keeper"
	expectedHostValue     = "localhost"
	expectedPortValue     = 59890
	expectedProtocolValue = "http"
)

func TestNewConfigProviderInfoUrl(t *testing.T) {
	lc := logger.NewMockClient()

	envVars := environment.NewVariables(lc)
	target, err := NewProviderInfo(envVars, goodUrlValue)
	require.NoError(t, err)

	actual := target.ServiceConfig()

	assert.Equal(t, expectedTypeValue, actual.Type)
	assert.Equal(t, expectedProtocolValue, actual.Protocol)
	assert.Equal(t, expectedHostValue, actual.Host)
	assert.Equal(t, expectedPortValue, actual.Port)
}

func TestNewConfigProviderInfoEnv(t *testing.T) {
	lc := logger.NewMockClient()

	err := os.Setenv(envKeyConfigUrl, goodUrlValue)
	require.NoError(t, err)

	envVars := environment.NewVariables(lc)
	target, err := NewProviderInfo(envVars, goodUrlValue)
	require.NoError(t, err)

	actual := target.ServiceConfig()

	assert.Equal(t, expectedTypeValue, actual.Type)
	assert.Equal(t, expectedProtocolValue, actual.Protocol)
	assert.Equal(t, expectedHostValue, actual.Host)
	assert.Equal(t, expectedPortValue, actual.Port)
}

func TestNewConfigProviderInfoBadUrl(t *testing.T) {
	lc := logger.NewMockClient()

	envVars := environment.NewVariables(lc)
	_, err := NewProviderInfo(envVars, badUrlValue)
	assert.Error(t, err)
}

func TestNewConfigProviderInfoBadEnvUrl(t *testing.T) {
	lc := logger.NewMockClient()

	// This should override the goodUrlValue below
	err := os.Setenv(envKeyConfigUrl, badUrlValue)
	require.NoError(t, err)

	envVars := environment.NewVariables(lc)
	_, err = NewProviderInfo(envVars, goodUrlValue)
	assert.Error(t, err)
}
