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

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/logging"
)

func TestNewConfigProviderInfoUrl(t *testing.T) {
	lc := logging.FactoryToStdout("unit-test")

	env := NewEnvironment()
	target, err := NewProviderInfo(lc, env, goodUrlValue)
	require.NoError(t, err)

	actual := target.ServiceConfig()

	assert.Equal(t, expectedTypeValue, actual.Type)
	assert.Equal(t, expectedProtocolValue, actual.Protocol)
	assert.Equal(t, expectedHostValue, actual.Host)
	assert.Equal(t, expectedPortValue, actual.Port)
}

func TestNewConfigProviderInfoEnv(t *testing.T) {
	lc := logging.FactoryToStdout("unit-test")

	err := os.Setenv(envKeyConfigUrl, goodUrlValue)
	require.NoError(t, err)

	env := NewEnvironment()
	target, err := NewProviderInfo(lc, env, goodUrlValue)
	require.NoError(t, err)

	actual := target.ServiceConfig()

	assert.Equal(t, expectedTypeValue, actual.Type)
	assert.Equal(t, expectedProtocolValue, actual.Protocol)
	assert.Equal(t, expectedHostValue, actual.Host)
	assert.Equal(t, expectedPortValue, actual.Port)
}

func TestNewConfigProviderInfoBadUrl(t *testing.T) {
	lc := logging.FactoryToStdout("unit-test")

	env := NewEnvironment()
	_, err := NewProviderInfo(lc, env, badUrlValue)
	assert.Error(t, err)
}

func TestNewConfigProviderInfoBadEnvUrl(t *testing.T) {
	lc := logging.FactoryToStdout("unit-test")

	// This should override the goodUrlValue below
	err := os.Setenv(envKeyConfigUrl, badUrlValue)
	require.NoError(t, err)

	env := NewEnvironment()
	_, err = NewProviderInfo(lc, env, goodUrlValue)
	assert.Error(t, err)
}
