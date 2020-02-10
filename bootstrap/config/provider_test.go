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

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/logging"
)

func TestNewConfigProviderInfoUrl(t *testing.T) {
	lc := logging.FactoryToStdout("unit-test")

	env := NewEnvironment()
	target, err := NewProviderInfo(lc, env, goodUrlValue)
	if !assert.NoError(t, err, "unexpected error") {
		t.Fatal()
	}

	actual := target.ServiceConfig()

	assert.Equal(t, expectedTypeValue, actual.Type)
	assert.Equal(t, expectedProtocolValue, actual.Protocol)
	assert.Equal(t, expectedHostValue, actual.Host)
	assert.Equal(t, expectedPortValue, actual.Port)
}

func TestNewConfigProviderInfoEnv(t *testing.T) {
	lc := logging.FactoryToStdout("unit-test")

	if err := os.Setenv(envKeyConfigUrl, goodUrlValue); err != nil {
		t.Fail()
	}

	env := NewEnvironment()
	target, err := NewProviderInfo(lc, env, goodUrlValue)
	if !assert.NoError(t, err, "unexpected error") {
		t.Fatal()
	}

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
	if !assert.Error(t, err, "Expected an error") {
		t.Fatal()
	}
}

func TestNewConfigProviderInfoBadEnvUrl(t *testing.T) {
	lc := logging.FactoryToStdout("unit-test")

	if err := os.Setenv(envKeyConfigUrl, badUrlValue); err != nil {
		t.Fail()
	}

	env := NewEnvironment()
	_, err := NewProviderInfo(lc, env, goodUrlValue)
	if !assert.Error(t, err, "Expected an error") {
		t.Fatal()
	}
}
