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

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/logging"

	"github.com/stretchr/testify/assert"
)

func TestNewConfigProviderInfoUrl(t *testing.T) {
	lc := logging.FactoryToStdout("unit-test")

	target, err := NewProviderInfo(lc, goodUrlValue)
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

	if err := os.Setenv(envKeyUrl, goodUrlValue); err != nil {
		t.Fail()
	}

	target, err := NewProviderInfo(lc, goodUrlValue)
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

	_, err := NewProviderInfo(lc, badUrlValue)
	if !assert.Error(t, err, "Expected an error") {
		t.Fatal()
	}
}

func TestNewConfigProviderInfoBadEnvUrl(t *testing.T) {
	lc := logging.FactoryToStdout("unit-test")

	if err := os.Setenv(envKeyUrl, badUrlValue); err != nil {
		t.Fail()
	}

	_, err := NewProviderInfo(lc, goodUrlValue)
	if !assert.Error(t, err, "Expected an error") {
		t.Fatal()
	}
}
