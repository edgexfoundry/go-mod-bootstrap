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

package commandline

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDefaultCommonFlagsAllFlags(t *testing.T) {
	expectedUseRegistry := true
	expectedConfigProviderUrl := "consul.http://localhost:8500"
	expectedProfile := "docker"
	expectedConfigDirectory := "/res"
	expectedFileName := "config.toml"

	var arguments []string
	arguments = append(arguments, "-r")
	arguments = append(arguments, "-cp="+expectedConfigProviderUrl)
	arguments = append(arguments, "-p="+expectedProfile)
	arguments = append(arguments, "-confdir="+expectedConfigDirectory)
	arguments = append(arguments, "-f="+expectedFileName)

	actual := NewDefaultCommonFlags("")
	actual.Parse(arguments)

	assert.Equal(t, expectedUseRegistry, actual.UseRegistry())
	assert.Equal(t, expectedConfigProviderUrl, actual.ConfigProviderUrl())
	assert.Equal(t, expectedProfile, actual.Profile())
	assert.Equal(t, expectedConfigDirectory, actual.ConfigDirectory())
	assert.Equal(t, expectedFileName, actual.ConfigFileName())
}

func TestNewDefaultCommonFlagsDefaultsNoFlags(t *testing.T) {
	expectedUseRegistry := false
	expectedConfigProviderUrl := ""
	expectedProfile := ""
	expectedConfigDirectory := ""
	expectedFileName := "configuration.toml"

	var arguments []string

	actual := NewDefaultCommonFlags("")
	actual.Parse(arguments)

	assert.Equal(t, expectedUseRegistry, actual.UseRegistry())
	assert.Equal(t, expectedConfigProviderUrl, actual.ConfigProviderUrl())
	assert.Equal(t, expectedProfile, actual.Profile())
	assert.Equal(t, expectedConfigDirectory, actual.ConfigDirectory())
	assert.Equal(t, expectedFileName, actual.ConfigFileName())
}

func TestNewDefaultCommonFlagsDefaultForCP(t *testing.T) {
	expectedConfigProviderUrl := "consul.http://localhost:8500"

	var arguments []string
	arguments = append(arguments, "-cp")

	actual := NewDefaultCommonFlags("")
	actual.Parse(arguments)
	assert.Equal(t, expectedConfigProviderUrl, actual.ConfigProviderUrl())
}

func TestNewDefaultCommonFlagsOverrideForCP(t *testing.T) {
	expectedConfigProviderUrl := "consul.http://docker-core-consul:8500"

	var arguments []string
	arguments = append(arguments, "-cp="+expectedConfigProviderUrl)

	actual := NewDefaultCommonFlags("")
	actual.Parse(arguments)
	assert.Equal(t, expectedConfigProviderUrl, actual.ConfigProviderUrl())
}

func TestNewDefaultCommonFlagsDefaultForConfigProvider(t *testing.T) {
	expectedConfigProviderUrl := "consul.http://localhost:8500"

	var arguments []string
	arguments = append(arguments, "-configProvider")

	actual := NewDefaultCommonFlags("")
	actual.Parse(arguments)
	assert.Equal(t, expectedConfigProviderUrl, actual.ConfigProviderUrl())
}

func TestNewDefaultCommonFlagsOverrideConfigProvider(t *testing.T) {
	expectedConfigProviderUrl := "consul.http://docker-core-consul:8500"

	var arguments []string
	arguments = append(arguments, "-configProvider="+expectedConfigProviderUrl)

	actual := NewDefaultCommonFlags("")
	actual.Parse(arguments)
	assert.Equal(t, expectedConfigProviderUrl, actual.ConfigProviderUrl())
}
