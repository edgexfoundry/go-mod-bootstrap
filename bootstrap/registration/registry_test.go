//
// Copyright (c) 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package registration

import (
	"testing"

	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"github.com/edgexfoundry/go-mod-registry/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/environment"
	"github.com/edgexfoundry/go-mod-bootstrap/config"
)

// TODO: Remove RegistryUrl parts for release v2.0.0 when -registry is a bool
func TestCreateRegistryClient(t *testing.T) {
	lc := logger.NewClientStdOut("unit-test", false, "TRACE")
	tests := []struct {
		Name          string
		RegistryUrl   string
		ExpectedError string
	}{
		{
			Name:        "Success - blank url",
			RegistryUrl: "",
		},
		{
			Name:        "Success - with url",
			RegistryUrl: "consul://localhost:8500",
		},
		{
			Name:        "Success - with dot url",
			RegistryUrl: ".",
		},
		{
			Name:          "Failure - bad url",
			RegistryUrl:   "not a url",
			ExpectedError: "failed to parse Registry Provider URL (not a url):",
		},
		{
			Name:          "Failure - RegistryUrl Missing port",
			RegistryUrl:   "consul://localhost",
			ExpectedError: "failed to parse Registry Provider URL (consul://localhost): strconv.Atoi:",
		},
	}

	serviceConfig := unitTestConfiguration{
		Service: config.ServiceInfo{
			Host:     "localhost",
			Port:     8080,
			Protocol: "http",
		},
		Registry: config.RegistryInfo{
			Host: "localhost",
			Port: 8500,
			Type: "consul",
		},
	}

	envVars := environment.NewVariables()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			actual, err := createRegistryClient("unit-test", serviceConfig, test.RegistryUrl, envVars, lc)
			if len(test.ExpectedError) > 0 {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedError)
				return // test complete
			}

			require.NoError(t, err)
			assert.NotNil(t, actual)
		})
	}
}

// TODO: Remove this test for release v2.0.0 when -registry is a bool
func TestOverrideRegistryConfigWithUrl(t *testing.T) {

	tests := []struct {
		Name          string
		RegistryUrl   string
		Expected      types.Config
		ExpectedError string
	}{
		{
			Name:        "Success - Good URL",
			RegistryUrl: "consul://localhost:8500",
			Expected: types.Config{
				Type:     "consul",
				Protocol: "http",
				Host:     "localhost",
				Port:     8500,
			},
		},
		{
			Name:          "Error - Bad URL",
			RegistryUrl:   "not a url",
			ExpectedError: "failed to parse Registry Provider URL (not a url):",
		},
		{
			Name:          "Error - RegistryUrl Missing port",
			RegistryUrl:   "consul://localhost",
			ExpectedError: "failed to parse Registry Provider URL (consul://localhost): strconv.Atoi:",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			actual, err := OverrideRegistryConfigWithUrl(types.Config{}, test.RegistryUrl)
			if len(test.ExpectedError) > 0 {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedError)
				return // test complete
			}

			require.NoError(t, err)
			assert.Equal(t, test.Expected, actual)
		})
	}
}

type unitTestConfiguration struct {
	Service  config.ServiceInfo
	Registry config.RegistryInfo
}

func (ut unitTestConfiguration) GetInsecureSecrets() config.InsecureSecrets {
	return nil
}

func (ut unitTestConfiguration) UpdateFromRaw(rawConfig interface{}) bool {
	panic("should not be called")
}

func (ut unitTestConfiguration) EmptyWritablePtr() interface{} {
	panic("should not be called")
}

func (ut unitTestConfiguration) UpdateWritableFromRaw(rawWritable interface{}) bool {
	panic("should not be called")
}

func (ut unitTestConfiguration) GetBootstrap() config.BootstrapConfiguration {
	return config.BootstrapConfiguration{
		Service:  ut.Service,
		Registry: ut.Registry,
	}
}

func (ut unitTestConfiguration) GetLogLevel() string {
	return "TRACE"
}

func (ut unitTestConfiguration) GetRegistryInfo() config.RegistryInfo {
	return ut.Registry
}
