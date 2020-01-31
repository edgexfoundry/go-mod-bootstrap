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
	"fmt"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"os"
	"strconv"

	"github.com/edgexfoundry/go-mod-bootstrap/config"

	"github.com/edgexfoundry/go-mod-configuration/pkg/types"
)

const (
	envKeyUrl             = "edgex_configuration_provider"
	envKeyStartupDuration = "startup_duration"
	envKeyStartupInterval = "startup_interval"
)

// OverrideConfigProviderInfoFromEnvironment overrides the Configuration Provider ServiceConfig values
// from an environment variable value (if it exists).
func OverrideConfigProviderInfoFromEnvironment(
	lc logger.LoggingClient,
	configProviderInfo types.ServiceConfig) (types.ServiceConfig, error) {

	//	Override the configuration provider info, if provided.
	if env := os.Getenv(envKeyUrl); env != "" {
		lc.Info(fmt.Sprintf("Overriding Confiuragtion Provider information from environment variable. %s=%s", envKeyUrl, env))

		if err := configProviderInfo.PopulateFromUrl(env); err != nil {
			return types.ServiceConfig{}, err
		}
	}

	return configProviderInfo, nil
}

// OverrideStartupInfoFromEnvironment overrides the Service StartupInfo values from an environment variable value (if it exists).
func OverrideStartupInfoFromEnvironment(
	lc logger.LoggingClient,
	startup config.StartupInfo) config.StartupInfo {

	//	Override the startup timer configuration, if provided.
	if env := os.Getenv(envKeyStartupDuration); env != "" {
		lc.Info(fmt.Sprintf("Overriding startup duration from environment variable. %s=%s", envKeyStartupDuration, env))

		if n, err := strconv.ParseInt(env, 10, 0); err == nil && n > 0 {
			startup.Duration = int(n)
		}
	}

	//	Override the startup timer interval, if provided.
	if env := os.Getenv(envKeyStartupInterval); env != "" {
		lc.Info(fmt.Sprintf("Overriding startup interval from environment variable. %s=%s", envKeyStartupInterval, env))

		if n, err := strconv.ParseInt(env, 10, 0); err == nil && n > 0 {
			startup.Interval = int(n)
		}
	}

	return startup
}
