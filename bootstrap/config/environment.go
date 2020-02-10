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
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/edgexfoundry/go-mod-configuration/pkg/types"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"github.com/pelletier/go-toml"

	"github.com/edgexfoundry/go-mod-bootstrap/config"
)

const (
	envKeyConfigUrl       = "EDGEX_CONFIGURATION_PROVIDER"
	envKeyRegistryUrl     = "edgex_registry"   // TODO: Remove for v2.0.0
	envKeyStartupDuration = "startup_duration" // TODO: Change to EDGEX_STARTUP_DURATION for v2.0.0
	envKeyStartupInterval = "startup_interval" // TODO: Change to EDGEX_STARTUP_INTERVAL for v2.0.0
)

// Environment is receiver that holds Environment variables and encapsulates toml.Tree-based configuration field
// overrides.  Assumes "_" embedded in Environment variable key separates substructs; e.g. foo_bar_baz might refer to
//
// 		type foo struct {
// 			bar struct {
//          	baz string
//  		}
//		}
type Environment struct {
	env map[string]string
}

// NewEnvironment constructor reads/stores os.Environ() for use by Environment receiver methods.
func NewEnvironment() *Environment {
	osEnv := os.Environ()
	e := &Environment{
		env: make(map[string]string, len(osEnv)),
	}
	for _, env := range osEnv {
		kv := strings.Split(env, "=")
		if len(kv) == 2 && len(kv[0]) > 0 && len(kv[1]) > 0 {
			e.env[kv[0]] = kv[1]
		}
	}
	return e
}

// UseRegistry returns whether the envKeyRegistryUrl key is set
// TODO: remove this func for release v2.0.0 when envKeyRegistryUrl is removed
func (e *Environment) UseRegistry() bool {
	_, ok := os.LookupEnv(envKeyRegistryUrl)
	return ok
}

// OverrideConfiguration method replaces values in the configuration for matching Environment variable keys.
// serviceConfig must be pointer to the service configuration.
func (e *Environment) OverrideConfiguration(lc logger.LoggingClient, serviceConfig interface{}) (int, error) {
	var overrideCount = 0

	contents, err := toml.Marshal(reflect.ValueOf(serviceConfig).Elem().Interface())
	if err != nil {
		return 0, err
	}

	configTree, err := toml.LoadBytes(contents)
	if err != nil {
		return 0, err
	}

	for envVar, envValue := range e.env {
		key := strings.Replace(envVar, "_", ".", -1)
		switch {
		case configTree.Has(key):
			oldValue := configTree.Get(key)

			newValue, err := e.convertToType(oldValue, envValue)
			if err != nil {
				return 0, fmt.Errorf("environment value override failed for %s=%s: %s", envVar, envValue, err.Error())
			}

			configTree.Set(key, newValue)
			overrideCount++
			lc.Info(fmt.Sprintf("Environment varable override of %s by: %s=%s", key, envVar, envValue))
		}
	}

	// Put the configuration back into the services configuration struct with the overridden values
	err = configTree.Unmarshal(serviceConfig)
	if err != nil {
		return 0, fmt.Errorf("could not marshal toml configTree to configuration: %s", err.Error())
	}

	return overrideCount, nil
}

// OverrideConfigProviderInfo overrides the Configuration Provider ServiceConfig values
// from an Environment variable value (if it exists).
func (_ *Environment) OverrideConfigProviderInfo(
	lc logger.LoggingClient,
	configProviderInfo types.ServiceConfig) (types.ServiceConfig, error) {

	if url := os.Getenv(envKeyConfigUrl); len(url) > 0 {
		lc.Info(fmt.Sprintf("Confiuragtion Provider information overridden by Environment variable: %s=%s", envKeyConfigUrl, url))

		if err := configProviderInfo.PopulateFromUrl(url); err != nil {
			return types.ServiceConfig{}, err
		}
	} else {
		// TODO: Remove this for release V2.0.0
		// This is for backwards compatibility with Fuji Device Services.
		// If --registry=<url> is used then we must use the <url> for the configuration provider.
		if url := os.Getenv(envKeyRegistryUrl); len(url) > 0 {
			lc.Info(fmt.Sprintf("Confiuragtion Provider information overridden by Environment variable: %s=%s", envKeyRegistryUrl, url))

			if err := configProviderInfo.PopulateFromUrl(url); err != nil {
				return types.ServiceConfig{}, err
			}
		}
	}

	return configProviderInfo, nil
}

// TODO: Remove this func for release V2.0.0
// This is for backwards compatibility with Fuji Device Services.
// If --registry=<url> is used then we must use the <url> for the configuration provider.
// GetRegistryProviderInfoOverride get the overrides for Registry Provider Config values
// from an Environment variable value (if it exists).
func (_ *Environment) GetRegistryProviderInfoOverride(lc logger.LoggingClient) string {
	url := os.Getenv(envKeyRegistryUrl)
	if len(url) > 0 {
		lc.Info(fmt.Sprintf("Registry Provider information overridden by Environment variable: %s=%s", envKeyRegistryUrl, url))
	}

	return url
}

// OverrideStartupInfo overrides the Service StartupInfo values from an Environment variable value (if it exists).
func (_ *Environment) OverrideStartupInfo(
	lc logger.LoggingClient,
	startup config.StartupInfo) config.StartupInfo {

	//	OverrideConfiguration the startup timer configuration, if provided.
	if value := os.Getenv(envKeyStartupDuration); len(value) > 0 {
		lc.Info(fmt.Sprintf("Startup duration value overridden by Environment variable: %s=%s", envKeyStartupDuration, value))

		if n, err := strconv.ParseInt(value, 10, 0); err == nil && n > 0 {
			startup.Duration = int(n)
		}
	}

	//	OverrideConfiguration the startup timer interval, if provided.
	if value := os.Getenv(envKeyStartupInterval); len(value) > 0 {
		lc.Info(fmt.Sprintf("Startup interval value overridden by Environment variable: %s=%s", envKeyStartupInterval, value))

		if n, err := strconv.ParseInt(value, 10, 0); err == nil && n > 0 {
			startup.Interval = int(n)
		}
	}

	return startup
}

// convertToType attempts to convert the string value to the specified type of the old value
func (_ *Environment) convertToType(oldValue interface{}, value string) (newValue interface{}, err error) {
	switch oldValue.(type) {
	case []string:
		newValue = parseCommaSeparatedSlice(value)
	case []interface{}:
		newValue = parseCommaSeparatedSlice(value)
	case string:
		newValue = value
	case bool:
		newValue, err = strconv.ParseBool(value)
	case int:
		newValue, err = strconv.ParseInt(value, 10, strconv.IntSize)
		newValue = int(newValue.(int64))
	case int8:
		newValue, err = strconv.ParseInt(value, 10, 8)
		newValue = int8(newValue.(int64))
	case int16:
		newValue, err = strconv.ParseInt(value, 10, 16)
		newValue = int16(newValue.(int64))
	case int32:
		newValue, err = strconv.ParseInt(value, 10, 32)
		newValue = int32(newValue.(int64))
	case int64:
		newValue, err = strconv.ParseInt(value, 10, 64)
	case uint:
		newValue, err = strconv.ParseUint(value, 10, strconv.IntSize)
		newValue = uint(newValue.(uint64))
	case uint8:
		newValue, err = strconv.ParseUint(value, 10, 8)
		newValue = uint8(newValue.(uint64))
	case uint16:
		newValue, err = strconv.ParseUint(value, 10, 16)
		newValue = uint16(newValue.(uint64))
	case uint32:
		newValue, err = strconv.ParseUint(value, 10, 32)
		newValue = uint32(newValue.(uint64))
	case uint64:
		newValue, err = strconv.ParseUint(value, 10, 64)
	case float32:
		newValue, err = strconv.ParseFloat(value, 32)
		newValue = float32(newValue.(float64))
	case float64:
		newValue, err = strconv.ParseFloat(value, 64)
	default:
		err = fmt.Errorf(
			"configuration type of '%s' is not supported for environment variable override",
			reflect.TypeOf(oldValue).String())
	}

	return newValue, err
}

// parseCommaSeparatedSlice converts comma separated list to a string slice
func parseCommaSeparatedSlice(value string) (values []interface{}) {
	// Assumption is environment variable value is comma separated
	// Whitespace can vary so must be trimmed out
	result := strings.Split(strings.TrimSpace(value), ",")
	for _, entry := range result {
		values = append(values, strings.TrimSpace(entry))
	}

	return values
}
