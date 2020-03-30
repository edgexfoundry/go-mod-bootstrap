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
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/edgexfoundry/go-mod-configuration/configuration"
	configTypes "github.com/edgexfoundry/go-mod-configuration/pkg/types"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/flags"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/logging"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/startup"
)

const writableKey = "/Writable"

// UpdatedStream defines the stream type that is notified by ListenForChanges when a configuration update is received.
type UpdatedStream chan<- struct{}

type Processor struct {
	Logger          logger.LoggingClient
	flags           flags.Common
	environment     *Environment
	startupTimer    startup.Timer
	ctx             context.Context
	wg              *sync.WaitGroup
	configUpdated   UpdatedStream
	overwriteConfig bool
}

// NewProcessor creates a new configuration Processor
func NewProcessor(
	lc logger.LoggingClient,
	flags flags.Common,
	environment *Environment,
	startupTimer startup.Timer,
	ctx context.Context,
	wg *sync.WaitGroup,
	configUpdated UpdatedStream,
) Processor {
	return Processor{
		Logger:        lc,
		flags:         flags,
		environment:   environment,
		startupTimer:  startupTimer,
		ctx:           ctx,
		wg:            wg,
		configUpdated: configUpdated,
	}
}

func (cp Processor) Process(serviceKey string, configStem string, serviceConfig interfaces.Configuration) error {
	// Create some shorthand for frequently used items
	environment := cp.environment
	lc := cp.Logger

	cp.overwriteConfig = cp.flags.OverwriteConfig()

	// TODO: remove this check once -r/-registry is back to a bool in release v2.0.0
	if len(cp.flags.ConfigProviderUrl()) > 0 && len(cp.flags.RegistryUrl()) > 0 {
		return fmt.Errorf("use of -cp/-configProvider with -r/-registry=<url> not premitted")
	}

	// Local configuration must be loaded first in case need registry config info and/or
	// need to push it to the Configuration Provider.
	if err := cp.loadFromFile(serviceConfig); err != nil {
		return err
	}

	// Override file-based configuration with environment variables.
	// Environment variable overrides have precedence over all others,
	// so make sure they are applied before config is used for anything.
	overrideCount, err := environment.OverrideConfiguration(lc, serviceConfig)
	if err != nil {
		return err
	}

	configProviderUrl := cp.flags.ConfigProviderUrl()

	// TODO: remove this check once -r/-registry is back to a bool and only enable registry usage in release v2.0.0
	// For backwards compatibility with Fuji device and app services that use just -r/-registry for both registry and config
	if len(configProviderUrl) == 0 && cp.flags.UseRegistry() {
		if len(cp.flags.RegistryUrl()) > 0 {
			configProviderUrl = cp.flags.RegistryUrl()
			lc.Info("Config Provider URL created from -r/-registry=<url> flag")
		} else {
			// Have to use the Registry config for Configuration provider
			registryConfig := serviceConfig.GetBootstrap().Registry
			configProviderUrl = fmt.Sprintf("%s.http://%s:%d", registryConfig.Type, registryConfig.Host, registryConfig.Port)
			lc.Info("Config Provider URL created from Registry configuration")
		}
	}
	// Create new ProviderInfo and initialize it from command-line flag or Environment variables
	configProviderInfo, err := NewProviderInfo(lc, cp.environment, configProviderUrl)
	if err != nil {
		return err
	}

	switch configProviderInfo.UseProvider() {
	case true:
		configClient, err := cp.createProviderClient(serviceKey, configStem, configProviderInfo.ServiceConfig())
		if err != nil {
			return fmt.Errorf("failed to create Configuration Provider client: %s", err.Error())
		}

		for cp.startupTimer.HasNotElapsed() {
			if err := cp.processWithProvider(
				configClient,
				serviceConfig,
				overrideCount,
			); err != nil {
				lc.Error(err.Error())
				select {
				case <-cp.ctx.Done():
					return errors.New("aborted Updating to/from Configuration Provider")
				default:
					cp.startupTimer.SleepForInterval()
					continue
				}
			}

			break
		}

		// Have to create new Logger here so it is used in long running listenForChanges()
		cp.Logger = logging.FactoryFromConfiguration(serviceKey, serviceConfig)
		cp.listenForChanges(serviceConfig, configClient)

	case false:
		// Have to create new Logger here so that have one created from local configuration.
		cp.Logger = logging.FactoryFromConfiguration(serviceKey, serviceConfig)
		cp.logConfigInfo("Using local configuration from file", overrideCount)
	}
	return err
}

// createProviderClient creates and returns a configuration.Client instance and logs Client connection information
func (cp Processor) createProviderClient(
	serviceKey string,
	configStem string,
	providerConfig configTypes.ServiceConfig) (configuration.Client, error) {

	providerConfig.BasePath = configStem + serviceKey

	cp.Logger.Info(fmt.Sprintf(
		"Using Configuration provider (%s) from: %s with base path of %s",
		providerConfig.Type,
		providerConfig.GetUrl(),
		providerConfig.BasePath))

	return configuration.NewConfigurationClient(providerConfig)
}

// LoadFromFile attempts to read and unmarshal toml-based configuration into a configuration struct.
func (cp Processor) loadFromFile(config interfaces.Configuration) error {
	configDir := cp.flags.ConfigDirectory()
	envValue := os.Getenv(envConfDir)
	if len(envValue) > 0 {
		configDir = envValue
		logEnvironmentOverride(cp.Logger, "-c/-confdir", envFile, envValue)
	}

	if len(configDir) == 0 {
		configDir = "./res"
	}

	profileDir := cp.flags.Profile()
	// TODO: For release v2.0.0 just use envProfile
	key, envValue := getEnvironmentValue(envProfile, envV1Profile)
	if len(envValue) > 0 {
		profileDir = envValue
		logEnvironmentOverride(cp.Logger, "-p/-profile", key, envValue)
	}

	// remainder is simplification of LoadFromFile() in internal/pkg/config/loader.go
	if len(profileDir) > 0 {
		profileDir += "/"
	}

	configFileName := cp.flags.ConfigFileName()
	envValue = os.Getenv(envFile)
	if len(envValue) > 0 {
		configFileName = envValue
		logEnvironmentOverride(cp.Logger, "-f/-file", envFile, envValue)
	}

	fileName := configDir + "/" + profileDir + configFileName

	contents, err := ioutil.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("could not load configuration file (%s): %s", fileName, err.Error())
	}
	if err = toml.Unmarshal(contents, config); err != nil {
		return fmt.Errorf("could not load configuration file (%s): %s", fileName, err.Error())
	}

	cp.Logger.Info(fmt.Sprintf("Loaded configuration from %s", fileName))

	return nil
}

// ProcessWithProvider puts configuration if doesnt exist in provider (i.e. self-seed) or
// gets configuration from provider and updates the service's configuration with environment overrides after receiving
// them from the provider so that environment override supersede any changes made in the provider.
func (cp Processor) processWithProvider(
	configClient configuration.Client,
	serviceConfig interfaces.Configuration,
	overrideCount int) error {

	if !configClient.IsAlive() {
		return errors.New("configuration provider is not available")
	}

	hasConfig, err := configClient.HasConfiguration()
	if err != nil {
		return fmt.Errorf("could not determine if Configuration provider has configuration: %s", err.Error())
	}

	if !hasConfig || cp.overwriteConfig {
		// Environment overrides already applied previously so just push to Configuration Provider
		// Note that serviceConfig is a pointer, so we have to use reflection to dereference it.
		err = configClient.PutConfiguration(reflect.ValueOf(serviceConfig).Elem().Interface(), true)
		if err != nil {
			return fmt.Errorf("could not push configuration into Configuration Provider: %s", err.Error())
		}

		cp.logConfigInfo("Configuration has been pushed to into Configuration Provider", overrideCount)
	} else {
		rawConfig, err := configClient.GetConfiguration(serviceConfig)
		if err != nil {
			return fmt.Errorf("could not get configuration from Configuration provider: %s", err.Error())
		}

		if !serviceConfig.UpdateFromRaw(rawConfig) {
			return errors.New("configuration from Configuration provider failed type check")
		}

		overrideCount, err := cp.environment.OverrideConfiguration(cp.Logger, serviceConfig)
		if err != nil {
			return err
		}

		cp.logConfigInfo("Configuration has been pulled from Configuration provider", overrideCount)
	}

	return nil
}

// listenForChanges leverages the Configuration Provider client's WatchForChanges() method to receive changes to and update the
// service's configuration struct's writable sub-struct.  It's assumed the log level is universally part of the
// writable struct and this function explicitly updates the loggingClient's log level when new configuration changes
// are received.
func (cp Processor) listenForChanges(serviceConfig interfaces.Configuration, configClient configuration.Client) {
	lc := cp.Logger

	cp.wg.Add(1)
	go func() {
		defer cp.wg.Done()

		errorStream := make(chan error)
		defer close(errorStream)

		updateStream := make(chan interface{})
		defer close(updateStream)

		configClient.WatchForChanges(updateStream, errorStream, serviceConfig.EmptyWritablePtr(), writableKey)

		for {
			select {
			case <-cp.ctx.Done():
				return

			case ex := <-errorStream:
				lc.Error(ex.Error())

			case raw, ok := <-updateStream:
				if !ok {
					return
				}

				if !serviceConfig.UpdateWritableFromRaw(raw) {
					lc.Error("ListenForChanges() type check failed")
					return
				}

				lc.Info("Writeable configuration has been updated from the Configuration Provider")
				_ = lc.SetLogLevel(serviceConfig.GetLogLevel())

				if cp.configUpdated != nil {
					cp.configUpdated <- struct{}{}
				}
			}
		}
	}()
}

// logConfigInfo logs the config info message with number over overrides that occurred.
func (cp Processor) logConfigInfo(message string, overrideCount int) {
	cp.Logger.Info(fmt.Sprintf("%s (%d environment overrides applied)", message, overrideCount))
}
