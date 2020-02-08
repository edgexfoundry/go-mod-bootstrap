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
	"sync"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/startup"

	"github.com/edgexfoundry/go-mod-configuration/configuration"
	configTypes "github.com/edgexfoundry/go-mod-configuration/pkg/types"

	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
)

const writableKey = "/Writable"

// createClient creates and returns a configuration.Client instance.
func createClient(serviceKey string, providerConfig configTypes.ServiceConfig, configStem string) (configuration.Client, error) {
	providerConfig.BasePath = configStem + serviceKey
	return configuration.NewConfigurationClient(providerConfig)
}

// UpdateFromProvider connects to the config provider, gets configuration, and updates the service's
// configuration struct.
func UpdateFromProvider(
	ctx context.Context,
	startupTimer startup.Timer,
	providerConfig configTypes.ServiceConfig,
	serviceConfig interfaces.Configuration,
	configStem string,
	lc logger.LoggingClient,
	serviceKey string) (configuration.Client, error) {

	var updateFromConfigProvider = func(configClient configuration.Client) error {
		if !configClient.IsAlive() {
			return errors.New("configuration provider is not available")
		}

		rawConfig, err := configClient.GetConfiguration(serviceConfig)
		if err != nil {
			return fmt.Errorf("could not get configuration from Registry: %v", err.Error())
		}

		if !serviceConfig.UpdateFromRaw(rawConfig) {
			return errors.New("configuration from Registry failed type check")
		}

		return nil
	}

	configClient, err := createClient(serviceKey, providerConfig, configStem)
	if err != nil {
		return nil, fmt.Errorf("createClient failed: %v", err.Error())
	}

	for startupTimer.HasNotElapsed() {
		if err := updateFromConfigProvider(configClient); err != nil {
			lc.Warn(err.Error())
			select {
			case <-ctx.Done():
				return nil, errors.New("aborted UpdateFromProvider()")
			default:
				startupTimer.SleepForInterval()
				continue
			}
		}
		return configClient, nil
	}
	return nil, errors.New("unable to update configuration from provider in allotted time")
}

// ListenForChanges leverages the registry client's WatchForChanges() method to receive changes to and update the
// service's configuration struct's writable sub-struct.  It's assumed the log level is universally part of the
// writable struct and this function explicitly updates the loggingClient's log level when new configuration changes
// are received.
func ListenForChanges(
	ctx context.Context,
	wg *sync.WaitGroup,
	config interfaces.Configuration,
	lc logger.LoggingClient,
	configClient configuration.Client) {

	wg.Add(1)
	go func() {
		defer wg.Done()

		errorStream := make(chan error)
		defer close(errorStream)

		updateStream := make(chan interface{})
		defer close(updateStream)

		configClient.WatchForChanges(updateStream, errorStream, config.EmptyWritablePtr(), writableKey)

		for {
			select {
			case <-ctx.Done():
				return

			case ex := <-errorStream:
				lc.Error(ex.Error())

			case raw, ok := <-updateStream:
				if !ok {
					return
				}

				if !config.UpdateWritableFromRaw(raw) {
					lc.Error("ListenForChanges() type check failed")
					return
				}

				lc.Info("Writeable configuration has been updated from the Configuration Provider")
				_ = lc.SetLogLevel(config.GetLogLevel())
			}
		}
	}()
}
