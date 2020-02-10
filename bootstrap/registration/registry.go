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

package registration

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/edgexfoundry/go-mod-configuration/pkg/types"
	"github.com/edgexfoundry/go-mod-core-contracts/clients"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	registryTypes "github.com/edgexfoundry/go-mod-registry/pkg/types"
	"github.com/edgexfoundry/go-mod-registry/registry"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/config"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/flags"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/startup"
)

// createRegistryClient creates and returns a registry.Client instance.
// For backwards compatibility with Fuji Device Service, -registry is a string that can contain a provider URL.
// TODO: Remove registryUrl parameter for release v2.0.0
func createRegistryClient(
	serviceKey string,
	serviceConfig interfaces.Configuration,
	registryUrl string,
	environment *config.Environment,
	lc logger.LoggingClient) (registry.Client, error) {
	var err error
	bootstrapConfig := serviceConfig.GetBootstrap()

	registryConfig := registryTypes.Config{
		Host:            bootstrapConfig.Registry.Host,
		Port:            bootstrapConfig.Registry.Port,
		Type:            bootstrapConfig.Registry.Type,
		ServiceKey:      serviceKey,
		ServiceHost:     bootstrapConfig.Service.Host,
		ServicePort:     bootstrapConfig.Service.Port,
		ServiceProtocol: bootstrapConfig.Service.Protocol,
		CheckInterval:   bootstrapConfig.Service.CheckInterval,
		CheckRoute:      clients.ApiPingRoute,
	}

	// TODO: Remove this block for release v2.0.0
	// For backwards compatibility with Fuji Device Service, -registry is a string that can contain a provider URL.
	if len(registryUrl) > 0 && registryUrl != flags.UseRegistryNoUrlValue {
		registryConfig, err = OverrideRegistryConfigWithUrl(registryConfig, registryUrl)
		if err != nil {
			return nil, err
		}
	}

	// TODO: Remove this block for release v2.0.0
	// For backwards compatibility, registry information can be override with environment variable.
	registryUrl = environment.GetRegistryProviderInfoOverride(lc)
	if len(registryUrl) > 0 {
		registryConfig, err = OverrideRegistryConfigWithUrl(registryConfig, registryUrl)
		if err != nil {
			return nil, err
		}
	}

	lc.Info(fmt.Sprintf("Using Registry (%s) from %s", registryConfig.Type, registryConfig.GetRegistryUrl()))

	return registry.NewRegistryClient(registryConfig)
}

// TODO: Remove this func for release v2.0.0
// For backwards compatibility with Fuji Device Service, -registry is a string that can contain a provider URL.
func OverrideRegistryConfigWithUrl(registryConfig registryTypes.Config, registryUrl string) (registryTypes.Config, error) {
	if len(registryUrl) == 0 {
		return registryConfig, nil
	}

	urlDetails, err := url.Parse(registryUrl)
	if err != nil {
		return registryConfig, fmt.Errorf("failed to parse Registry Provider URL (%s): %s", registryUrl, err.Error())
	}

	port, err := strconv.Atoi(urlDetails.Port())
	if err != nil {
		return registryConfig, fmt.Errorf("failed to parse Registry Provider URL (%s): %s", registryUrl, err.Error())
	}

	registryConfig.Port = port
	registryConfig.Host = urlDetails.Hostname()
	registryConfig.Protocol = types.DefaultProtocol
	registryConfig.Type = urlDetails.Scheme

	return registryConfig, nil
}

// TODO: Remove registryUrl parameter for release v2.0.0
// RegisterWithRegistry connects to the registry and registers the service with the Registry
func RegisterWithRegistry(
	ctx context.Context,
	startupTimer startup.Timer,
	config interfaces.Configuration,
	registryUrl string,
	environment *config.Environment,
	lc logger.LoggingClient,
	serviceKey string) (registry.Client, error) {

	var registryWithRegistry = func(registryClient registry.Client) error {
		if !registryClient.IsAlive() {
			return errors.New("registry is not available")
		}

		if err := registryClient.Register(); err != nil {
			return fmt.Errorf("could not register service with Registry: %v", err.Error())
		}

		return nil
	}

	registryClient, err := createRegistryClient(serviceKey, config, registryUrl, environment, lc)
	if err != nil {
		return nil, fmt.Errorf("createRegistryClient failed: %v", err.Error())
	}

	for startupTimer.HasNotElapsed() {
		if err := registryWithRegistry(registryClient); err != nil {
			lc.Warn(err.Error())
			select {
			case <-ctx.Done():
				return nil, errors.New("aborted RegisterWithRegistry()")
			default:
				startupTimer.SleepForInterval()
				continue
			}
		}
		return registryClient, nil
	}
	return nil, errors.New("unable to register with Registry in allotted time")
}
