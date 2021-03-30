/*******************************************************************************
 * Copyright 2019 Dell Inc.
 * Copyright 2020 Intel Inc.
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
	"os"

	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/v2"
	registryTypes "github.com/edgexfoundry/go-mod-registry/v2/pkg/types"
	"github.com/edgexfoundry/go-mod-registry/v2/registry"

	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/token"
)

// createRegistryClient creates and returns a registry.Client instance.
func createRegistryClient(
	serviceKey string,
	serviceConfig interfaces.Configuration,
	lc logger.LoggingClient) (registry.Client, error) {
	bootstrapConfig := serviceConfig.GetBootstrap()

	tokenFile := bootstrapConfig.Registry.AccessTokenFile
	accessToken, err := token.LoadAccessToken(tokenFile)
	if err != nil {
		// access token file doesn't exist means the access token is not needed.
		if os.IsNotExist(err) {
			lc.Warnf("Registry access token at %s doesn't exist. Skipping use of access token", tokenFile)
		} else {
			return nil, fmt.Errorf("unable to load Registry client access token at %s: %s", tokenFile, err.Error())
		}
	}

	registryConfig := registryTypes.Config{
		Host:            bootstrapConfig.Registry.Host,
		Port:            bootstrapConfig.Registry.Port,
		Type:            bootstrapConfig.Registry.Type,
		AccessToken:     accessToken,
		ServiceKey:      serviceKey,
		ServiceHost:     bootstrapConfig.Service.Host,
		ServicePort:     bootstrapConfig.Service.Port,
		ServiceProtocol: bootstrapConfig.Service.Protocol,
		CheckInterval:   bootstrapConfig.Service.CheckInterval,
		CheckRoute:      v2.ApiPingRoute,
	}

	lc.Info(fmt.Sprintf("Using Registry (%s) from %s", registryConfig.Type, registryConfig.GetRegistryUrl()))

	return registry.NewRegistryClient(registryConfig)
}

// RegisterWithRegistry connects to the registry and registers the service with the Registry
func RegisterWithRegistry(
	ctx context.Context,
	startupTimer startup.Timer,
	config interfaces.Configuration,
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

	registryClient, err := createRegistryClient(serviceKey, config, lc)
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
