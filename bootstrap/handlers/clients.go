/*******************************************************************************
 * Copyright 2022 Intel Inc.
 * Copyright (C) 2023 Intel Corporation
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

package handlers

import (
	"context"
	"fmt"
	"sync"
	"time"

	clients "github.com/edgexfoundry/go-mod-core-contracts/v3/clients/http"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/interfaces"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/common"
	clientsMessaging "github.com/edgexfoundry/go-mod-messaging/v3/clients"
	"github.com/edgexfoundry/go-mod-registry/v3/pkg/types"
	"github.com/edgexfoundry/go-mod-registry/v3/registry"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/secret"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/di"
)

// ClientsBootstrap contains data to boostrap the configured clients
type ClientsBootstrap struct {
	registry  registry.Client
	inDevMode bool
}

// NewClientsBootstrap is a factory method that returns the initialized "ClientsBootstrap" receiver struct.
func NewClientsBootstrap(devMode bool) *ClientsBootstrap {
	return &ClientsBootstrap{
		inDevMode: devMode,
	}
}

// BootstrapHandler fulfills the BootstrapHandler contract.
// It creates instances of each of the EdgeX clients that are in the service's configuration and place them in the DIC.
// If the registry is enabled it will be used to get the URL for client otherwise it will use configuration for the url.
// This handler will fail if an unknown client is specified.
func (cb *ClientsBootstrap) BootstrapHandler(
	_ context.Context,
	_ *sync.WaitGroup,
	startupTimer startup.Timer,
	dic *di.Container) bool {

	lc := container.LoggingClientFrom(dic.Get)
	config := container.ConfigurationFrom(dic.Get)
	cb.registry = container.RegistryFrom(dic.Get)
	jwtSecretProvider := secret.NewJWTSecretProvider(container.SecretProviderExtFrom(dic.Get))

	if config.GetBootstrap().Clients != nil {
		for serviceKey, serviceInfo := range *config.GetBootstrap().Clients {
			var url string
			var err error

			if !serviceInfo.UseMessageBus {
				url, err = cb.getClientUrl(serviceKey, serviceInfo.Url(), startupTimer, lc)
				if err != nil {
					lc.Error(err.Error())
					return false
				}
			}

			switch serviceKey {
			case common.CoreDataServiceKey:
				dic.Update(di.ServiceConstructorMap{
					container.EventClientName: func(get di.Get) interface{} {
						return clients.NewEventClient(url, jwtSecretProvider)
					},
				})
			case common.CoreMetaDataServiceKey:
				dic.Update(di.ServiceConstructorMap{
					container.DeviceClientName: func(get di.Get) interface{} {
						return clients.NewDeviceClient(url, jwtSecretProvider)
					},
					container.DeviceServiceClientName: func(get di.Get) interface{} {
						return clients.NewDeviceServiceClient(url, jwtSecretProvider)
					},
					container.DeviceProfileClientName: func(get di.Get) interface{} {
						return clients.NewDeviceProfileClient(url, jwtSecretProvider)
					},
					container.ProvisionWatcherClientName: func(get di.Get) interface{} {
						return clients.NewProvisionWatcherClient(url, jwtSecretProvider)
					},
				})

			case common.CoreCommandServiceKey:
				var client interfaces.CommandClient

				if serviceInfo.UseMessageBus {
					// TODO: Move following outside loop when multiple messaging based clients exist
					messageClient := container.MessagingClientFrom(dic.Get)
					if messageClient == nil {
						lc.Errorf("Unable to create Command client using MessageBus: %s", "MessageBus Client was not created")
						return false
					}

					// TODO: Move following outside loop when multiple messaging based clients exist
					timeout, err := time.ParseDuration(config.GetBootstrap().Service.RequestTimeout)
					if err != nil {
						lc.Errorf("Unable to parse Service.RequestTimeout as a time duration: %v", err)
						return false
					}

					baseTopic := config.GetBootstrap().MessageBus.GetBaseTopicPrefix()
					client = clientsMessaging.NewCommandClient(messageClient, baseTopic, timeout)

					lc.Infof("Using messaging for '%s' clients", serviceKey)
				} else {
					client = clients.NewCommandClient(url, jwtSecretProvider)
				}

				dic.Update(di.ServiceConstructorMap{
					container.CommandClientName: func(get di.Get) interface{} {
						return client
					},
				})

			case common.SupportNotificationsServiceKey:
				dic.Update(di.ServiceConstructorMap{
					container.NotificationClientName: func(get di.Get) interface{} {
						return clients.NewNotificationClient(url, jwtSecretProvider)
					},
					container.SubscriptionClientName: func(get di.Get) interface{} {
						return clients.NewSubscriptionClient(url, jwtSecretProvider)
					},
				})

			case common.SupportSchedulerServiceKey:
				dic.Update(di.ServiceConstructorMap{
					container.IntervalClientName: func(get di.Get) interface{} {
						return clients.NewIntervalClient(url, jwtSecretProvider)
					},
					container.IntervalActionClientName: func(get di.Get) interface{} {
						return clients.NewIntervalActionClient(url, jwtSecretProvider)
					},
				})

			default:

			}
		}
	}
	return true
}

func (cb *ClientsBootstrap) getClientUrl(serviceKey string, defaultUrl string, startupTimer startup.Timer, lc logger.LoggingClient) (string, error) {
	if cb.registry == nil || cb.inDevMode {
		lc.Infof("Using REST for '%s' clients @ %s", serviceKey, defaultUrl)
		return defaultUrl, nil
	}

	var err error
	var endpoint types.ServiceEndpoint

	for startupTimer.HasNotElapsed() {
		endpoint, err = cb.registry.GetServiceEndpoint(serviceKey)
		if err == nil {
			break
		}

		lc.Warnf("unable to Get service endpoint for '%s': %s. retrying...", serviceKey, err.Error())
		startupTimer.SleepForInterval()
	}

	if err != nil {
		return "", fmt.Errorf("unable to Get service endpoint for '%s': %s. Giving up", serviceKey, err.Error())
	}

	url := fmt.Sprintf("http://%s:%v", endpoint.Host, endpoint.Port)

	lc.Infof("Using registry for URL for '%s': %s", serviceKey, url)

	return url, nil
}
