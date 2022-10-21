/*******************************************************************************
 * Copyright 2022 Intel Inc.
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

	clients "github.com/edgexfoundry/go-mod-core-contracts/v2/clients/http"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/interfaces"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/common"
	clientsMessaging "github.com/edgexfoundry/go-mod-messaging/v2/clients"
	"github.com/edgexfoundry/go-mod-registry/v2/pkg/types"
	"github.com/edgexfoundry/go-mod-registry/v2/registry"

	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/di"
)

// ClientsBootstrap contains data to boostrap the configured clients
type ClientsBootstrap struct {
	registry registry.Client
}

// NewClientsBootstrap is a factory method that returns the initialized "ClientsBootstrap" receiver struct.
func NewClientsBootstrap() *ClientsBootstrap {
	return &ClientsBootstrap{}
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

	for serviceKey, serviceInfo := range config.GetBootstrap().Clients {
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
					return clients.NewEventClient(url)
				},
			})
		case common.CoreMetaDataServiceKey:
			dic.Update(di.ServiceConstructorMap{
				container.DeviceClientName: func(get di.Get) interface{} {
					return clients.NewDeviceClient(url)
				},
				container.DeviceServiceClientName: func(get di.Get) interface{} {
					return clients.NewDeviceServiceClient(url)
				},
				container.DeviceProfileClientName: func(get di.Get) interface{} {
					return clients.NewDeviceProfileClient(url)
				},
				container.ProvisionWatcherClientName: func(get di.Get) interface{} {
					return clients.NewProvisionWatcherClient(url)
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

				client, err = clientsMessaging.NewCommandClient(messageClient, serviceInfo.Topics, timeout)
				if err != nil {
					lc.Errorf("Unable to create messaging based Command Client: %v", err)
					return false
				}

				lc.Infof("Using messaging for '%s' clients", serviceKey)
			} else {
				client = clients.NewCommandClient(url)
			}

			dic.Update(di.ServiceConstructorMap{
				container.CommandClientName: func(get di.Get) interface{} {
					return client
				},
			})

		case common.SupportNotificationsServiceKey:
			dic.Update(di.ServiceConstructorMap{
				container.NotificationClientName: func(get di.Get) interface{} {
					return clients.NewNotificationClient(url)
				},
				container.SubscriptionClientName: func(get di.Get) interface{} {
					return clients.NewSubscriptionClient(url)
				},
			})

		case common.SupportSchedulerServiceKey:
			dic.Update(di.ServiceConstructorMap{
				container.IntervalClientName: func(get di.Get) interface{} {
					return clients.NewIntervalClient(url)
				},
				container.IntervalActionClientName: func(get di.Get) interface{} {
					return clients.NewIntervalActionClient(url)
				},
			})

		default:

		}
	}

	return true
}

func (cb *ClientsBootstrap) getClientUrl(serviceKey string, defaultUrl string, startupTimer startup.Timer, lc logger.LoggingClient) (string, error) {
	if cb.registry == nil {
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
