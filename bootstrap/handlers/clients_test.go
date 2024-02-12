//
// Copyright (c) 2022 Intel Corporation
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

package handlers

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
	loggerMocks "github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger/mocks"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/common"
	messagingMocks "github.com/edgexfoundry/go-mod-messaging/v3/messaging/mocks"
	"github.com/edgexfoundry/go-mod-registry/v3/pkg/types"
	"github.com/edgexfoundry/go-mod-registry/v3/registry"
	registryMocks "github.com/edgexfoundry/go-mod-registry/v3/registry/mocks"
	"github.com/stretchr/testify/mock"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/interfaces/mocks"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/di"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientsBootstrapHandler(t *testing.T) {
	lc := logger.NewMockClient()

	coreDataClientInfo := config.ClientInfo{
		Host:     "localhost",
		Port:     59880,
		Protocol: "http",
	}

	metadataClientInfo := config.ClientInfo{
		Host:     "localhost",
		Port:     59881,
		Protocol: "http",
	}

	commandHttpClientInfo := config.ClientInfo{
		Host:     "localhost",
		Port:     59882,
		Protocol: "http",
	}

	commandMessagingClientInfo := config.ClientInfo{
		UseMessageBus: true,
	}

	notificationClientInfo := config.ClientInfo{
		Host:     "localhost",
		Port:     59860,
		Protocol: "http",
	}

	subscriberClientInfo := config.ClientInfo{
		Host:     "localhost",
		Port:     59861,
		Protocol: "http",
	}

	registryMock := &registryMocks.Client{}
	registryMock.On("GetServiceEndpoint", common.CoreDataServiceKey).Return(types.ServiceEndpoint{}, nil)
	registryMock.On("GetServiceEndpoint", common.CoreMetaDataServiceKey).Return(types.ServiceEndpoint{}, nil)
	registryMock.On("GetServiceEndpoint", common.CoreCommandServiceKey).Return(types.ServiceEndpoint{}, nil)
	registryMock.On("GetServiceEndpoint", common.SupportNotificationsServiceKey).Return(types.ServiceEndpoint{}, nil)
	registryMock.On("GetServiceEndpoint", common.SupportSchedulerServiceKey).Return(types.ServiceEndpoint{}, nil)

	registryErrorMock := &registryMocks.Client{}
	registryErrorMock.On("GetServiceEndpoint", common.CoreDataServiceKey).Return(types.ServiceEndpoint{}, errors.New("some error"))

	startupTimer := startup.NewTimer(1, 1)

	tests := []struct {
		Name                   string
		CoreDataClientInfo     *config.ClientInfo
		CommandClientInfo      *config.ClientInfo
		MetadataClientInfo     *config.ClientInfo
		NotificationClientInfo *config.ClientInfo
		SchedulerClientInfo    *config.ClientInfo
		Registry               registry.Client
		ExpectedResult         bool
	}{
		{
			Name:                   "All ClientsBootstrap",
			CoreDataClientInfo:     &coreDataClientInfo,
			CommandClientInfo:      &commandHttpClientInfo,
			MetadataClientInfo:     &metadataClientInfo,
			NotificationClientInfo: &notificationClientInfo,
			SchedulerClientInfo:    &subscriberClientInfo,
			Registry:               nil,
			ExpectedResult:         true,
		},
		{
			Name:                   "All ClientsBootstrap using registry",
			CoreDataClientInfo:     &coreDataClientInfo,
			CommandClientInfo:      &commandHttpClientInfo,
			MetadataClientInfo:     &metadataClientInfo,
			NotificationClientInfo: &notificationClientInfo,
			SchedulerClientInfo:    &subscriberClientInfo,
			Registry:               registryMock,
			ExpectedResult:         true,
		},
		{
			Name:                   "Core Data Client using registry fails",
			CoreDataClientInfo:     &coreDataClientInfo,
			CommandClientInfo:      nil,
			MetadataClientInfo:     nil,
			NotificationClientInfo: nil,
			SchedulerClientInfo:    nil,
			Registry:               registryErrorMock,
			ExpectedResult:         false,
		},
		{
			Name:                   "No ClientsBootstrap",
			CoreDataClientInfo:     nil,
			CommandClientInfo:      nil,
			MetadataClientInfo:     nil,
			NotificationClientInfo: nil,
			SchedulerClientInfo:    nil,
			Registry:               nil,
			ExpectedResult:         true,
		},
		{
			Name:                   "Only Core Data ClientsBootstrap",
			CoreDataClientInfo:     &coreDataClientInfo,
			CommandClientInfo:      nil,
			MetadataClientInfo:     nil,
			NotificationClientInfo: nil,
			SchedulerClientInfo:    nil,
			Registry:               nil,
			ExpectedResult:         true,
		},
		{
			Name:                   "Only Metadata ClientsBootstrap",
			CoreDataClientInfo:     nil,
			CommandClientInfo:      nil,
			MetadataClientInfo:     &metadataClientInfo,
			NotificationClientInfo: nil,
			SchedulerClientInfo:    nil,
			Registry:               nil,
			ExpectedResult:         true,
		},
		{
			Name:                   "Only Messaging based Command ClientsBootstrap",
			CoreDataClientInfo:     nil,
			CommandClientInfo:      &commandMessagingClientInfo,
			MetadataClientInfo:     nil,
			NotificationClientInfo: nil,
			SchedulerClientInfo:    nil,
			Registry:               nil,
			ExpectedResult:         true,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			clients := make(config.ClientsCollection)

			if test.CoreDataClientInfo != nil {
				clients[common.CoreDataServiceKey] = test.CoreDataClientInfo
			}

			if test.CommandClientInfo != nil {
				clients[common.CoreCommandServiceKey] = test.CommandClientInfo
			}

			if test.MetadataClientInfo != nil {
				clients[common.CoreMetaDataServiceKey] = test.MetadataClientInfo
			}

			if test.NotificationClientInfo != nil {
				clients[common.SupportNotificationsServiceKey] = test.NotificationClientInfo
			}

			if test.SchedulerClientInfo != nil {
				clients[common.SupportSchedulerServiceKey] = test.SchedulerClientInfo
			}

			bootstrapConfig := config.BootstrapConfiguration{
				Service: &config.ServiceInfo{
					RequestTimeout: "30s",
				},
				Clients:    &clients,
				MessageBus: &config.MessageBusInfo{},
			}

			configMock := &mocks.Configuration{}
			configMock.On("GetBootstrap").Return(bootstrapConfig)

			messageClient := &messagingMocks.MessageClient{}
			messageClient.On("Subscribe", mock.Anything, mock.Anything).Return(nil)

			secProviderExt := &mocks.SecretProviderExt{}

			dic := di.NewContainer(di.ServiceConstructorMap{
				container.LoggingClientInterfaceName: func(get di.Get) interface{} {
					return lc
				},
				container.RegistryClientInterfaceName: func(get di.Get) interface{} {
					return test.Registry
				},
				container.ConfigurationInterfaceName: func(get di.Get) interface{} {
					return configMock
				},
				container.MessagingClientName: func(get di.Get) interface{} {
					return messageClient
				},
				container.SecretProviderExtName: func(get di.Get) interface{} {
					return secProviderExt
				},
			})

			actualResult := NewClientsBootstrap().BootstrapHandler(context.Background(), &sync.WaitGroup{}, startupTimer, dic)
			require.Equal(t, actualResult, test.ExpectedResult)
			if test.ExpectedResult == false {
				return
			}

			eventClient := container.EventClientFrom(dic.Get)
			readingClient := container.ReadingClientFrom(dic.Get)
			commandClient := container.CommandClientFrom(dic.Get)
			deviceServiceClient := container.DeviceServiceClientFrom(dic.Get)
			deviceProfileClient := container.DeviceProfileClientFrom(dic.Get)
			deviceClient := container.DeviceClientFrom(dic.Get)
			provisionWatcherClient := container.ProvisionWatcherClientFrom(dic.Get)
			notificationClient := container.NotificationClientFrom(dic.Get)
			subscriptionClient := container.SubscriptionClientFrom(dic.Get)
			intervalClient := container.IntervalClientFrom(dic.Get)
			intervalActionClient := container.IntervalActionClientFrom(dic.Get)

			if test.CoreDataClientInfo != nil {
				assert.NotNil(t, eventClient)
				assert.NotNil(t, readingClient)
			} else {
				assert.Nil(t, eventClient)
				assert.Nil(t, readingClient)
			}

			if test.CommandClientInfo != nil {
				assert.NotNil(t, commandClient)
			} else {
				assert.Nil(t, commandClient)
			}

			if test.MetadataClientInfo != nil {
				assert.NotNil(t, deviceServiceClient)
				assert.NotNil(t, deviceProfileClient)
				assert.NotNil(t, deviceClient)
				assert.NotNil(t, provisionWatcherClient)
			} else {
				assert.Nil(t, deviceServiceClient)
				assert.Nil(t, deviceProfileClient)
				assert.Nil(t, deviceClient)
				assert.Nil(t, provisionWatcherClient)
			}

			if test.NotificationClientInfo != nil {
				assert.NotNil(t, notificationClient)
				assert.NotNil(t, subscriptionClient)
			} else {
				assert.Nil(t, notificationClient)
				assert.Nil(t, subscriptionClient)
			}

			if test.SchedulerClientInfo != nil {
				assert.NotNil(t, intervalClient)
				assert.NotNil(t, intervalActionClient)
			} else {
				assert.Nil(t, intervalClient)
				assert.Nil(t, intervalActionClient)
			}

			if test.Registry != nil {
				registryMock.AssertExpectations(t)
			}
		})
	}
}

func TestCommandMessagingClientErrors(t *testing.T) {
	validDuration := "30s"
	invalidDuration := "xyz"

	tests := []struct {
		Name                   string
		MessagingClientPresent bool
		TimeoutDuration        string
	}{
		{"Missing Messaging Client", false, validDuration},
		{"Bad Timeout duration", true, invalidDuration},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			mockLogger := &loggerMocks.LoggingClient{}
			mockLogger.On("Errorf", mock.Anything)
			mockLogger.On("Errorf", mock.Anything, mock.Anything)

			mockMessaging := &messagingMocks.MessageClient{}

			clients := make(config.ClientsCollection)
			clients[common.CoreCommandServiceKey] = &config.ClientInfo{
				UseMessageBus: true,
			}

			bootstrapConfig := config.BootstrapConfiguration{
				Service: &config.ServiceInfo{
					RequestTimeout: test.TimeoutDuration,
				},
				Clients: &clients,
			}

			configMock := &mocks.Configuration{}
			configMock.On("GetBootstrap").Return(bootstrapConfig)

			dic := di.NewContainer(di.ServiceConstructorMap{
				container.LoggingClientInterfaceName: func(get di.Get) interface{} {
					return mockLogger
				},
				container.ConfigurationInterfaceName: func(get di.Get) interface{} {
					return configMock
				},
				container.MessagingClientName: func(get di.Get) interface{} {
					if test.MessagingClientPresent {
						return mockMessaging
					} else {
						return nil
					}
				},
			})

			startupTimer := startup.NewTimer(1, 1)
			actualResult := NewClientsBootstrap().BootstrapHandler(context.Background(), &sync.WaitGroup{}, startupTimer, dic)
			require.False(t, actualResult)

			mockLogger.AssertNumberOfCalls(t, "Errorf", 1)
		})
	}
}
