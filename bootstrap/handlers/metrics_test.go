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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/container"
	mocks2 "github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/interfaces/mocks"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/di"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/edgexfoundry/go-mod-messaging/v4/messaging/mocks"
)

func TestServiceMetrics_BootstrapHandler(t *testing.T) {
	tests := []struct {
		Name           string
		Interval       string
		ExpectedResult bool
	}{
		{"Happy Path", "5s", true},
		{"Invalid Interval", "five seconds", false},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			target := NewServiceMetrics("unit-test")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			mockMessagingClient := &mocks.MessageClient{}
			mockConfiguration := &mocks2.Configuration{}
			mockConfiguration.On("GetBootstrap").Return(config.BootstrapConfiguration{
				MessageBus: &config.MessageBusInfo{},
			})

			dic := di.NewContainer(di.ServiceConstructorMap{
				container.LoggingClientInterfaceName: func(get di.Get) interface{} {
					return logger.NewMockClient()
				},
				container.MessagingClientName: func(get di.Get) interface{} {
					return mockMessagingClient
				},
				container.ConfigurationInterfaceName: func(get di.Get) interface{} {
					return mockConfiguration
				},
			})

			expectedTelemetryInfo := config.TelemetryInfo{
				Interval: test.Interval,
				Metrics:  make(map[string]bool),
				Tags:     make(map[string]string),
			}

			mockConfiguration.On("GetTelemetryInfo").Return(&expectedTelemetryInfo)
			wg := &sync.WaitGroup{}
			actualResult := target.BootstrapHandler(ctx, wg, startup.NewTimer(int(time.Second*5), int(time.Second*1)), dic)
			manager := container.MetricsManagerFrom(dic.Get)
			require.Equal(t, test.ExpectedResult, actualResult)
			if test.ExpectedResult == false {
				require.Nil(t, manager)
				return // Test complete
			}

			require.NotNil(t, manager)
		})
	}
}
