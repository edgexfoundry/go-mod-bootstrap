/*******************************************************************************
 * Copyright 2022 Intel Corp.
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
	"strings"
	"sync"

	"github.com/edgexfoundry/go-mod-messaging/v2/messaging"
	"github.com/edgexfoundry/go-mod-messaging/v2/pkg/types"

	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/container"
	boostrapMessaging "github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/messaging"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/di"
)

// MessagingBootstrapHandler fulfills the BootstrapHandler contract.  If creates and initializes the Messaging client
// and adds it to the DIC
func MessagingBootstrapHandler(ctx context.Context, wg *sync.WaitGroup, startupTimer startup.Timer, dic *di.Container) bool {
	lc := container.LoggingClientFrom(dic.Get)
	configuration := container.ConfigurationFrom(dic.Get)

	messageQueue := configuration.GetBootstrap().MessageQueue
	if len(messageQueue.Host) == 0 {
		lc.Error("MessageQueue configuration not set or missing from service's GetBootstrap() implementation")
		return false
	}

	// Make sure the MessageBus password is not leaked into the Service Config that can be retrieved via the /config endpoint
	messageBusInfo := deepCopy(messageQueue)

	if len(messageBusInfo.AuthMode) > 0 &&
		!strings.EqualFold(strings.TrimSpace(messageBusInfo.AuthMode), boostrapMessaging.AuthModeNone) {
		if err := boostrapMessaging.SetOptionsAuthData(&messageBusInfo, lc, dic); err != nil {
			lc.Errorf("setting the MessageBus auth options failed: %v", err)
			return false
		}
	}

	msgClient, err := messaging.NewMessageClient(
		types.MessageBusConfig{
			PublishHost: types.HostInfo{
				Host:     messageBusInfo.Host,
				Port:     messageBusInfo.Port,
				Protocol: messageBusInfo.Protocol,
			},
			SubscribeHost: types.HostInfo{
				Host:     messageBusInfo.Host,
				Port:     messageBusInfo.Port,
				Protocol: messageBusInfo.Protocol,
			},
			Type:     messageBusInfo.Type,
			Optional: messageBusInfo.Optional,
		})

	if err != nil {
		lc.Errorf("Failed to create MessageClient: %v", err)
		return false
	}

	for startupTimer.HasNotElapsed() {
		select {
		case <-ctx.Done():
			return false
		default:
			err = msgClient.Connect()
			if err != nil {
				lc.Warnf("Unable to connect MessageBus: %s", err.Error())
				startupTimer.SleepForInterval()
				continue
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				<-ctx.Done()
				if msgClient != nil {
					_ = msgClient.Disconnect()
				}
				lc.Infof("Disconnected from MessageBus")
			}()

			dic.Update(di.ServiceConstructorMap{
				container.MessagingClientName: func(get di.Get) interface{} {
					return msgClient
				},
			})

			lc.Infof(
				"Connected to %s Message Bus @ %s://%s:%d publishing on '%s' prefix topic with AuthMode='%s'",
				messageBusInfo.Type,
				messageBusInfo.Protocol,
				messageBusInfo.Host,
				messageBusInfo.Port,
				messageBusInfo.PublishTopicPrefix,
				messageBusInfo.AuthMode)

			return true
		}
	}

	lc.Error("Connecting to MessageBus time out")
	return false
}

func deepCopy(target config.MessageBusInfo) config.MessageBusInfo {
	result := config.MessageBusInfo{
		Type:               target.Type,
		Protocol:           target.Protocol,
		Host:               target.Host,
		Port:               target.Port,
		PublishTopicPrefix: target.PublishTopicPrefix,
		SubscribeTopic:     target.SubscribeTopic,
		AuthMode:           target.AuthMode,
		SecretName:         target.SecretName,
		SubscribeEnabled:   target.SubscribeEnabled,
	}
	result.Optional = make(map[string]string)
	for key, value := range target.Optional {
		result.Optional[key] = value
	}

	return result
}
