package handlers

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
	"github.com/edgexfoundry/go-mod-messaging/v2/messaging"
	"github.com/stretchr/testify/assert"

	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/interfaces/mocks"
	boostrapMessaging "github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/messaging"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/di"
)

var lc logger.LoggingClient
var dic *di.Container
var usernameSecretData = map[string]string{
	boostrapMessaging.SecretUsernameKey: "username",
	boostrapMessaging.SecretPasswordKey: "password",
}

func TestMain(m *testing.M) {
	lc = logger.NewMockClient()

	dic = di.NewContainer(di.ServiceConstructorMap{
		container.LoggingClientInterfaceName: func(get di.Get) interface{} {
			return lc
		},
	})

	os.Exit(m.Run())
}

func TestBootstrapHandler(t *testing.T) {
	validCreateClient := config.MessageBusInfo{
		Type:               messaging.Redis,
		Protocol:           "redis",
		Host:               "localhost",
		Port:               6379,
		PublishTopicPrefix: "edgex/events/#",
		AuthMode:           boostrapMessaging.AuthModeUsernamePassword,
		SecretName:         "redisdb",
	}

	invalidSecrets := config.MessageBusInfo{
		AuthMode:   boostrapMessaging.AuthModeCert,
		SecretName: "redisdb",
	}

	invalidNoConnect := config.MessageBusInfo{
		Type:       messaging.MQTT, // This will cause no connection since broker not available
		Protocol:   "tcp",
		Host:       "localhost",
		Port:       8765,
		AuthMode:   boostrapMessaging.AuthModeUsernamePassword,
		SecretName: "redisdb",
	}

	tests := []struct {
		Name           string
		MessageQueue   config.MessageBusInfo
		ExpectedResult bool
		ExpectClient   bool
	}{
		{"Valid - creates client", validCreateClient, true, true},
		{"Invalid - secrets error", invalidSecrets, false, false},
		{"Invalid - can't connect", invalidNoConnect, false, false},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			provider := &mocks.SecretProvider{}
			provider.On("GetSecret", test.MessageQueue.SecretName).Return(usernameSecretData, nil)
			configMock := &mocks.Configuration{}
			configMock.On("GetBootstrap").Return(config.BootstrapConfiguration{
				MessageQueue: test.MessageQueue,
			})

			dic.Update(di.ServiceConstructorMap{
				container.ConfigurationInterfaceName: func(get di.Get) interface{} {
					return configMock
				},
				container.SecretProviderName: func(get di.Get) interface{} {
					return provider
				},
				container.MessagingClientName: func(get di.Get) interface{} {
					return nil
				},
			})

			actual := MessagingBootstrapHandler(context.Background(), &sync.WaitGroup{}, startup.NewTimer(1, 1), dic)
			assert.Equal(t, test.ExpectedResult, actual)
			assert.Empty(t, test.MessageQueue.Optional)
			if test.ExpectClient {
				assert.NotNil(t, container.MessagingClientFrom(dic.Get))
			} else {
				assert.Nil(t, container.MessagingClientFrom(dic.Get))
			}
		})
	}
}
