package handlers

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
	"github.com/edgexfoundry/go-mod-messaging/v3/messaging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/interfaces/mocks"
	boostrapMessaging "github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/messaging"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/di"
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
	validCreateClientSecure := config.MessageBusInfo{
		Type:       messaging.Redis,
		Protocol:   "redis",
		Host:       "localhost",
		Port:       6379,
		AuthMode:   boostrapMessaging.AuthModeUsernamePassword,
		SecretName: "redisdb",
	}

	validCreateClientNonSecure := validCreateClientSecure
	validCreateClientNonSecure.AuthMode = boostrapMessaging.AuthModeNone

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
		MessageBus     config.MessageBusInfo
		Secure         bool
		ExpectedResult bool
		ExpectClient   bool
	}{
		{"Valid secure - creates client", validCreateClientSecure, true, true, true},
		{"Valid non-secure - creates client", validCreateClientNonSecure, false, true, true},
		{"Invalid - secrets error", invalidSecrets, false, false, false},
		{"Invalid - can't connect", invalidNoConnect, true, false, false},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			providerMock := &mocks.SecretProvider{}
			providerMock.On("GetSecret", test.MessageBus.SecretName).Return(usernameSecretData, nil)
			configMock := &mocks.Configuration{}
			configMock.On("GetBootstrap").Return(config.BootstrapConfiguration{
				MessageBus: test.MessageBus,
			})

			dic.Update(di.ServiceConstructorMap{
				container.ConfigurationInterfaceName: func(get di.Get) interface{} {
					return configMock
				},
				container.SecretProviderName: func(get di.Get) interface{} {
					return providerMock
				},
				container.MessagingClientName: func(get di.Get) interface{} {
					return nil
				},
			})

			actual := MessagingBootstrapHandler(context.Background(), &sync.WaitGroup{}, startup.NewTimer(1, 1), dic)
			assert.Equal(t, test.ExpectedResult, actual)
			assert.Empty(t, test.MessageBus.Optional)
			if test.ExpectClient {
				assert.NotNil(t, container.MessagingClientFrom(dic.Get))
			} else {
				assert.Nil(t, container.MessagingClientFrom(dic.Get))
			}

			if test.Secure {
				providerMock.AssertCalled(t, "GetSecret", mock.Anything)
			} else {
				providerMock.AssertNotCalled(t, "GetSecret", mock.Anything)
			}
		})
	}
}
