package messaging

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/interfaces/mocks"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/di"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
	"github.com/edgexfoundry/go-mod-messaging/v2/messaging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var lc logger.LoggingClient
var dic *di.Container
var usernameSecretData = map[string]string{
	SecretUsernameKey: "username",
	SecretPasswordKey: "password",
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
	validCreateClient := messageTestConfig{
		messageBusInfo: config.MessageBusInfo{
			Type:               messaging.ZeroMQ, // Use ZMQ so no issue connecting.
			Protocol:           "http",
			Host:               "*",
			Port:               8765,
			PublishTopicPrefix: "edgex/events/#",
			AuthMode:           AuthModeUsernamePassword,
			SecretName:         "redisdb",
		},
	}

	invalidSecrets := messageTestConfig{
		messageBusInfo: config.MessageBusInfo{
			AuthMode:   AuthModeCert,
			SecretName: "redisdb",
		},
	}

	invalidNoConnect := messageTestConfig{
		messageBusInfo: config.MessageBusInfo{
			Type:       messaging.MQTT, // This will cause no connection since broker not available
			Protocol:   "tcp",
			Host:       "localhost",
			Port:       8765,
			AuthMode:   AuthModeUsernamePassword,
			SecretName: "redisdb",
		},
	}

	tests := []struct {
		Name           string
		Config         messageTestConfig
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
			provider.On("GetSecret", validCreateClient.GetMessageBusInfo().SecretName).Return(usernameSecretData, nil)
			dic.Update(di.ServiceConstructorMap{
				container.ConfigurationInterfaceName: func(get di.Get) interface{} {
					return test.Config
				},
				container.SecretProviderName: func(get di.Get) interface{} {
					return provider
				},
				container.MessagingClientName: func(get di.Get) interface{} {
					return nil
				},
			})

			actual := BootstrapHandler(context.Background(), &sync.WaitGroup{}, startup.NewTimer(1, 1), dic)
			assert.Equal(t, test.ExpectedResult, actual)
			if test.ExpectClient {
				assert.NotNil(t, container.MessagingClientFrom(dic.Get))
			} else {
				assert.Nil(t, container.MessagingClientFrom(dic.Get))
			}
		})
	}
}

func TestGetSecretData(t *testing.T) {
	// setup mock secret client
	expectedSecretData := map[string]string{
		"username": "TEST_USER",
		"password": "TEST_PASS",
	}

	mockSecretProvider := &mocks.SecretProvider{}
	mockSecretProvider.On("GetSecret", "").Return(nil)
	mockSecretProvider.On("GetSecret", "notfound").Return(nil, errors.New("Not Found"))
	mockSecretProvider.On("GetSecret", "mqtt").Return(expectedSecretData, nil)

	dic.Update(di.ServiceConstructorMap{
		container.SecretProviderName: func(get di.Get) interface{} {
			return mockSecretProvider
		},
	})

	tests := []struct {
		Name            string
		AuthMode        string
		SecretName      string
		ExpectedSecrets *SecretData
		ExpectingError  bool
	}{
		{"No Auth No error", AuthModeNone, "", nil, false},
		{"Auth No SecretData found", AuthModeCA, "notfound", nil, true},
		{"Auth With SecretData", AuthModeUsernamePassword, "mqtt", &SecretData{
			Username:     "TEST_USER",
			Password:     "TEST_PASS",
			KeyPemBlock:  []uint8{},
			CertPemBlock: []uint8{},
			CaPemBlock:   []uint8{},
		}, false},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			secretData, err := GetSecretData(test.AuthMode, test.SecretName, mockSecretProvider)
			if test.ExpectingError {
				assert.Error(t, err, "Expecting error")
				return
			}
			require.Equal(t, test.ExpectedSecrets, secretData)
		})
	}
}

func TestValidateSecrets(t *testing.T) {
	tests := []struct {
		Name             string
		AuthMode         string
		secrets          SecretData
		ErrorExpectation bool
		ErrorMessage     string
	}{
		{"Invalid AuthMode", "BadAuthMode", SecretData{}, true, "Invalid AuthMode of 'BadAuthMode' selected"},
		{"No Auth No error", AuthModeNone, SecretData{}, false, ""},
		{"UsernamePassword No Error", AuthModeUsernamePassword, SecretData{
			Username: "user",
			Password: "Password",
		}, false, ""},
		{"UsernamePassword Error no Username", AuthModeUsernamePassword, SecretData{
			Password: "Password",
		}, true, "AuthModeUsernamePassword selected however Username or Password was not found for secret=unit-test"},
		{"UsernamePassword Error no Password", AuthModeUsernamePassword, SecretData{
			Username: "user",
		}, true, "AuthModeUsernamePassword selected however Username or Password was not found for secret=unit-test"},
		{"ClientCert No Error", AuthModeCert, SecretData{
			CertPemBlock: []byte("----"),
			KeyPemBlock:  []byte("----"),
		}, false, ""},
		{"ClientCert No Key", AuthModeCert, SecretData{
			CertPemBlock: []byte("----"),
		}, true, "AuthModeCert selected however the key or cert PEM block was not found for secret=unit-test"},
		{"ClientCert No Cert", AuthModeCert, SecretData{
			KeyPemBlock: []byte("----"),
		}, true, "AuthModeCert selected however the key or cert PEM block was not found for secret=unit-test"},
		{"CACert no error", AuthModeCA, SecretData{
			CaPemBlock: []byte(testCACert),
		}, false, ""},
		{"CACert invalid error", AuthModeCA, SecretData{
			CaPemBlock: []byte(`------`),
		}, true, "Error parsing CA Certificate"},
		{"CACert no ca error", AuthModeCA, SecretData{}, true, "AuthModeCA selected however no PEM Block was found for secret=unit-test"},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			result := ValidateSecretData(test.AuthMode, "unit-test", &test.secrets)
			if test.ErrorExpectation {
				assert.Error(t, result, "Result should be an error")
				assert.Equal(t, test.ErrorMessage, result.(error).Error())
			} else {
				assert.Nil(t, result, "Should be nil")
			}
		})
	}
}

func TestSetOptionalAuthData(t *testing.T) {
	tests := []struct {
		Name                string
		Authmode            string
		SecretName          string
		Provider            *mocks.SecretProvider
		SecretData          map[string]string
		ExpectedOptionsData map[string]string
		ErrorExpected       bool
	}{
		{
			Name:       "Valid Username/Password",
			Authmode:   AuthModeUsernamePassword,
			SecretName: "user",
			Provider:   &mocks.SecretProvider{},
			SecretData: usernameSecretData,
			ExpectedOptionsData: map[string]string{
				OptionsUsernameKey: "username",
				OptionsPasswordKey: "password",
			},
			ErrorExpected: false,
		},
		{
			Name:       "Valid Client Cert",
			Authmode:   AuthModeCert,
			SecretName: "client",
			Provider:   &mocks.SecretProvider{},
			SecretData: map[string]string{
				SecretClientCert: testClientCert,
				SecretClientKey:  testClientKey,
			},
			ExpectedOptionsData: map[string]string{
				OptionsCertPEMBlockKey: testClientCert,
				OptionsKeyPEMBlockKey:  testClientKey,
			},
			ErrorExpected: false,
		},
		{
			Name:       "Valid CA Cert",
			Authmode:   AuthModeCA,
			SecretName: "ca",
			Provider:   &mocks.SecretProvider{},
			SecretData: map[string]string{
				SecretCACert: testCACert,
			},
			ExpectedOptionsData: map[string]string{
				OptionsCaPEMBlockKey: testCACert,
			},
			ErrorExpected: false,
		},
		{
			Name:          "Invalid - no provider",
			Authmode:      AuthModeUsernamePassword,
			Provider:      nil,
			ErrorExpected: true,
		},
		{
			Name:          "Invalid - Secret not found",
			Authmode:      AuthModeUsernamePassword,
			SecretName:    "",
			Provider:      &mocks.SecretProvider{},
			ErrorExpected: true,
		},
		{
			Name:       "Invalid - Secret data invalid",
			Authmode:   AuthModeUsernamePassword,
			SecretName: "user",
			Provider:   &mocks.SecretProvider{},
			SecretData: map[string]string{
				SecretCACert: testCACert,
			},
			ErrorExpected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var dic *di.Container
			if test.Provider != nil {
				if len(test.SecretName) == 0 {
					test.SecretName = "notfound"
					test.Provider.On("GetSecret", test.SecretName).Return(nil, errors.New("Not Found"))
				} else {
					test.Provider.On("GetSecret", test.SecretName).Return(test.SecretData, nil)
				}

				dic = di.NewContainer(di.ServiceConstructorMap{
					container.SecretProviderName: func(get di.Get) interface{} {
						return test.Provider
					},
				})
			} else {
				dic = di.NewContainer(di.ServiceConstructorMap{})
			}

			messageBusInfo := config.MessageBusInfo{
				AuthMode:   test.Authmode,
				SecretName: test.SecretName,
			}

			err := setOptionsAuthData(&messageBusInfo, lc, dic)
			if test.ErrorExpected {
				require.Error(t, err)
				return
			}

			assert.Equal(t, test.ExpectedOptionsData, messageBusInfo.Optional)
		})
	}
}

type messageTestConfig struct {
	messageBusInfo config.MessageBusInfo
}

func (c messageTestConfig) GetMessageBusInfo() config.MessageBusInfo {
	return c.messageBusInfo
}

func (c messageTestConfig) UpdateFromRaw(_ interface{}) bool {
	panic("implement me")
}

func (c messageTestConfig) UpdateWritableFromRaw(_ interface{}) bool {
	panic("implement me")
}

func (c messageTestConfig) EmptyWritablePtr() interface{} {
	panic("implement me")
}

func (c messageTestConfig) GetBootstrap() config.BootstrapConfiguration {
	panic("implement me")
}

func (c messageTestConfig) GetLogLevel() string {
	panic("implement me")
}

func (c messageTestConfig) GetRegistryInfo() config.RegistryInfo {
	panic("implement me")
}

func (c messageTestConfig) GetInsecureSecrets() config.InsecureSecrets {
	panic("implement me")
}
