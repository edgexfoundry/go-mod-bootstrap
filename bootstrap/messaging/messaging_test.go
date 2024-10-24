package messaging

import (
	"errors"
	"os"
	"testing"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/interfaces/mocks"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/secret"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/di"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
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
		SecureMode       bool
		AuthMode         string
		SecretData       *SecretData
		ErrorExpectation bool
		ErrorMessage     string
	}{
		{"Invalid AuthMode", true, "BadAuthMode", &SecretData{}, true, "Invalid AuthMode of 'BadAuthMode' selected"},
		{"No Auth No error", true, AuthModeNone, &SecretData{}, false, ""},
		{"UsernamePassword No Error", true, AuthModeUsernamePassword, &SecretData{
			Username: "user",
			Password: "Password",
		}, false, ""},
		{"UsernamePassword Error no Username", true, AuthModeUsernamePassword, &SecretData{
			Password: "Password",
		}, true, "AuthModeUsernamePassword selected however Username or Password was not found for secret=unit-test"},
		{"UsernamePassword blank - non-secure", false, AuthModeUsernamePassword, &SecretData{
			Username: "",
			Password: "",
		}, false, ""},
		{"UsernamePassword Error no Password", true, AuthModeUsernamePassword, &SecretData{
			Username: "user",
		}, true, "AuthModeUsernamePassword selected however Username or Password was not found for secret=unit-test"},
		{"ClientCert No Error", true, AuthModeCert, &SecretData{
			CertPemBlock: []byte("----"),
			KeyPemBlock:  []byte("----"),
		}, false, ""},
		{"ClientCert No Key", true, AuthModeCert, &SecretData{
			CertPemBlock: []byte("----"),
		}, true, "AuthModeCert selected however the key or cert PEM block was not found for secret=unit-test"},
		{"ClientCert No Cert", true, AuthModeCert, &SecretData{
			KeyPemBlock: []byte("----"),
		}, true, "AuthModeCert selected however the key or cert PEM block was not found for secret=unit-test"},
		{"CACert no error", true, AuthModeCA, &SecretData{
			CaPemBlock: []byte(testCACert),
		}, false, ""},
		{"CACert invalid error", true, AuthModeCA, &SecretData{
			CaPemBlock: []byte(`------`),
		}, true, "Error parsing CA Certificate"},
		{"CACert no ca error", true, AuthModeCA, &SecretData{}, true, "AuthModeCA selected however no PEM Block was found for secret=unit-test"},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.SecureMode {
				_ = os.Setenv(secret.EnvSecretStore, "true")
				defer func() { _ = os.Setenv(secret.EnvSecretStore, "false") }()
			}

			result := ValidateSecretData(test.AuthMode, "unit-test", test.SecretData)
			if test.ErrorExpectation {
				require.Error(t, result, "Result should be an error")
				assert.Equal(t, test.ErrorMessage, result.Error())
			} else {
				assert.Nil(t, result, "Should be nil")
			}
		})
	}
}

func TestSetOptionalAuthData(t *testing.T) {
	_ = os.Setenv(secret.EnvSecretStore, "true")
	defer func() { _ = os.Setenv(secret.EnvSecretStore, "false") }()

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
					test.Provider.On("GetSecret", test.SecretName).Return(nil, errors.New("Not Found")).Once()
				} else {
					test.Provider.On("GetSecret", test.SecretName).Return(test.SecretData, nil).Once()
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

			err := SetOptionsAuthData(&messageBusInfo, lc, dic)
			if test.ErrorExpected {
				require.Error(t, err)
				return
			}

			assert.Equal(t, test.ExpectedOptionsData, messageBusInfo.Optional)
		})
	}
}
