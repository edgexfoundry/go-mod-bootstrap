package file

import (
	"path"
	"testing"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/interfaces/mocks"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/di"
	"github.com/stretchr/testify/assert"
)

var dic *di.Container

func TestLoadFile(t *testing.T) {
	tests := []struct {
		Name               string
		Path               string
		ContentLength      int
		ExpectedErr        string
		expectedSecretData map[string]string
	}{
		{"Valid - load from YAML file", path.Join("..", "config", "testdata", "configuration.yaml"), 4533, "", nil},
		{"Valid - load from JSON file", path.Join(".", "testdata", "configuration.json"), 142, "", nil},
		{"Valid - load from HTTP", "http://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/testdata/configuration.yaml", 4533, "", nil},
		{"Valid - load from HTTPS", "https://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/testdata/configuration.yaml", 4533, "", nil},
		{"Valid - load from HTTPS with secret", "https://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/testdata/configuration.yaml?edgexSecretName=mySecretName", 4533, "", map[string]string{"type": "httpheader", "headername": "Authorization", "headercontents": "Basic 1234567890"}},
		{"Invalid - File not found", "bogus", 0, "Could not read file", nil},
		{"Invalid - parse uri fail", "{test:\"test\"}", 0, "Could not parse file path", nil},
		{"Invalid - load from invalid HTTP", "http://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/configuration.yaml", 1, "Invalid status code", nil},
		{"Invalid - load from invalid HTTPS", "https://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/configuration.yaml", 1, "Invalid status code", nil},
		{"Invalid - load from HTTPS with invalid secret", "https://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/testdata/configuration.yaml?edgexSecretName=mySecretName", 4533, "Secret type is not httpheader", map[string]string{"type": "invalidheader", "headername": "Authorization", "headercontents": "Basic 1234567890"}},
		{"Invalid - load from HTTPS with empty secret", "https://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/testdata/configuration.yaml?edgexSecretName=mySecretName", 0, "Secret headername and headercontents can not be empty", map[string]string{"type": "httpheader", "headername": "", "headercontents": ""}},
	}

	for _, tc := range tests {
		mockSecretProvider := &mocks.SecretProvider{}
		if tc.expectedSecretData != nil {
			mockSecretProvider.On("GetSecret", "").Return(nil)
			mockSecretProvider.On("GetSecret", "mySecretName").Return(tc.expectedSecretData, nil)
		}
		dic = di.NewContainer(di.ServiceConstructorMap{
			container.SecretProviderName: func(get di.Get) interface{} {
				return mockSecretProvider
			},
		})

		t.Run(tc.Name, func(t *testing.T) {
			bytesOut, err := Load(tc.Path, DefaultTimeout, mockSecretProvider)
			if tc.ExpectedErr != "" {
				assert.Contains(t, err.Error(), tc.ExpectedErr)
				return
			}

			assert.Equal(t, tc.ContentLength, len(bytesOut))
		})
	}
}
