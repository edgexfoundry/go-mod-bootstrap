package file

import (
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/interfaces/mocks"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/di"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/stretchr/testify/assert"
)

var dic *di.Container

func TestLoadFile(t *testing.T) {
	lc := logger.NewMockClient()
	tests := []struct {
		Name               string
		Path               string
		ContentLength      int
		ExpectedErr        string
		expectedSecretData map[string]string
	}{
		{"Valid - load from YAML file", path.Join("..", "config", "testdata", "configuration.yaml"), 4446, "", nil},
		{"Valid - load from JSON file", path.Join(".", "testdata", "configuration.json"), 142, "", nil},
		{"Valid - load from HTTP", "http://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/testdata/configuration.yaml", 4446, "", nil},
		{"Valid - load from HTTPS", "https://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/testdata/configuration.yaml", 4446, "", nil},
		{"Valid - load from HTTPS with secret", "https://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/testdata/configuration.yaml?edgexSecretName=mySecretName", 4446, "", map[string]string{"type": "httpheader", "headername": "Authorization", "headercontents": "Basic 1234567890"}},
		{"Invalid - File not found", "bogus", 0, "Could not read file", nil},
		{"Invalid - parse uri fail", "{test:\"test\"}", 0, "Could not parse file path", nil},
		{"Invalid - load from invalid HTTP", "http://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/configuration.yaml", 1, "Invalid status code", nil},
		{"Invalid - load from invalid HTTPS", "https://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/configuration.yaml", 1, "Invalid status code", nil},
		{"Invalid - load from HTTPS with invalid secret", "https://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/testdata/configuration.yaml?edgexSecretName=mySecretName", 4446, "Secret type is not httpheader", map[string]string{"type": "invalidheader", "headername": "Authorization", "headercontents": "Basic 1234567890"}},
		{"Invalid - load from HTTPS with empty secret", "https://raw.githubusercontent.com/edgexfoundry/go-mod-bootstrap/main/bootstrap/config/testdata/configuration.yaml?edgexSecretName=mySecretName", 0, "Secret headername and headercontents can not be empty", map[string]string{"type": "httpheader", "headername": "", "headercontents": ""}},
	}

	for _, tc := range tests {
		mockSecretProvider := &mocks.SecretProvider{}
		if tc.expectedSecretData != nil {
			mockSecretProvider.On("GetSecret", "mySecretName").Return(tc.expectedSecretData, nil)
		}
		dic = di.NewContainer(di.ServiceConstructorMap{
			container.SecretProviderName: func(get di.Get) interface{} {
				return mockSecretProvider
			},
		})

		t.Run(tc.Name, func(t *testing.T) {
			bytesOut, err := Load(tc.Path, mockSecretProvider, lc)
			if tc.ExpectedErr != "" {
				assert.Contains(t, err.Error(), tc.ExpectedErr)
				return
			}

			assert.Equal(t, tc.ContentLength, len(bytesOut))
			mockSecretProvider.AssertExpectations(t)
		})
	}
}

func TestLoadFile_WithHTTPServer(t *testing.T) {

	lc := logger.MockLogger{}

	expectedHeaderKey := "Authorization"
	expectedHeaderContents := "Basic 1234567890"
	expectedSecretData := map[string]string{"type": "httpheader", "headername": expectedHeaderKey, "headercontents": expectedHeaderContents}

	mockSecretProvider := &mocks.SecretProvider{}
	mockSecretProvider.On("GetSecret", "mySecretName").Return(expectedSecretData, nil)
	dic = di.NewContainer(di.ServiceConstructorMap{
		container.SecretProviderName: func(get di.Get) interface{} {
			return mockSecretProvider
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contents := r.Header.Get(expectedHeaderKey)
		require.Equal(t, expectedHeaderContents, contents)
		_, err := w.Write([]byte("test passed"))
		require.NoError(t, err)
	}))
	defer ts.Close()

	query := "?edgexSecretName=mySecretName"
	path := ts.URL + query

	bytesOut, err := Load(path, mockSecretProvider, lc)

	require.NoError(t, err)
	assert.NotEmpty(t, bytesOut)
	mockSecretProvider.AssertExpectations(t)
}
