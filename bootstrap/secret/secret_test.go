/*******************************************************************************
 * Copyright 2022 Intel Inc.
 * Copyright 2025 IOTech Ltd.
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

package secret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/environment"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/startup"
	bootstrapConfig "github.com/edgexfoundry/go-mod-bootstrap/v4/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/di"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/common"
	"github.com/edgexfoundry/go-mod-secrets/v4/pkg/token/authtokenloader/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const expectedUsername = "admin"
const expectedPassword = "password"
const expectedSecretName = "redisdb"
const expectedInsecureJWT = "" // Empty when in non-secure mode
const expectedSecureJWT = "secureJwtToken"

// nolint: gosec
var testTokenResponse = `{"auth":{"accessor":"9OvxnrjgV0JTYMeBreak7YJ9","client_token":"s.oPJ8uuJCkTRb2RDdcNova8wg","entity_id":"","lease_duration":3600,"metadata":{"edgex-service-name":"edgex-core-data"},"orphan":true,"policies":["default","edgex-service-edgex-core-data"],"renewable":true,"token_policies":["default","edgex-service-edgex-core-data"],"token_type":"service"},"data":null,"lease_duration":0,"lease_id":"","renewable":false,"request_id":"ee749ee1-c8bf-6fa9-3ed5-644181fc25b0","warnings":null,"wrap_info":null}`
var expectedSecrets = map[string]string{UsernameKey: expectedUsername, PasswordKey: expectedPassword}
var expectedSecureJwtData = map[string]string{"token": expectedSecureJWT}

func TestNewSecretProvider(t *testing.T) {
	tests := []struct {
		Name   string
		Secure string
	}{
		{"Valid Secure", "true"},
		{"Valid Insecure", "false"},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			_ = os.Setenv(EnvSecretStore, tc.Secure)
			timer := startup.NewStartUpTimer("UnitTest")

			dic := di.NewContainer(di.ServiceConstructorMap{
				container.LoggingClientInterfaceName: func(get di.Get) interface{} {
					return logger.NewMockClient()
				},
				container.ConfigurationInterfaceName: func(get di.Get) interface{} {
					return TestConfig{}
				},
			})

			var configuration interfaces.Configuration
			expectedJWT := expectedInsecureJWT

			if tc.Secure == "true" {
				testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.RequestURI {
					case "/v1/auth/token/lookup-self":
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(testTokenResponse))
					case "/v1/secret/edgex/testServiceKey/redisdb":
						w.WriteHeader(http.StatusOK)
						data := make(map[string]interface{})
						data["data"] = expectedSecrets
						response, _ := json.Marshal(data)
						_, _ = w.Write(response)
					case "/v1/identity/oidc/token/testServiceKey":
						w.WriteHeader(http.StatusOK)
						data := make(map[string]interface{})
						data["data"] = expectedSecureJwtData
						response, _ := json.Marshal(data)
						_, _ = w.Write(response)
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer testServer.Close()

				serverUrl, _ := url.Parse(testServer.URL)
				err := os.Setenv("SECRETSTORE_PORT", serverUrl.Port())
				require.NoError(t, err)

				mockTokenLoader := &mocks.AuthTokenLoader{}
				mockTokenLoader.On("Load", "/tmp/edgex/secrets/testServiceKey/secrets-token.json").Return("Test Token", nil)
				dic.Update(di.ServiceConstructorMap{
					container.AuthTokenLoaderInterfaceName: func(get di.Get) interface{} {
						return mockTokenLoader
					},
				})

				expectedJWT = expectedSecureJWT
			} else {
				configuration = TestConfig{
					map[string]bootstrapConfig.InsecureSecretsInfo{
						"DB": {
							SecretName: expectedSecretName,
							SecretData: expectedSecrets,
						},
					},
				}
			}

			envVars := environment.NewVariables(logger.NewMockClient())

			actual, err := NewSecretProvider(configuration, envVars, context.Background(), timer, dic, "testServiceKey")
			require.NoError(t, err)
			require.NotNil(t, actual)

			actualProvider := container.SecretProviderFrom(dic.Get)
			assert.NotNil(t, actualProvider)
			actualSecrets, err := actualProvider.GetSecret(expectedSecretName)
			require.NoError(t, err)
			assert.Equal(t, expectedUsername, actualSecrets[UsernameKey])
			assert.Equal(t, expectedPassword, actualSecrets[PasswordKey])

			actualProviderExt := container.SecretProviderExtFrom(dic.Get)
			assert.NotNil(t, actualProviderExt)

			actualJWT, err := actualProviderExt.GetSelfJWT()
			require.NoError(t, err)
			assert.Equal(t, expectedJWT, actualJWT)
		})
	}
}

func TestAddPrefix(t *testing.T) {
	expectedPrefixPath := "/v1/secret/edgex/"

	tests := []struct {
		name             string
		storeName        string
		expectedFullPath string
	}{
		{"non-empty StoreName", "core-command", expectedPrefixPath + "core-command"},
		{"empty StoreName", "", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualStoreFullPath := addEdgeXSecretNamePrefix(test.storeName)
			require.Equal(t, test.expectedFullPath, actualStoreFullPath)
		})
	}
}

func TestBuildSecretStoreConfig(t *testing.T) {
	expectedServiceKey := "unit-test"
	expectedHost := "edgex-secret-store"
	expectedPort := 8201
	expectedTokenFile := "/token.json"
	expectedRuntimeTokenProviderEnabled := true
	expectedRuntimeTokenProviderHost := "edgex-security-spiffe-token-provider"
	expectedRuntimeTokenProviderRequiredSecrets := "mqtt-bus"
	os.Setenv("SECRETSTORE_HOST", expectedHost)
	os.Setenv("SECRETSTORE_PORT", strconv.FormatInt(int64(expectedPort), 10))
	os.Setenv("SECRETSTORE_TOKENFILE", expectedTokenFile)
	os.Setenv("SECRETSTORE_RUNTIMETOKENPROVIDER_ENABLED", strconv.FormatBool(expectedRuntimeTokenProviderEnabled))
	os.Setenv("SECRETSTORE_RUNTIMETOKENPROVIDER_HOST", expectedRuntimeTokenProviderHost)
	os.Setenv("SECRETSTORE_RUNTIMETOKENPROVIDER_REQUIREDSECRETS", expectedRuntimeTokenProviderRequiredSecrets)

	lc := logger.NewMockClient()
	target, err := BuildSecretStoreConfig(expectedServiceKey, environment.NewVariables(lc), lc)
	require.NoError(t, err)

	require.NotEqual(t, bootstrapConfig.SecretStoreInfo{}, target)
	assert.Equal(t, expectedServiceKey, target.StoreName)
	assert.Equal(t, expectedHost, target.Host)
	assert.Equal(t, expectedPort, target.Port)
	assert.Equal(t, expectedTokenFile, target.TokenFile)
	assert.Equal(t, expectedRuntimeTokenProviderEnabled, target.RuntimeTokenProvider.Enabled)
	assert.Equal(t, expectedRuntimeTokenProviderHost, target.RuntimeTokenProvider.Host)
	assert.Equal(t, expectedRuntimeTokenProviderHost, target.RuntimeTokenProvider.Host)
	assert.Equal(t, expectedRuntimeTokenProviderRequiredSecrets, target.RuntimeTokenProvider.RequiredSecrets)
}

func TestBuildSecretStoreSetupClientConfig(t *testing.T) {
	expectedHost := "edgex-security-secretstore-setup"
	expectedPort := 59843
	expectedPrt := "http"

	os.Setenv("CLIENTS_SECURITY_SECRETSTORE_SETUP_HOST", expectedHost)

	lc := logger.NewMockClient()
	target, err := BuildSecretStoreSetupClientConfig(environment.NewVariables(lc), lc)
	require.NoError(t, err)

	require.NotEqual(t, &bootstrapConfig.ClientsCollection{}, target)
	require.NotNil(t, target)

	clientConfig := *target
	require.NotNil(t, clientConfig)
	require.Equal(t, expectedHost, clientConfig[common.SecuritySecretStoreSetupServiceKey].Host)
	require.Equal(t, expectedPort, clientConfig[common.SecuritySecretStoreSetupServiceKey].Port)
	require.Equal(t, expectedPrt, clientConfig[common.SecuritySecretStoreSetupServiceKey].Protocol)
}
