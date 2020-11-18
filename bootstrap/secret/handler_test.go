/*******************************************************************************
 * Copyright 2020 Intel Inc.
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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/di"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"github.com/edgexfoundry/go-mod-secrets/pkg/token/authtokenloader/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testTokenResponse = `{"auth":{"accessor":"9OvxnrjgV0JTYMeBydak7YJ9","client_token":"s.oPJ8uuJCkTRb2RDdcNvaz8wg","entity_id":"","lease_duration":3600,"metadata":{"edgex-service-name":"edgex-core-data"},"orphan":true,"policies":["default","edgex-service-edgex-core-data"],"renewable":true,"token_policies":["default","edgex-service-edgex-core-data"],"token_type":"service"},"data":null,"lease_duration":0,"lease_id":"","renewable":false,"request_id":"ee749ee1-c8bf-6fa9-3ed5-644181fc25b0","warnings":null,"wrap_info":null}`

func TestProvider_BootstrapHandler(t *testing.T) {
	timer := startup.NewStartUpTimer("UnitTest")

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(testTokenResponse))
	}))
	defer testServer.Close()

	url, _ := url.Parse(testServer.URL)
	port, _ := strconv.Atoi(url.Port())
	config := NewTestConfig(port)

	mockTokenLoader := &mocks.AuthTokenLoader{}
	mockTokenLoader.On("Load", "token.json").Return("Test Token", nil)
	dic := di.NewContainer(di.ServiceConstructorMap{
		container.LoggingClientInterfaceName: func(get di.Get) interface{} {
			return logger.NewClientStdOut("TestProvider_BootstrapHandler", false, "DEBUG")
		},
		container.ConfigurationInterfaceName: func(get di.Get) interface{} {
			return config
		},
		container.AuthTokenLoaderInterfaceName: func(get di.Get) interface{} {
			return mockTokenLoader
		},
	})

	target := NewProvider()
	actual := target.BootstrapHandler(context.Background(), &sync.WaitGroup{}, timer, dic)
	require.True(t, actual)
	assert.NotNil(t, container.SecretProviderFrom(dic.Get))
}
