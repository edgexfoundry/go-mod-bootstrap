//
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.
//
// SPDX-License-Identifier: Apache-2.0
//

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/logging"
	"github.com/edgexfoundry/go-mod-bootstrap/config"
	"github.com/edgexfoundry/go-mod-bootstrap/di"

	"github.com/edgexfoundry/go-mod-secrets/pkg/providers/vault"
)

type configurationStruct struct {
	writable    writableInfo
	logging     config.LoggingInfo
	secretStore config.SecretStoreInfo
}

type writableInfo struct {
	logLevel string
}

func (c *configurationStruct) UpdateFromRaw(rawConfig interface{}) bool {
	return true
}

func (c *configurationStruct) EmptyWritablePtr() interface{} {
	return &writableInfo{}
}

func (c *configurationStruct) UpdateWritableFromRaw(rawWritable interface{}) bool {
	return true
}

func (c *configurationStruct) GetBootstrap() interfaces.BootstrapConfiguration {
	// temporary until we can make backwards-breaking configuration.toml change
	return interfaces.BootstrapConfiguration{
		Logging:     c.logging,
		SecretStore: c.secretStore,
	}
}

func (c *configurationStruct) GetLogLevel() string {
	return c.writable.logLevel
}

func (c *configurationStruct) GetRegistryInfo() config.RegistryInfo {
	return config.RegistryInfo{}
}

func TestGetClient(t *testing.T) {
	// run in parallel with other tests
	t.Parallel()

	// setup
	tokenPeriod := 6
	var tokenDataMap sync.Map
	// ttl > half of period
	tokenDataMap.Store("testToken1", vault.TokenLookupMetadata{
		Renewable: true,
		Ttl:       tokenPeriod * 7 / 10,
		Period:    tokenPeriod,
	})
	// ttl = half of period
	tokenDataMap.Store("testToken2", vault.TokenLookupMetadata{
		Renewable: true,
		Ttl:       tokenPeriod / 2,
		Period:    tokenPeriod,
	})
	// ttl < half of period
	tokenDataMap.Store("testToken3", vault.TokenLookupMetadata{
		Renewable: true,
		Ttl:       tokenPeriod * 3 / 10,
		Period:    tokenPeriod,
	})
	// to be expired token
	tokenDataMap.Store("toToExpiredToken", vault.TokenLookupMetadata{
		Renewable: true,
		Ttl:       1,
		Period:    tokenPeriod,
	})
	// expired token
	tokenDataMap.Store("expiredToken", vault.TokenLookupMetadata{
		Renewable: true,
		Ttl:       0,
		Period:    tokenPeriod,
	})
	// not renewable token
	tokenDataMap.Store("unrenewableToken", vault.TokenLookupMetadata{
		Renewable: false,
		Ttl:       0,
		Period:    tokenPeriod,
	})

	server := getMockTokenServer(&tokenDataMap)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Errorf("error on parsing server url %s: %s", server.URL, err)
	}
	host, port, _ := net.SplitHostPort(serverURL.Host)
	portNum, _ := strconv.Atoi(port)

	bkgCtx := context.Background()
	testSecretStoreInfo := config.SecretStoreInfo{
		Host:       host,
		Port:       portNum,
		Path:       "/test",
		Protocol:   "http",
		ServerName: "mockVaultServer",
	}
	lc := logging.FactoryToStdout("clientTest")

	testContainer := di.NewContainer(di.ServiceConstructorMap{
		container.ConfigurationInterfaceName: func(get di.Get) interface{} {
			return &configurationStruct{
				secretStore: testSecretStoreInfo,
			}
		},
		container.LoggingClientInterfaceName: func(get di.Get) interface{} {
			return lc
		},
	})

	tests := []struct {
		name                string
		authToken           string
		tokenFile           string
		expectedNilCallback bool
		expectedNewToken    string
		expectedRetry       bool
		expectError         bool
		expectedErrorType   error
	}{
		{
			name:                "New secret client with testToken1, more than half of TTL remaining",
			authToken:           "testToken1",
			tokenFile:           "testdata/replacement.json",
			expectedNilCallback: false,
			expectedNewToken:    "replacement-token",
			expectedRetry:       true,
			expectError:         false,
			expectedErrorType:   nil,
		},
		{
			name:                "New secret client with the same first token again",
			authToken:           "testToken1",
			tokenFile:           "testdata/replacement.json",
			expectedNilCallback: false,
			expectedNewToken:    "replacement-token",
			expectedRetry:       true,
			expectError:         false,
			expectedErrorType:   nil,
		},
		{
			name:                "New secret client with testToken2, half of TTL remaining",
			authToken:           "testToken2",
			expectedNilCallback: false,
			tokenFile:           "testdata/replacement.json",
			expectedNewToken:    "replacement-token",
			expectedRetry:       true,
			expectError:         false,
			expectedErrorType:   nil,
		},
		{
			name:                "New secret client with testToken3, less than half of TTL remaining",
			authToken:           "testToken3",
			tokenFile:           "testdata/replacement.json",
			expectedNilCallback: false,
			expectedNewToken:    "replacement-token",
			expectedRetry:       true,
			expectError:         false,
			expectedErrorType:   nil,
		},
		{
			name:                "New secret client with expired token, no TTL remaining",
			authToken:           "expiredToken",
			tokenFile:           "testdata/replacement.json",
			expectedNilCallback: false,
			expectedNewToken:    "replacement-token",
			expectedRetry:       true,
			expectError:         true,
			expectedErrorType:   nil,
		},
		{
			name:                "New secret client with expired token, non-existing TokenFile path",
			authToken:           "expiredToken",
			tokenFile:           "testdata/non-existing.json",
			expectedNilCallback: false,
			expectedNewToken:    "",
			expectedRetry:       false,
			expectError:         true,
			expectedErrorType:   nil,
		},
		{
			name:                "New secret client with expired test token, but same expired replacement token",
			authToken:           "test-token",
			tokenFile:           "testdata/testToken.json",
			expectedNilCallback: false,
			expectedNewToken:    "test-token",
			expectedRetry:       false,
			expectError:         true,
			expectedErrorType:   nil,
		},
		{
			name:                "New secret client with unauthenticated token",
			authToken:           "test-token",
			expectedNilCallback: true,
			expectedNewToken:    "",
			expectedRetry:       false,
			expectError:         true,
			expectedErrorType:   nil,
		},
		{
			name:                "New secret client with unrenewable token",
			authToken:           "unrenewableToken",
			expectedNilCallback: true,
			expectedNewToken:    "",
			expectedRetry:       true,
			expectError:         false,
			expectedErrorType:   nil,
		},
		{
			name:                "New secret client with no TokenFile",
			authToken:           "testToken1",
			tokenFile:           "",
			expectedNilCallback: true,
			expectedNewToken:    "",
			expectedRetry:       false,
			expectError:         false,
			expectedErrorType:   nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testSecretStoreInfo.TokenFile = test.tokenFile
			testContainer.Update(
				di.ServiceConstructorMap{
					container.ConfigurationInterfaceName: func(get di.Get) interface{} {
						return &configurationStruct{
							secretStore: testSecretStoreInfo,
						}
					},
				})
			cfgHTTP := vault.SecretConfig{
				Host:           host,
				Port:           portNum,
				Protocol:       "http",
				Authentication: vault.AuthenticationInfo{AuthToken: test.authToken},
			}

			sclient := NewSecretVaultClient(bkgCtx, cfgHTTP, testContainer)
			_, err := sclient.GetClient()

			if test.expectedErrorType != nil && err == nil {
				t.Errorf("Expected error %v but none was received", test.expectedErrorType)
			}

			if !test.expectError && err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			}

			if test.expectError && test.expectedErrorType != nil && err != nil {
				eet := reflect.TypeOf(test.expectedErrorType)
				aet := reflect.TypeOf(err)
				if !aet.AssignableTo(eet) {
					t.Errorf("Expected error of type %v, but got an error of type %v", eet, aet)
				}
			}

			tokenCallback := sclient.getDefaultTokenExpiredCallback(testSecretStoreInfo)
			if test.expectedNilCallback && tokenCallback != nil {
				t.Error("expected nil token expired callback func, but found not nil")
			}
			if !test.expectedNilCallback {
				if tokenCallback == nil {
					t.Error("expected some non-nil token expired callback func, but found nil")
				} else {
					repToken, retry := tokenCallback(test.authToken)

					if repToken != test.expectedNewToken {
						t.Errorf("expected a new token [%s] from callback but got [%s]", test.expectedNewToken, repToken)
					}

					if retry != test.expectedRetry {
						t.Errorf("expected retry %v for a default token expired callback but got %v", test.expectedRetry, retry)
					}

					lc.Debug(fmt.Sprintf("repToken = %s, retry = %v", repToken, retry))
				}
			}
		})
	}
	// wait for some time to allow renewToken to be run if any
	time.Sleep(7 * time.Second)
}

func getMockTokenServer(tokenDataMap *sync.Map) *httptest.Server {

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		urlPath := req.URL.String()
		if req.Method == http.MethodGet && urlPath == "/v1/auth/token/lookup-self" {
			token := req.Header.Get(vault.AuthTypeHeader)
			sampleTokenLookup, exists := tokenDataMap.Load(token)
			if !exists {
				rw.WriteHeader(403)
				_, _ = rw.Write([]byte("permission denied"))
			} else {
				resp := &vault.TokenLookupResponse{
					Data: sampleTokenLookup.(vault.TokenLookupMetadata),
				}
				if ret, err := json.Marshal(resp); err != nil {
					rw.WriteHeader(500)
					_, _ = rw.Write([]byte(err.Error()))
				} else {
					rw.WriteHeader(200)
					_, _ = rw.Write(ret)
				}
			}
		} else if req.Method == http.MethodPost && urlPath == "/v1/auth/token/renew-self" {
			token := req.Header.Get(vault.AuthTypeHeader)
			sampleTokenLookup, exists := tokenDataMap.Load(token)
			if !exists {
				rw.WriteHeader(403)
				_, _ = rw.Write([]byte("permission denied"))
			} else {
				currentTTL := sampleTokenLookup.(vault.TokenLookupMetadata).Ttl
				if currentTTL <= 0 {
					// already expired
					rw.WriteHeader(403)
					_, _ = rw.Write([]byte("permission denied"))
				} else {
					tokenPeriod := sampleTokenLookup.(vault.TokenLookupMetadata).Period

					tokenDataMap.Store(token, vault.TokenLookupMetadata{
						Renewable: true,
						Ttl:       tokenPeriod,
						Period:    tokenPeriod,
					})
					rw.WriteHeader(200)
					_, _ = rw.Write([]byte("token renewed"))
				}
			}
		} else {
			rw.WriteHeader(404)
			_, _ = rw.Write([]byte(fmt.Sprintf("Unknown urlPath: %s", urlPath)))
		}
	}))
	return server
}
