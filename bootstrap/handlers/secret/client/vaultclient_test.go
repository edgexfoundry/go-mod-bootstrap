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
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/logging"
	"github.com/edgexfoundry/go-mod-bootstrap/config"

	"github.com/edgexfoundry/go-mod-secrets/pkg/providers/vault"
)

func TestGetVaultClient(t *testing.T) {
	// setup
	tokenPeriod := 6
	tokenDataMap := initTokenData(tokenPeriod)
	server := getMockTokenServer(tokenDataMap)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Errorf("error on parsing server url %s: %s", server.URL, err)
	}
	host, port, _ := net.SplitHostPort(serverURL.Host)
	portNum, _ := strconv.Atoi(port)

	bkgCtx := context.Background()
	lc := logging.FactoryToStdout("clientTest")

	testSecretStoreInfo := config.SecretStoreInfo{
		Host:       host,
		Port:       portNum,
		Path:       "/test",
		Protocol:   "http",
		ServerName: "mockVaultServer",
	}

	tests := []struct {
		name                string
		authToken           string
		tokenFile           string
		expectedNewToken    string
		expectedNilCallback bool
		expectedRetry       bool
		expectError         bool
	}{
		{
			name:                "New secret client with testToken1, more than half of TTL remaining",
			authToken:           "testToken1",
			tokenFile:           "testdata/replacement.json",
			expectedNilCallback: false,
			expectedNewToken:    "replacement-token",
			expectedRetry:       true,
			expectError:         false,
		},
		{
			name:                "New secret client with the same first token again",
			authToken:           "testToken1",
			tokenFile:           "testdata/replacement.json",
			expectedNilCallback: false,
			expectedNewToken:    "replacement-token",
			expectedRetry:       true,
			expectError:         false,
		},
		{
			name:                "New secret client with testToken2, half of TTL remaining",
			authToken:           "testToken2",
			expectedNilCallback: false,
			tokenFile:           "testdata/replacement.json",
			expectedNewToken:    "replacement-token",
			expectedRetry:       true,
			expectError:         false,
		},
		{
			name:                "New secret client with testToken3, less than half of TTL remaining",
			authToken:           "testToken3",
			tokenFile:           "testdata/replacement.json",
			expectedNilCallback: false,
			expectedNewToken:    "replacement-token",
			expectedRetry:       true,
			expectError:         false,
		},
		{
			name:                "New secret client with expired token, no TTL remaining",
			authToken:           "expiredToken",
			tokenFile:           "testdata/replacement.json",
			expectedNilCallback: false,
			expectedNewToken:    "replacement-token",
			expectedRetry:       true,
			expectError:         true,
		},
		{
			name:                "New secret client with expired token, non-existing TokenFile path",
			authToken:           "expiredToken",
			tokenFile:           "testdata/non-existing.json",
			expectedNilCallback: false,
			expectedNewToken:    "",
			expectedRetry:       false,
			expectError:         true,
		},
		{
			name:                "New secret client with expired test token, but same expired replacement token",
			authToken:           "test-token",
			tokenFile:           "testdata/testToken.json",
			expectedNilCallback: false,
			expectedNewToken:    "test-token",
			expectedRetry:       false,
			expectError:         true,
		},
		{
			name:                "New secret client with unauthenticated token",
			authToken:           "test-token",
			expectedNilCallback: true,
			expectedNewToken:    "",
			expectedRetry:       false,
			expectError:         true,
		},
		{
			name:                "New secret client with unrenewable token",
			authToken:           "unrenewableToken",
			expectedNilCallback: true,
			expectedNewToken:    "",
			expectedRetry:       true,
			expectError:         false,
		},
		{
			name:                "New secret client with no TokenFile",
			authToken:           "testToken1",
			tokenFile:           "",
			expectedNilCallback: true,
			expectedNewToken:    "",
			expectedRetry:       false,
			expectError:         false,
		},
	}

	for _, test := range tests {
		testSecretStoreInfo.TokenFile = test.tokenFile
		// pinned local variables to avoid scopelint warnings
		testToken := test.authToken
		cfgHTTP := vault.SecretConfig{
			Host:           host,
			Port:           portNum,
			Protocol:       "http",
			Authentication: vault.AuthenticationInfo{AuthToken: testToken},
		}
		expectError := test.expectError
		expectedCallbackNil := test.expectedNilCallback
		expectedNewToken := test.expectedNewToken
		expectedRetry := test.expectedRetry

		t.Run(test.name, func(t *testing.T) {
			sclient := NewVault(bkgCtx, cfgHTTP, lc)
			_, err := sclient.Get(testSecretStoreInfo)

			if expectError && err == nil {
				t.Error("Expected error but none was received")
			}

			if !expectError && err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			}

			tokenCallback := sclient.getDefaultTokenExpiredCallback(testSecretStoreInfo)
			if expectedCallbackNil && tokenCallback != nil {
				t.Error("expected nil token expired callback func, but found not nil")
			}
			if !expectedCallbackNil {
				if tokenCallback == nil {
					t.Error("expected some non-nil token expired callback func, but found nil")
				} else {
					repToken, retry := tokenCallback(testToken)

					if repToken != expectedNewToken {
						t.Errorf("expected a new token [%s] from callback but got [%s]", expectedNewToken, repToken)
					}

					if retry != expectedRetry {
						t.Errorf("expected retry %v for a default token expired callback but got %v", expectedRetry, retry)
					}

					lc.Debug(fmt.Sprintf("repToken = %s, retry = %v", repToken, retry))
				}
			}
		})
	}
	// wait for some time to allow renewToken to be run if any
	time.Sleep(7 * time.Second)
}

func initTokenData(tokenPeriod int) *sync.Map {
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

	return &tokenDataMap
}
