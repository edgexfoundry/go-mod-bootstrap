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

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/config"
	"github.com/edgexfoundry/go-mod-bootstrap/di"

	"github.com/edgexfoundry/go-mod-secrets/pkg"
	"github.com/edgexfoundry/go-mod-secrets/pkg/providers/vault"
	"github.com/edgexfoundry/go-mod-secrets/pkg/token/authtokenloader"
	"github.com/edgexfoundry/go-mod-secrets/pkg/token/fileioperformer"
)

type SecretVaultClient struct {
	ctx    *context.Context
	config *vault.SecretConfig
	dic    *di.Container
}

func NewSecretVaultClient(
	ctx context.Context,
	config vault.SecretConfig,
	dic *di.Container) SecretVaultClient {
	return SecretVaultClient{
		ctx:    &ctx,
		config: &config,
		dic:    dic,
	}
}

func (c SecretVaultClient) GetClient() (pkg.SecretClient, error) {

	lc := container.LoggingClientFrom(c.dic.Get)
	configuration := container.ConfigurationFrom(c.dic.Get)
	secretStoreInfo := configuration.GetBootstrap().SecretStore

	return vault.NewSecretClientFactory().NewSecretClient(
		*c.ctx,
		*c.config,
		lc,
		c.getDefaultTokenExpiredCallback(secretStoreInfo))
}

func (c SecretVaultClient) getDefaultTokenExpiredCallback(
	secretStoreInfo config.SecretStoreInfo) func(expiredToken string) (replacementToken string, retry bool) {
	// if there is no tokenFile, then no replacement token can be used and hence no callback
	if secretStoreInfo.TokenFile == "" {
		return nil
	}

	lc := container.LoggingClientFrom(c.dic.Get)
	tokenFile := secretStoreInfo.TokenFile
	return func(expiredToken string) (replacementToken string, retry bool) {
		// during the callback, we want to re-read the token from the disk
		// specified by tokenFile and set the retry to true if a new token
		// is different from the expiredToken
		fileIoPerformer := fileioperformer.NewDefaultFileIoPerformer()
		authTokenLoader := authtokenloader.NewAuthTokenLoader(fileIoPerformer)
		reReadToken, err := authTokenLoader.Load(tokenFile)
		if err != nil {
			lc.Error(fmt.Sprintf("fail to load auth token from tokenFile %s: %v", tokenFile, err))
			return "", false
		}

		if reReadToken == expiredToken {
			lc.Error("No new replacement token found for the expired token")
			return reReadToken, false
		}

		return reReadToken, true
	}
}
