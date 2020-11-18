/********************************************************************************
 *  Copyright 2019 Dell Inc.
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
	"fmt"
	"sync"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/config"
	"github.com/edgexfoundry/go-mod-bootstrap/di"
	"github.com/edgexfoundry/go-mod-secrets/pkg/types"
	"github.com/edgexfoundry/go-mod-secrets/secrets"

	"github.com/edgexfoundry/go-mod-secrets/pkg/token/authtokenloader"
	"github.com/edgexfoundry/go-mod-secrets/pkg/token/fileioperformer"
)

// BootstrapHandler full initializes the Provider store manager.
func (p *Provider) BootstrapHandler(
	ctx context.Context,
	_ *sync.WaitGroup,
	startupTimer startup.Timer,
	dic *di.Container) bool {

	p.lc = container.LoggingClientFrom(dic.Get)
	p.configuration = container.ConfigurationFrom(dic.Get)

	// attempt to create a new SecretProvider client only if security is enabled.
	if p.IsSecurityEnabled() {
		var err error

		p.lc.Info("Creating SecretClient")

		secretStoreConfig := p.configuration.GetBootstrap().SecretStore

		for startupTimer.HasNotElapsed() {
			var secretConfig types.SecretConfig

			p.lc.Info("Reading secret store configuration and authentication token")

			secretConfig, err = p.getSecretConfig(secretStoreConfig, dic)
			if err == nil {
				var secretClient secrets.SecretClient

				p.lc.Info("Attempting to create secret client")
				secretClient, err = secrets.NewClient(ctx, secretConfig, p.lc, p.defaultTokenExpiredCallback)
				if err == nil {
					p.secretClient = secretClient
					p.lc.Info("Created SecretClient")
					break
				}
			}

			p.lc.Warn(fmt.Sprintf("Retryable failure while creating SecretClient: %s", err.Error()))
			startupTimer.SleepForInterval()
		}

		if err != nil {
			p.lc.Error(fmt.Sprintf("unable to create SecretClient: %s", err.Error()))
			return false
		}
	}

	dic.Update(di.ServiceConstructorMap{
		container.SecretProviderName: func(get di.Get) interface{} {
			return p
		},
	})

	return true
}

// getSecretConfig creates a SecretConfig based on the SecretStoreInfo configuration properties.
// If a token file is present it will override the Authentication.AuthToken value.
func (p *Provider) getSecretConfig(secretStoreInfo config.SecretStoreInfo, dic *di.Container) (types.SecretConfig, error) {
	secretConfig := types.SecretConfig{
		Host:                    secretStoreInfo.Host,
		Port:                    secretStoreInfo.Port,
		Path:                    secretStoreInfo.Path,
		Protocol:                secretStoreInfo.Protocol,
		Namespace:               secretStoreInfo.Namespace,
		RootCaCertPath:          secretStoreInfo.RootCaCertPath,
		ServerName:              secretStoreInfo.ServerName,
		Authentication:          secretStoreInfo.Authentication,
		AdditionalRetryAttempts: secretStoreInfo.AdditionalRetryAttempts,
		RetryWaitPeriod:         secretStoreInfo.RetryWaitPeriod,
	}

	if !p.IsSecurityEnabled() || secretStoreInfo.TokenFile == "" {
		return secretConfig, nil
	}

	// only bother getting a token if security is enabled and the configuration-provided token file is not empty.
	fileIoPerformer := container.FileIoPerformerFrom(dic.Get)
	if fileIoPerformer == nil {
		fileIoPerformer = fileioperformer.NewDefaultFileIoPerformer()
	}

	tokenLoader := container.AuthTokenLoaderFrom(dic.Get)
	if tokenLoader == nil {
		tokenLoader = authtokenloader.NewAuthTokenLoader(fileIoPerformer)
	}

	token, err := tokenLoader.Load(secretStoreInfo.TokenFile)
	if err != nil {
		return secretConfig, err
	}
	secretConfig.Authentication.AuthToken = token
	return secretConfig, nil
}
