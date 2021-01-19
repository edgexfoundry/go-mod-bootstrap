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

package handlers

import (
	"context"
	"fmt"
	"sync"

	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/secret"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/di"
	"github.com/edgexfoundry/go-mod-secrets/pkg/types"
	"github.com/edgexfoundry/go-mod-secrets/secrets"

	"github.com/edgexfoundry/go-mod-secrets/pkg/token/authtokenloader"
	"github.com/edgexfoundry/go-mod-secrets/pkg/token/fileioperformer"
)

// SecureProviderBootstrapHandler full initializes the Secret Provider.
func SecureProviderBootstrapHandler(
	ctx context.Context,
	_ *sync.WaitGroup,
	startupTimer startup.Timer,
	dic *di.Container) bool {
	lc := container.LoggingClientFrom(dic.Get)
	configuration := container.ConfigurationFrom(dic.Get)

	var provider interfaces.SecretProvider

	switch secret.IsSecurityEnabled() {
	case true:
		// attempt to create a new Secure client only if security is enabled.
		var err error

		lc.Info("Creating SecretClient")

		secretStoreConfig := configuration.GetBootstrap().SecretStore

		for startupTimer.HasNotElapsed() {
			var secretConfig types.SecretConfig

			lc.Info("Reading secret store configuration and authentication token")

			tokenLoader := container.AuthTokenLoaderFrom(dic.Get)
			if tokenLoader == nil {
				tokenLoader = authtokenloader.NewAuthTokenLoader(fileioperformer.NewDefaultFileIoPerformer())
			}

			secretConfig, err = getSecretConfig(secretStoreConfig, tokenLoader)
			if err == nil {
				secureProvider := secret.NewSecureProvider(configuration, lc, tokenLoader)
				var secretClient secrets.SecretClient

				lc.Info("Attempting to create secret client")
				secretClient, err = secrets.NewClient(ctx, secretConfig, lc, secureProvider.DefaultTokenExpiredCallback)
				if err == nil {
					secureProvider.SetClient(secretClient)
					provider = secureProvider
					lc.Info("Created SecretClient")
					break
				}
			}

			lc.Warn(fmt.Sprintf("Retryable failure while creating SecretClient: %s", err.Error()))
			startupTimer.SleepForInterval()
		}

		if err != nil {
			lc.Error(fmt.Sprintf("unable to create SecretClient: %s", err.Error()))
			return false
		}

	case false:
		provider = secret.NewInsecureProvider(configuration, lc)
	}

	dic.Update(di.ServiceConstructorMap{
		container.SecretProviderName: func(get di.Get) interface{} {
			return provider
		},
	})

	return true
}

// getSecretConfig creates a SecretConfig based on the SecretStoreInfo configuration properties.
// If a token file is present it will override the Authentication.AuthToken value.
func getSecretConfig(secretStoreInfo config.SecretStoreInfo, tokenLoader authtokenloader.AuthTokenLoader) (types.SecretConfig, error) {
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

	if !secret.IsSecurityEnabled() || secretStoreInfo.TokenFile == "" {
		return secretConfig, nil
	}

	token, err := tokenLoader.Load(secretStoreInfo.TokenFile)
	if err != nil {
		return secretConfig, err
	}

	secretConfig.Authentication.AuthToken = token
	return secretConfig, nil
}
