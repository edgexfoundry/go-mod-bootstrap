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
	"os"
	"sync"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/handlers/secret/client"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/config"
	"github.com/edgexfoundry/go-mod-bootstrap/di"

	"github.com/edgexfoundry/go-mod-secrets/pkg"
	"github.com/edgexfoundry/go-mod-secrets/pkg/providers/vault"
	"github.com/edgexfoundry/go-mod-secrets/pkg/token/authtokenloader"
	"github.com/edgexfoundry/go-mod-secrets/pkg/token/fileioperformer"
)

type SecretProvider struct {
	secretClient pkg.SecretClient
}

func NewSecret() *SecretProvider {
	return &SecretProvider{}
}

// BootstrapHandler creates a secretClient to be used for obtaining secrets from a SecretProvider store manager.
// NOTE: This BootstrapHandler is responsible for creating a utility that will most likely be used by other
// BootstrapHandlers to obtain sensitive data, such as database credentials. This BootstrapHandler should be processed
// before other BootstrapHandlers, possibly even first since it has not other dependencies.
func (s *SecretProvider) BootstrapHandler(
	ctx context.Context,
	_ *sync.WaitGroup,
	startupTimer startup.Timer,
	dic *di.Container) bool {

	lc := container.LoggingClientFrom(dic.Get)

	// attempt to create a new SecretProvider client only if security is enabled.
	if s.isSecurityEnabled() {
		var err error

		lc.Info("Creating SecretClient")

		configuration := container.ConfigurationFrom(dic.Get)
		secretStoreConfig := configuration.GetBootstrap().SecretStore

		for startupTimer.HasNotElapsed() {
			var secretConfig vault.SecretConfig

			lc.Info("Reading secret store configuration and authentication token")

			secretConfig, err = s.getSecretConfig(secretStoreConfig)
			if err == nil {
				var secretClient pkg.SecretClient

				lc.Info("Attempting to create secretclient")
				secretClient, err = client.NewVault(ctx, secretConfig, lc).Get(configuration.GetBootstrap().SecretStore)
				if err == nil {
					s.secretClient = secretClient
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
	}

	dic.Update(di.ServiceConstructorMap{
		container.CredentialsProviderName: func(get di.Get) interface{} {
			return s
		},
	})

	return true
}

// getSecretConfig creates a SecretConfig based on the SecretStoreInfo configuration properties.
// If a tokenfile is present it will override the Authentication.AuthToken value.
func (s *SecretProvider) getSecretConfig(secretStoreInfo config.SecretStoreInfo) (vault.SecretConfig, error) {
	secretConfig := vault.SecretConfig{
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

	if !s.isSecurityEnabled() || secretStoreInfo.TokenFile == "" {
		return secretConfig, nil
	}

	// only bother getting a token if security is enabled and the configuration-provided tokenfile is not empty.
	fileIoPerformer := fileioperformer.NewDefaultFileIoPerformer()
	authTokenLoader := authtokenloader.NewAuthTokenLoader(fileIoPerformer)

	token, err := authTokenLoader.Load(secretStoreInfo.TokenFile)
	if err != nil {
		return secretConfig, err
	}
	secretConfig.Authentication.AuthToken = token
	return secretConfig, nil
}

// isSecurityEnabled determines if security has been enabled.
func (s *SecretProvider) isSecurityEnabled() bool {
	env := os.Getenv("EDGEX_SECURITY_SECRET_STORE")
	return env != "false"
}
