/*******************************************************************************
 * Copyright 2018 Dell Inc.
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
	"errors"
	"fmt"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"github.com/edgexfoundry/go-mod-secrets/pkg/token/authtokenloader"
	"github.com/edgexfoundry/go-mod-secrets/pkg/token/fileioperformer"
	"github.com/edgexfoundry/go-mod-secrets/secrets"

	"os"
	"strings"
	"sync"
	"time"
)

const (
	EnvSecretStore = "EDGEX_SECURITY_SECRET_STORE"
	UsernameKey    = "username"
	PasswordKey    = "password"
)

// Provider implements the SecretProvider interface
type Provider struct {
	secretClient  secrets.SecretClient
	lc            logger.LoggingClient
	configuration interfaces.Configuration
	secretsCache  map[string]map[string]string // secret's path, key, value
	cacheMutex    *sync.Mutex
	lastUpdated   time.Time
}

// NewProvider creates, basic initializes and returns a new Provider instance.
// The full initialization occurs in the bootstrap handler.
func NewProvider() *Provider {
	return &Provider{
		secretsCache: make(map[string]map[string]string),
		cacheMutex:   &sync.Mutex{},
		lastUpdated:  time.Now(),
	}
}

// NewProviderWithDependents creates, initializes and returns a new full initialized Provider instance.
func NewProviderWithDependents(client secrets.SecretClient, config interfaces.Configuration, lc logger.LoggingClient) *Provider {
	provider := NewProvider()
	provider.secretClient = client
	provider.configuration = config
	provider.lc = lc
	return provider
}

// GetSecrets retrieves secrets from a secret store.
// path specifies the type or location of the secrets to retrieve.
// keys specifies the secrets which to retrieve. If no keys are provided then all the keys associated with the
// specified path will be returned.
func (p *Provider) GetSecrets(path string, keys ...string) (map[string]string, error) {
	if !p.IsSecurityEnabled() {
		return p.getInsecureSecrets(path, keys...)
	}

	if cachedSecrets := p.getSecretsCache(path, keys...); cachedSecrets != nil {
		return cachedSecrets, nil
	}

	if p.secretClient == nil {
		return nil, errors.New("can't get secret(p), secret client is not properly initialized")
	}

	secrets, err := p.secretClient.GetSecrets(path, keys...)
	if err != nil {
		return nil, err
	}

	p.updateSecretsCache(path, secrets)
	return secrets, nil
}

// GetInsecureSecrets retrieves secrets from the Writable.InsecureSecrets section of the configuration
// path specifies the type or location of the secrets to retrieve.
// keys specifies the secrets which to retrieve. If no keys are provided then all the keys associated with the
// specified path will be returned.
func (p *Provider) getInsecureSecrets(path string, keys ...string) (map[string]string, error) {
	secrets := make(map[string]string)
	pathExists := false
	var missingKeys []string

	insecureSecrets := p.configuration.GetInsecureSecrets()
	if insecureSecrets == nil {
		err := fmt.Errorf("InsecureSecrets missing from configuration")
		return nil, err
	}

	for _, insecureSecret := range insecureSecrets {
		if insecureSecret.Path == path {
			if len(keys) == 0 {
				// If no keys are provided then all the keys associated with the specified path will be returned
				for k, v := range insecureSecret.Secrets {
					secrets[k] = v
				}
				return secrets, nil
			}

			pathExists = true
			for _, key := range keys {
				value, keyExists := insecureSecret.Secrets[key]
				if !keyExists {
					missingKeys = append(missingKeys, key)
					continue
				}
				secrets[key] = value
			}
		}
	}

	if len(missingKeys) > 0 {
		err := fmt.Errorf("No value for the keys: [%s] exists", strings.Join(missingKeys, ","))
		return nil, err
	}

	if !pathExists {
		// if path is not in secret store
		err := fmt.Errorf("Error, path (%v) doesn't exist in secret store", path)
		return nil, err
	}

	return secrets, nil
}

func (p *Provider) getSecretsCache(path string, keys ...string) map[string]string {
	secrets := make(map[string]string)

	// Synchronize cache access
	p.cacheMutex.Lock()
	defer p.cacheMutex.Unlock()

	// check cache for keys
	allKeysExistInCache := false
	cachedSecrets, cacheExists := p.secretsCache[path]
	value := ""

	if cacheExists {
		for _, key := range keys {
			value, allKeysExistInCache = cachedSecrets[key]
			if !allKeysExistInCache {
				return nil
			}
			secrets[key] = value
		}

		// return secrets if the requested keys exist in cache
		if allKeysExistInCache {
			return secrets
		}
	}

	return nil
}

func (p *Provider) updateSecretsCache(path string, secrets map[string]string) {
	// Synchronize cache access
	p.cacheMutex.Lock()
	defer p.cacheMutex.Unlock()

	if _, cacheExists := p.secretsCache[path]; !cacheExists {
		p.secretsCache[path] = secrets
	}

	for key, value := range secrets {
		p.secretsCache[path][key] = value
	}
}

// StoreSecrets stores the secrets to a secret store.
// it sets the values requested at provided keys
// path specifies the type or location of the secrets to store
// secrets map specifies the "key": "value" pairs of secrets to store
func (p *Provider) StoreSecrets(path string, secrets map[string]string) error {
	if !p.IsSecurityEnabled() {
		return errors.New("storing secrets is not supported when running in insecure mode")
	}

	if p.secretClient == nil {
		return errors.New("can't store secret(p) 'SecretProvider' is not properly initialized")
	}

	err := p.secretClient.StoreSecrets(path, secrets)
	if err != nil {
		return err
	}

	// Synchronize cache access before clearing
	p.cacheMutex.Lock()
	// Clearing cache because adding a new secret(p) possibly invalidates the previous cache
	p.secretsCache = make(map[string]map[string]string)
	p.cacheMutex.Unlock()
	//indicate to the SDK that the cache has been invalidated
	p.lastUpdated = time.Now()
	return nil
}

// InsecureSecretsUpdated resets LastUpdate if not running in secure mode. If running in secure mode, changes to
// InsecureSecrets have no impact and are not used.
func (p *Provider) InsecureSecretsUpdated() {
	if !p.IsSecurityEnabled() {
		p.lastUpdated = time.Now()
	}
}

func (p *Provider) SecretsLastUpdated() time.Time {
	return p.lastUpdated
}

// isSecurityEnabled determines if security has been enabled.
func (p *Provider) IsSecurityEnabled() bool {
	env := os.Getenv(EnvSecretStore)
	return env != "false" // Any other value is considered secure mode enabled
}

// defaultTokenExpiredCallback is the default implementation of tokenExpiredCallback function
// It utilizes the tokenFile to re-read the token and enable retry if any update from the expired token
func (p *Provider) defaultTokenExpiredCallback(expiredToken string) (replacementToken string, retry bool) {
	tokenFile := p.configuration.GetBootstrap().SecretStore.TokenFile

	// during the callback, we want to re-read the token from the disk
	// specified by tokenFile and set the retry to true if a new token
	// is different from the expiredToken
	fileIoPerformer := fileioperformer.NewDefaultFileIoPerformer()
	authTokenLoader := authtokenloader.NewAuthTokenLoader(fileIoPerformer)
	reReadToken, err := authTokenLoader.Load(tokenFile)
	if err != nil {
		p.lc.Error(fmt.Sprintf("fail to load auth token from tokenFile %s: %v", tokenFile, err))
		return "", false
	}

	if reReadToken == expiredToken {
		p.lc.Error("No new replacement token found for the expired token")
		return reReadToken, false
	}

	return reReadToken, true
}
