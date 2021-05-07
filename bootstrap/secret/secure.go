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
	"sync"
	"time"

	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/interfaces"

	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
	"github.com/edgexfoundry/go-mod-secrets/v2/pkg/token/authtokenloader"
	"github.com/edgexfoundry/go-mod-secrets/v2/secrets"
)

const TokenTypeConsul = "consul"

// SecureProvider implements the SecretProvider interface
type SecureProvider struct {
	secretClient  secrets.SecretClient
	lc            logger.LoggingClient
	loader        authtokenloader.AuthTokenLoader
	configuration interfaces.Configuration
	secretsCache  map[string]map[string]string // secret's path, key, value
	cacheMutex    *sync.RWMutex
	lastUpdated   time.Time
}

// NewSecureProvider creates & initializes Provider instance for secure secrets.
func NewSecureProvider(config interfaces.Configuration, lc logger.LoggingClient, loader authtokenloader.AuthTokenLoader) *SecureProvider {
	provider := &SecureProvider{
		configuration: config,
		lc:            lc,
		loader:        loader,
		secretsCache:  make(map[string]map[string]string),
		cacheMutex:    &sync.RWMutex{},
		lastUpdated:   time.Now(),
	}
	return provider
}

// SetClient sets the secret client that is used to access the secure secrets
func (p *SecureProvider) SetClient(client secrets.SecretClient) {
	p.secretClient = client
}

// GetSecret retrieves secrets from a secret store.
// path specifies the type or location of the secrets to retrieve.
// keys specifies the secrets which to retrieve. If no keys are provided then all the keys associated with the
// specified path will be returned.
func (p *SecureProvider) GetSecret(path string, keys ...string) (map[string]string, error) {
	if cachedSecrets := p.getSecretsCache(path, keys...); cachedSecrets != nil {
		return cachedSecrets, nil
	}

	if p.secretClient == nil {
		return nil, errors.New("can't get secrets. Secure secret provider is not properly initialized")
	}

	secureSecrets, err := p.secretClient.GetSecrets(path, keys...)
	if err != nil {
		return nil, err
	}

	p.updateSecretsCache(path, secureSecrets)
	return secureSecrets, nil
}

func (p *SecureProvider) getSecretsCache(path string, keys ...string) map[string]string {
	secureSecrets := make(map[string]string)

	// Synchronize cache access
	p.cacheMutex.RLock()
	defer p.cacheMutex.RUnlock()

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
			secureSecrets[key] = value
		}

		// return secureSecrets if the requested keys exist in cache
		if allKeysExistInCache {
			return secureSecrets
		}
	}

	return nil
}

func (p *SecureProvider) updateSecretsCache(path string, secrets map[string]string) {
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

// StoreSecret stores the secrets to a secret store.
// it sets the values requested at provided keys
// path specifies the type or location of the secrets to store
// secrets map specifies the "key": "value" pairs of secrets to store
func (p *SecureProvider) StoreSecret(path string, secrets map[string]string) error {
	if p.secretClient == nil {
		return errors.New("can't store secrets. Secure secret provider is not properly initialized")
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

// SecretsUpdated is not need for secure secrets as this is handled when secrets are stored.
func (p *SecureProvider) SecretsUpdated() {
	// Do nothing
}

// SecretsLastUpdated returns the last time secure secrets were updated
func (p *SecureProvider) SecretsLastUpdated() time.Time {
	return p.lastUpdated
}

// GetAccessToken returns the access token for the requested token type.
func (p *SecureProvider) GetAccessToken(tokenType string, serviceKey string) (string, error) {
	switch tokenType {
	case TokenTypeConsul:
		return p.secretClient.GenerateConsulToken(serviceKey)
	default:
		return "", fmt.Errorf("invalid access token type '%s'", tokenType)
	}
}

// defaultTokenExpiredCallback is the default implementation of tokenExpiredCallback function
// It utilizes the tokenFile to re-read the token and enable retry if any update from the expired token
func (p *SecureProvider) DefaultTokenExpiredCallback(expiredToken string) (replacementToken string, retry bool) {
	tokenFile := p.configuration.GetBootstrap().SecretStore.TokenFile

	// during the callback, we want to re-read the token from the disk
	// specified by tokenFile and set the retry to true if a new token
	// is different from the expiredToken
	reReadToken, err := p.loader.Load(tokenFile)
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
