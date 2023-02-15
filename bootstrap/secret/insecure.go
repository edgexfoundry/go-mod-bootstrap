/*******************************************************************************
 * Copyright 2020-2023 Intel Corporation
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
	"strings"
	"time"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/interfaces"
	gometrics "github.com/rcrowley/go-metrics"

	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
)

// InsecureProvider implements the SecretProvider interface for insecure secrets
type InsecureProvider struct {
	lc                        logger.LoggingClient
	configuration             interfaces.Configuration
	lastUpdated               time.Time
	registeredSecretCallbacks map[string]func(secretName string)
	securitySecretsRequested  gometrics.Counter
	securitySecretsStored     gometrics.Counter
}

// NewInsecureProvider creates, initializes Provider for insecure secrets.
func NewInsecureProvider(config interfaces.Configuration, lc logger.LoggingClient) *InsecureProvider {
	return &InsecureProvider{
		configuration:             config,
		lc:                        lc,
		lastUpdated:               time.Now(),
		registeredSecretCallbacks: make(map[string]func(secretName string)),
		securitySecretsRequested:  gometrics.NewCounter(),
		securitySecretsStored:     gometrics.NewCounter(),
	}
}

// GetSecret retrieves secrets from a Insecure Secrets secret store.
// secretName specifies the type or location of the secrets to retrieve.
// keys specifies the secrets which to retrieve. If no keys are provided then all the keys associated with the
// specified secretName will be returned.
func (p *InsecureProvider) GetSecret(secretName string, keys ...string) (map[string]string, error) {
	p.securitySecretsRequested.Inc(1)

	results := make(map[string]string)
	secretNameExists := false
	var missingKeys []string

	insecureSecrets := p.configuration.GetInsecureSecrets()
	if insecureSecrets == nil {
		err := fmt.Errorf("InsecureSecrets missing from configuration")
		return nil, err
	}

	for _, insecureSecret := range insecureSecrets {
		if insecureSecret.SecretName == secretName {
			if len(keys) == 0 {
				// If no keys are provided then all the keys associated with the specified secretName will be returned
				for k, v := range insecureSecret.Secrets {
					results[k] = v
				}
				return results, nil
			}

			secretNameExists = true
			for _, key := range keys {
				value, keyExists := insecureSecret.Secrets[key]
				if !keyExists {
					missingKeys = append(missingKeys, key)
					continue
				}
				results[key] = value
			}
		}
	}

	if len(missingKeys) > 0 {
		err := fmt.Errorf("No value for the keys: [%s] exists", strings.Join(missingKeys, ","))
		return nil, err
	}

	if !secretNameExists {
		// if secretName is not in secret store
		err := fmt.Errorf("Error, secretName (%v) doesn't exist in secret store", secretName)
		return nil, err
	}

	return results, nil
}

// StoreSecret stores the secrets, but is not supported for Insecure Secrets
func (p *InsecureProvider) StoreSecret(_ string, _ map[string]string) error {
	return errors.New("storing secrets is not supported when running in insecure mode")
}

// SecretsUpdated resets LastUpdate time for the Insecure Secrets.
func (p *InsecureProvider) SecretsUpdated() {
	p.lastUpdated = time.Now()
}

// SecretsLastUpdated returns the last time insecure secrets were updated
func (p *InsecureProvider) SecretsLastUpdated() time.Time {
	return p.lastUpdated
}

// GetAccessToken returns the AccessToken for the specified type, which in insecure mode is not need
// so just returning an empty token.
func (p *InsecureProvider) GetAccessToken(_ string, _ string) (string, error) {
	return "", nil
}

// HasSecret returns true if the service's SecretStore contains a secret at the specified secretName.
func (p *InsecureProvider) HasSecret(secretName string) (bool, error) {
	insecureSecrets := p.configuration.GetInsecureSecrets()
	if insecureSecrets == nil {
		err := fmt.Errorf("InsecureSecret missing from configuration")
		return false, err
	}

	for _, insecureSecret := range insecureSecrets {
		if insecureSecret.SecretName == secretName {
			return true, nil
		}
	}

	return false, nil
}

// ListSecretSecretNames returns a list of SecretName for the current service from an insecure/secure secret store.
func (p *InsecureProvider) ListSecretNames() ([]string, error) {
	var results []string

	insecureSecrets := p.configuration.GetInsecureSecrets()
	if insecureSecrets == nil {
		err := fmt.Errorf("InsecureSecrets missing from configuration")
		return nil, err
	}

	for _, insecureSecret := range insecureSecrets {
		results = append(results, insecureSecret.SecretName)
	}

	return results, nil
}

// RegisteredSecretUpdatedCallback registers a callback for a secret.
func (p *InsecureProvider) RegisteredSecretUpdatedCallback(secretName string, callback func(secretName string)) error {
	if _, ok := p.registeredSecretCallbacks[secretName]; ok {
		return fmt.Errorf("there is a callback already registered for secretName '%v'", secretName)
	}

	// Register new call back for secretName.
	p.registeredSecretCallbacks[secretName] = callback

	return nil
}

// SecretUpdatedAtSecretName performs updates and callbacks for an updated secret or secretName.
func (p *InsecureProvider) SecretUpdatedAtSecretName(secretName string) {
	p.securitySecretsStored.Inc(1)

	p.lastUpdated = time.Now()
	if p.registeredSecretCallbacks != nil {
		// Execute Callback for provided secretName.
		for k, v := range p.registeredSecretCallbacks {
			if k == secretName {
				p.lc.Debugf("invoking callback registered for secretName: '%s'", secretName)
				v(secretName)
				return
			}
		}
	}
}

// DeregisterSecretUpdatedCallback removes a secret's registered callback secretName.
func (p *InsecureProvider) DeregisterSecretUpdatedCallback(secretName string) {
	// Remove secretName from map.
	delete(p.registeredSecretCallbacks, secretName)
}

// GetMetricsToRegister returns all metric objects that needs to be registered.
func (p *InsecureProvider) GetMetricsToRegister() map[string]interface{} {
	return map[string]interface{}{
		secretsRequestedMetricName: p.securitySecretsRequested,
		secretsStoredMetricName:    p.securitySecretsStored,
	}
}

// GetSelfJWT returns an encoded JWT for the current identity-based secret store token
func (p *InsecureProvider) GetSelfJWT() (string, error) {
	// If security is disabled, return an empty string
	// It is presumed HTTP invokers will not add an
	// authorization token that is empty to outbound requests.
	return "", nil
}

// IsJWTValid evaluates a given JWT and returns a true/false if the JWT is valid (i.e. belongs to us and current) or not
func (p *InsecureProvider) IsJWTValid(jwt string) (bool, error) {
	return true, nil
}
