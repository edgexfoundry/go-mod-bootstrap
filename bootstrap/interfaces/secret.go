package interfaces

import "time"

type SecretProvider interface {
	// StoreSecrets stores new secrets into the service's SecretStore at the specified path.
	StoreSecrets(path string, secrets map[string]string) error

	// GetSecrets retrieves secrets from the service's SecretStore at the specified path.
	GetSecrets(path string, keys ...string) (map[string]string, error)

	// InsecureSecretsUpdated sets the secrets last updated time to current time.
	// ignored if in secure mode. Needed for InsecureSecrets support in non-secure mode.
	InsecureSecretsUpdated()

	// SecretsLastUpdated returns the last time secrets were updated
	SecretsLastUpdated() time.Time

	// IsSecurityEnabled return boolean indicating if running in secure mode or not
	IsSecurityEnabled() bool
}
