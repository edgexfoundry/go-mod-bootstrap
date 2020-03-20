/*******************************************************************************
 * Copyright 2018 Dell Inc.
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
package config

import (
	"fmt"
	"time"

	"github.com/edgexfoundry/go-mod-core-contracts/clients"

	"github.com/edgexfoundry/go-mod-secrets/pkg/providers/vault"
)

// ServiceInfo contains configuration settings necessary for the basic operation of any EdgeX service.
type ServiceInfo struct {
	// BootTimeout indicates, in milliseconds, how long the service will retry connecting to upstream dependencies
	// before giving up. Default is 30,000.
	BootTimeout int
	// Health check interval
	CheckInterval string
	// Indicates the interval in milliseconds at which service clients should check for any configuration updates
	ClientMonitor int
	// Host is the hostname or IP address of the service.
	Host string
	// Port is the HTTP port of the service.
	Port int
	// The protocol that should be used to call this service
	Protocol string
	// StartupMsg specifies a string to log once service
	// initialization and startup is completed.
	StartupMsg string
	// MaxResultCount specifies the maximum size list supported
	// in response to REST calls to other services.
	MaxResultCount int
	// Timeout specifies a timeout (in milliseconds) for
	// processing REST calls from other services.
	Timeout int
}

// HealthCheck is a URL specifying a health check REST endpoint used by the Registry to determine if the
// service is available.
func (s ServiceInfo) HealthCheck() string {
	hc := fmt.Sprintf("%s://%s:%v%s", s.Protocol, s.Host, s.Port, clients.ApiPingRoute)
	return hc
}

// Url provides a way to obtain the full url of the host service for use in initialization or, in some cases,
// responses to a caller.
func (s ServiceInfo) Url() string {
	url := fmt.Sprintf("%s://%s:%v", s.Protocol, s.Host, s.Port)
	return url
}

// ConfigProviderInfo defines the type and location (via host/port) of the desired configuration provider (e.g. Consul, Eureka)
type ConfigProviderInfo struct {
	Host string
	Port int
	Type string
}

// RegistryInfo defines the type and location (via host/port) of the desired service registry (e.g. Consul, Eureka)
type RegistryInfo struct {
	Host string
	Port int
	Type string
}

// LoggingInfo provides basic parameters related to where logs should be written.
type LoggingInfo struct {
	EnableRemote bool
	File         string
}

// StartupInfo provides the startup timer values which are applied to the StartupTimer created at boot.
type StartupInfo struct {
	Duration int
	Interval int
}

// ClientInfo provides the host and port of another service in the eco-system.
type ClientInfo struct {
	// Host is the hostname or IP address of a service.
	Host string
	// Port defines the port on which to access a given service
	Port int
	// Protocol indicates the protocol to use when accessing a given service
	Protocol string
}

func (c ClientInfo) Url() string {
	url := fmt.Sprintf("%s://%s:%v", c.Protocol, c.Host, c.Port)
	return url
}

// SecretStoreInfo encapsulates configuration properties used to create a SecretClient.
type SecretStoreInfo struct {
	Host                    string
	Port                    int
	Path                    string
	Protocol                string
	Namespace               string
	RootCaCertPath          string
	ServerName              string
	Authentication          vault.AuthenticationInfo
	AdditionalRetryAttempts int
	RetryWaitPeriod         string
	retryWaitPeriodTime     time.Duration
	// TokenFile provides a location to a token file.
	TokenFile string
}

type Database struct {
	Credentials
	Type    string
	Timeout int
	Host    string
	Port    int
	Name    string
}

// Credentials encapsulates username-password attributes.
type Credentials struct {
	Username string
	Password string
}

//CertKeyPair encapsulates public certificate/private key pair for an SSL certificate
type CertKeyPair struct {
	Cert string
	Key  string
}
