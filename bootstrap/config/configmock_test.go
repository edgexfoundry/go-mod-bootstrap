//
// Copyright (c) 2023 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package config

import (
	"github.com/edgexfoundry/go-mod-bootstrap/v3/config"
)

type WritableInfo struct {
	LogLevel        string
	StoreAndForward StoreAndForwardInfo
	Telemetry       config.TelemetryInfo
}

type ConfigurationMockStruct struct {
	Writable WritableInfo
	Registry config.RegistryInfo
	Trigger  TriggerInfo
}

type TriggerInfo struct {
	Type string
}

type StoreAndForwardInfo struct {
	Enabled       bool
	RetryInterval string
	MaxRetryCount int
}

func (c *ConfigurationMockStruct) UpdateFromRaw(rawConfig interface{}) bool {
	configuration, ok := rawConfig.(*ConfigurationMockStruct)
	if ok {
		*c = *configuration
	}
	return ok
}

func (c *ConfigurationMockStruct) EmptyWritablePtr() interface{} {
	return &WritableInfo{}
}

func (c *ConfigurationMockStruct) UpdateWritableFromRaw(rawWritable interface{}) bool {
	writable, ok := rawWritable.(*WritableInfo)
	if ok {
		c.Writable = *writable
	}
	return ok
}

func (c *ConfigurationMockStruct) GetBootstrap() config.BootstrapConfiguration {
	return config.BootstrapConfiguration{
		Service:  c.transformToBootstrapServiceInfo(),
		Registry: c.Registry,
	}
}

func (c *ConfigurationMockStruct) GetLogLevel() string {
	return c.Writable.LogLevel
}

func (c *ConfigurationMockStruct) GetRegistryInfo() config.RegistryInfo {
	return c.Registry
}

func (c *ConfigurationMockStruct) GetInsecureSecrets() config.InsecureSecrets {
	return config.InsecureSecrets{}
}

func (c *ConfigurationMockStruct) GetTelemetryInfo() *config.TelemetryInfo {
	return &c.Writable.Telemetry
}

func (c *ConfigurationMockStruct) transformToBootstrapServiceInfo() config.ServiceInfo {
	return config.ServiceInfo{}
}

func (c *ConfigurationMockStruct) GetWritablePtr() any {
	return &c.Writable
}
