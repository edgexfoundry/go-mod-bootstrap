/*******************************************************************************
 * Copyright 2019 Dell Inc.
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
	"io/ioutil"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/interfaces"
)

const (
	envConfDir = "EDGEX_CONF_DIR"
	envProfile = "edgex_profile" // TODO: change to EDGEX_PROFILE for release v2.0.0
	envFile    = "EDGEX_CONFIG_FILE"
)

// LoadFromFile attempts to read and unmarshal toml-based configuration into a configuration struct.
func LoadFromFile(
	lc logger.LoggingClient,
	configDir,
	profileDir,
	configFileName string,
	config interfaces.Configuration) error {

	// ported from determinePath() in internal/pkg/config/loader.go
	envValue := os.Getenv(envConfDir)
	if len(envValue) > 0 {
		configDir = envValue
		lc.Info(fmt.Sprintf("Environment varable override of -confdir value by Environment varable: %s=%s", envConfDir, envValue))
	}

	if len(configDir) == 0 {
		configDir = "./res"
	}

	envValue = os.Getenv(envProfile)
	if len(envValue) > 0 {
		profileDir = envValue
		lc.Info(fmt.Sprintf("Environment varable override of -profile value by Environment varable: %s=%s", envProfile, envValue))
	}

	// remainder is simplification of LoadFromFile() in internal/pkg/config/loader.go
	if len(profileDir) > 0 {
		profileDir += "/"
	}

	envValue = os.Getenv(envFile)
	if len(envValue) > 0 {
		configFileName = envValue
		lc.Info(fmt.Sprintf("Environment varable override of -file value overridden by Environment varable: %s=%s", envFile, envValue))
	}

	fileName := configDir + "/" + profileDir + configFileName

	contents, err := ioutil.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("could not load configuration file (%s): %s", fileName, err.Error())
	}
	if err = toml.Unmarshal(contents, config); err != nil {
		return fmt.Errorf("could not load configuration file (%s): %s", fileName, err.Error())
	}

	lc.Info(fmt.Sprintf("Loaded configuration from %s", fileName))

	return nil
}
