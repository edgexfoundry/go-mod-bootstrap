/*******************************************************************************
 * Copyright 2019 Dell Inc.
 * Copyright 2023 Intel Corporation
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
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/utils"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/common"
	"github.com/mitchellh/copystructure"
	"gopkg.in/yaml.v3"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/config"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/environment"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/flags"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/di"

	"github.com/edgexfoundry/go-mod-configuration/v3/configuration"
	"github.com/edgexfoundry/go-mod-configuration/v3/pkg/types"

	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
)

const (
	writableKey       = "/Writable"
	allServicesKey    = "all-services"
	appServicesKey    = "app-services"
	deviceServicesKey = "device-services"
	pathSep           = "/"
)

// UpdatedStream defines the stream type that is notified by ListenForChanges when a configuration update is received.
type UpdatedStream chan struct{}

type Processor struct {
	lc                 logger.LoggingClient
	flags              flags.Common
	envVars            *environment.Variables
	startupTimer       startup.Timer
	ctx                context.Context
	wg                 *sync.WaitGroup
	configUpdated      UpdatedStream
	dic                *di.Container
	overwriteConfig    bool
	providerHasConfig  bool
	commonConfigClient configuration.Client
	appConfigClient    configuration.Client
	deviceConfigClient configuration.Client
}

// NewProcessor creates a new configuration Processor
func NewProcessor(
	flags flags.Common,
	envVars *environment.Variables,
	startupTimer startup.Timer,
	ctx context.Context,
	wg *sync.WaitGroup,
	configUpdated UpdatedStream,
	dic *di.Container,
) *Processor {
	return &Processor{
		lc:            container.LoggingClientFrom(dic.Get),
		flags:         flags,
		envVars:       envVars,
		startupTimer:  startupTimer,
		ctx:           ctx,
		wg:            wg,
		configUpdated: configUpdated,
		dic:           dic,
	}
}

func NewProcessorForCustomConfig(
	flags flags.Common,
	ctx context.Context,
	wg *sync.WaitGroup,
	dic *di.Container) *Processor {
	return &Processor{
		lc:    container.LoggingClientFrom(dic.Get),
		flags: flags,
		ctx:   ctx,
		wg:    wg,
		dic:   dic,
	}
}

func (cp *Processor) Process(
	serviceKey string,
	serviceType string,
	configStem string,
	serviceConfig interfaces.Configuration,
	secretProvider interfaces.SecretProvider) error {

	cp.overwriteConfig = cp.flags.OverwriteConfig()
	configProviderUrl := cp.flags.ConfigProviderUrl()

	// Create new ProviderInfo and initialize it from command-line flag or Variables
	configProviderInfo, err := NewProviderInfo(cp.envVars, configProviderUrl)
	if err != nil {
		return err
	}

	useProvider := configProviderInfo.UseProvider()

	var privateConfigClient configuration.Client
	var privateServiceConfig interfaces.Configuration

	if useProvider {
		getAccessToken, err := cp.getAccessTokenCallback(serviceKey, secretProvider, err, configProviderInfo)
		if err != nil {
			return err
		}

		if err := cp.loadCommonConfig(configStem, getAccessToken, configProviderInfo, serviceConfig, serviceType, CreateProviderClient); err != nil {
			return err
		}

		cp.lc.Info("Common configuration loaded from the Configuration Provider. No overrides applied")

		privateConfigClient, err = CreateProviderClient(cp.lc, serviceKey, configStem, getAccessToken, configProviderInfo.ServiceConfig())
		if err != nil {
			return fmt.Errorf("failed to create Configuration Provider client: %s", err.Error())
		}

		// TODO: figure out what uses the dic - this will not have the common config info!!
		// is this potentially custom config for app/device services?
		cp.dic.Update(di.ServiceConstructorMap{
			container.ConfigClientInterfaceName: func(get di.Get) any {
				return privateConfigClient
			},
		})

		cp.providerHasConfig, err = privateConfigClient.HasConfiguration()
		if err != nil {
			return fmt.Errorf("failed check for Configuration Provider has private configiuration: %s", err.Error())
		}

		if cp.providerHasConfig && !cp.overwriteConfig {
			privateServiceConfig, err = copyConfigurationStruct(serviceConfig)
			if err != nil {
				return err
			}
			if err := cp.loadConfigFromProvider(privateServiceConfig, privateConfigClient); err != nil {
				return err
			}
			if err := utils.MergeValues(serviceConfig, privateServiceConfig); err != nil {
				return fmt.Errorf("could not merge common and private configurations: %s", err.Error())
			}

			cp.lc.Info("Private configuration loaded from the Configuration Provider. No overrides applied")
		}
	} else {
		// Now load common configuration from local file if not using config provider and -cc/--commonConfig flag is used.
		// NOTE: Some security services don't use any common configuration and don't use the configuration provider.
		commonConfigLocation := environment.GetCommonConfigFileName(cp.lc, cp.flags.CommonConfig())
		if commonConfigLocation != "" {
			err := cp.loadCommonConfigFromFile(commonConfigLocation, serviceConfig, serviceType)
			if err != nil {
				return err
			}

			overrideCount, err := cp.envVars.OverrideConfiguration(serviceConfig)
			if err != nil {
				return err
			}
			cp.lc.Infof("Common configuration loaded from file with %d overrides applied", overrideCount)
		}
	}

	// Now load the private config from a local file if any of these conditions are true
	if !useProvider || !cp.providerHasConfig || cp.overwriteConfig {
		filePath := GetConfigFileLocation(cp.lc, cp.flags)
		configMap, err := cp.loadConfigYamlFromFile(filePath)
		if err != nil {
			return err
		}

		// apply overrides - Now only done when loaded from file and values will get pushed into Configuration Provider (if used)
		overrideCount, err := cp.envVars.OverrideConfigMapValues(configMap)
		if err != nil {
			return err
		}
		cp.lc.Infof("Private configuration loaded from file with %d overrides applied", overrideCount)

		if err := cp.mergeMapWithConfig(serviceConfig, configMap); err != nil {
			return err
		}

		if useProvider {
			if err := privateConfigClient.PutConfigurationMap(configMap, cp.overwriteConfig); err != nil {
				return fmt.Errorf("could not push private configuration into Configuration Provider: %s", err.Error())
			}

			cp.lc.Info("Private configuration has been pushed to into Configuration Provider with overrides applied")
		}
	}

	// listen for changes on Writable
	if useProvider {
		cp.listenForChanges(serviceConfig, privateConfigClient)
		cp.lc.Infof("listening for private config changes")
		cp.listenForCommonChanges(serviceConfig, cp.commonConfigClient, privateConfigClient)
		cp.lc.Infof("listening for all services common config changes")
		if cp.appConfigClient != nil {
			cp.listenForCommonChanges(serviceConfig, cp.appConfigClient, privateConfigClient)
			cp.lc.Infof("listening for application service common config changes")
		}
		if cp.deviceConfigClient != nil {
			cp.listenForCommonChanges(serviceConfig, cp.deviceConfigClient, privateConfigClient)
			cp.lc.Infof("listening for device service common config changes")
		}
	}

	// Now that configuration has been loaded and overrides applied the log level can be set as configured.
	err = cp.lc.SetLogLevel(serviceConfig.GetLogLevel())

	return err
}

type createProviderCallback func(
	logger.LoggingClient,
	string,
	string,
	types.GetAccessTokenCallback,
	types.ServiceConfig) (configuration.Client, error)

// loadCommonConfig will pull up to two separate common configs from the config provider
// - serviceConfig: all services section of the common config
// - serviceTypeConfig: if the service is an app or device service, this will have the type specific common config
// if there are separate configs, these will get merged into the serviceConfig
func (cp *Processor) loadCommonConfig(
	configStem string,
	getAccessToken types.GetAccessTokenCallback,
	configProviderInfo *ProviderInfo,
	serviceConfig interfaces.Configuration,
	serviceType string,
	createProvider createProviderCallback) error {

	var err error
	// check that common config is loaded into the provider
	// this need a separate config provider client here because the config ready variable is stored at the common config level
	// load the all services section of the common config
	cp.commonConfigClient, err = createProvider(cp.lc, common.CoreCommonConfigServiceKey+pathSep+allServicesKey, configStem, getAccessToken, configProviderInfo.ServiceConfig())
	if err != nil {
		return fmt.Errorf("failed to create provider for %s: %s", allServicesKey, err.Error())
	}
	// build the path for the common configuration ready value
	commonConfigReadyPath := fmt.Sprintf("%s/%s/%s", configStem, common.CoreCommonConfigServiceKey, config.CommonConfigDone)
	if err := cp.waitForCommonConfig(cp.commonConfigClient, commonConfigReadyPath); err != nil {
		return err
	}
	err = cp.loadConfigFromProvider(serviceConfig, cp.commonConfigClient)
	if err != nil {
		return fmt.Errorf("failed to load the common configuration for %s: %s", allServicesKey, err.Error())
	}

	// use the service type to determine which additional sections to load into the common configuration
	var serviceTypeConfig interfaces.Configuration
	switch serviceType {
	case config.ServiceTypeApp:
		cp.lc.Infof("loading the common configuration for service type %s", serviceType)
		serviceTypeConfig, err = copyConfigurationStruct(serviceConfig)
		if err != nil {
			return fmt.Errorf("failed to copy the configuration structure for %s: %s", appServicesKey, err.Error())
		}
		cp.appConfigClient, err = createProvider(cp.lc, common.CoreCommonConfigServiceKey+pathSep+appServicesKey, configStem, getAccessToken, configProviderInfo.ServiceConfig())
		if err != nil {
			return fmt.Errorf("failed to create provider for %s: %s", appServicesKey, err.Error())
		}
		err = cp.loadConfigFromProvider(serviceTypeConfig, cp.appConfigClient)
		if err != nil {
			return fmt.Errorf("failed to load the common configuration for %s: %s", appServicesKey, err.Error())
		}
	case config.ServiceTypeDevice:
		cp.lc.Infof("loading the common configuration for service type %s", serviceType)
		serviceTypeConfig, err = copyConfigurationStruct(serviceConfig)
		if err != nil {
			return fmt.Errorf("failed to copy the configuration structure for %s: %s", deviceServicesKey, err.Error())
		}
		cp.deviceConfigClient, err = createProvider(cp.lc, common.CoreCommonConfigServiceKey+pathSep+deviceServicesKey, configStem, getAccessToken, configProviderInfo.ServiceConfig())
		if err != nil {
			return fmt.Errorf("failed to create provider for %s: %s", deviceServicesKey, err.Error())
		}
		err = cp.loadConfigFromProvider(serviceTypeConfig, cp.deviceConfigClient)
		if err != nil {
			return fmt.Errorf("failed to load the common configuration for %s: %s", deviceServicesKey, err.Error())
		}
	default:
		// this case is covered by the initial call to get the common config for all-services
	}

	// merge together the common config and the service type config
	if serviceTypeConfig != nil {
		if err := utils.MergeValues(serviceConfig, serviceTypeConfig); err != nil {
			return fmt.Errorf("failed to merge %s config with common config: %s", serviceType, err.Error())
		}
	}

	return nil
}

// loadCommonConfigFromFile will pull up the common config from the provided file and load it into the passed in interface
func (cp *Processor) loadCommonConfigFromFile(
	configFile string,
	serviceConfig interfaces.Configuration,
	serviceType string) error {

	var err error

	commonConfig, err := cp.loadConfigYamlFromFile(configFile)
	if err != nil {
		return err
	}
	// separate out the necessary sections
	allServicesConfig, ok := commonConfig[allServicesKey].(map[string]any)
	if !ok {
		return fmt.Errorf("could not find %s section in common config %s", allServicesKey, configFile)
	}
	// use the service type to separate out the necessary sections
	var serviceTypeConfig map[string]any
	switch serviceType {
	case config.ServiceTypeApp:
		cp.lc.Infof("loading the common configuration for service type %s", serviceType)
		serviceTypeConfig, ok = commonConfig[appServicesKey].(map[string]any)
		if !ok {
			return fmt.Errorf("could not find %s section in common config %s", appServicesKey, configFile)
		}
	case config.ServiceTypeDevice:
		cp.lc.Infof("loading the common configuration for service type %s", serviceType)
		serviceTypeConfig, ok = commonConfig[deviceServicesKey].(map[string]any)
		if !ok {
			return fmt.Errorf("could not find %s section in common config %s", deviceServicesKey, configFile)
		}
	default:
		// this case is covered by the initial call to get the common config for all-services
	}

	if serviceType == config.ServiceTypeApp || serviceType == config.ServiceTypeDevice {
		utils.MergeMaps(allServicesConfig, serviceTypeConfig)
	}

	if err := utils.ConvertFromMap(allServicesConfig, serviceConfig); err != nil {
		return fmt.Errorf("failed to convert common configuration into service's configuration: %v", err)
	}

	return err
}

func (cp *Processor) getAccessTokenCallback(serviceKey string, secretProvider interfaces.SecretProvider, err error, configProviderInfo *ProviderInfo) (types.GetAccessTokenCallback, error) {
	var accessToken string
	var getAccessToken types.GetAccessTokenCallback

	// secretProvider will be nil if not configured to be used. In that case, no access token required.
	if secretProvider != nil {
		// Define the callback function to retrieve the Access Token
		getAccessToken = func() (string, error) {
			accessToken, err = secretProvider.GetAccessToken(configProviderInfo.serviceConfig.Type, serviceKey)
			if err != nil {
				return "", fmt.Errorf(
					"failed to get Configuration Provider (%s) access token: %s",
					configProviderInfo.serviceConfig.Type,
					err.Error())
			}

			cp.lc.Debugf("Using Configuration Provider access token of length %d", len(accessToken))
			return accessToken, nil
		}

	} else {
		cp.lc.Debug("Not configured to use Config Provider access token")
	}
	return getAccessToken, err
}

// LoadCustomConfigSection loads the specified custom configuration section from file or Configuration provider.
// Section will be seed if Configuration provider does yet have it. This is used for structures custom configuration
// in App and Device services
func (cp *Processor) LoadCustomConfigSection(updatableConfig interfaces.UpdatableConfig, sectionName string) error {
	if cp.envVars == nil {
		cp.envVars = environment.NewVariables(cp.lc)
	}

	configClient := container.ConfigClientFrom(cp.dic.Get)
	if configClient == nil {
		cp.lc.Info("Skipping use of Configuration Provider for custom configuration: Provider not available")
		filePath := GetConfigFileLocation(cp.lc, cp.flags)
		configMap, err := cp.loadConfigYamlFromFile(filePath)
		if err != nil {
			return err
		}

		err = utils.ConvertFromMap(configMap, updatableConfig)
		if err != nil {
			return fmt.Errorf("failed to convert custom configuration into service's configuration: %v", err)
		}
	} else {
		cp.lc.Infof("Checking if custom configuration ('%s') exists in Configuration Provider", sectionName)

		exists, err := configClient.HasSubConfiguration(sectionName)
		if err != nil {
			return fmt.Errorf(
				"unable to determine if custom configuration exists in Configuration Provider: %s",
				err.Error())
		}

		if exists && !cp.flags.OverwriteConfig() {
			rawConfig, err := configClient.GetConfiguration(updatableConfig)
			if err != nil {
				return fmt.Errorf(
					"unable to get custom configuration from Configuration Provider: %s", err.Error())
			}

			if ok := updatableConfig.UpdateFromRaw(rawConfig); !ok {
				return fmt.Errorf("unable to update custom configuration from Configuration Provider")
			}

			cp.lc.Info("Loaded custom configuration from Configuration Provider, no overrides applied")
		} else {
			filePath := GetConfigFileLocation(cp.lc, cp.flags)
			configMap, err := cp.loadConfigYamlFromFile(filePath)
			if err != nil {
				return err
			}

			// Must apply override before pushing into Configuration Provider
			overrideCount, err := cp.envVars.OverrideConfigMapValues(configMap)
			if err != nil {
				return fmt.Errorf("unable to apply environment overrides: %s", err.Error())
			}

			cp.lc.Info("Loaded custom configuration from File (%d envVars overrides applied)", overrideCount)

			err = configClient.PutConfigurationMap(configMap, true)
			if err != nil {
				return fmt.Errorf("error pushing custom config to Configuration Provider: %s", err.Error())
			}

			var overwriteMessage = ""
			if exists && cp.flags.OverwriteConfig() {
				overwriteMessage = "(overwritten)"
			}
			cp.lc.Infof("Custom Config loaded from file and pushed to Configuration Provider %s", overwriteMessage)
		}
	}

	return nil
}

// ListenForCustomConfigChanges listens for changes to the specified custom configuration section. When changes occur it
// applies the changes to the custom configuration section and signals the changes have occurred.
func (cp *Processor) ListenForCustomConfigChanges(
	configToWatch any,
	sectionName string,
	changedCallback func(any)) {
	configClient := container.ConfigClientFrom(cp.dic.Get)
	if configClient == nil {
		cp.lc.Warnf("unable to watch custom configuration for changes: Configuration Provider not enabled")
		return
	}

	cp.wg.Add(1)
	go func() {
		defer cp.wg.Done()

		errorStream := make(chan error)
		defer close(errorStream)

		updateStream := make(chan any)
		defer close(updateStream)

		configClient.WatchForChanges(updateStream, errorStream, configToWatch, sectionName)

		isFirstUpdate := true

		for {
			select {
			case <-cp.ctx.Done():
				configClient.StopWatching()
				cp.lc.Infof("Watching for '%s' configuration changes has stopped", sectionName)
				return

			case ex := <-errorStream:
				cp.lc.Error(ex.Error())

			case raw := <-updateStream:
				// Config Provider sends an update as soon as the watcher is connected even though there are not
				// any changes to the configuration. This causes an issue during start-up if there is an
				// envVars override of one of the Writable fields, so we must ignore the first update.
				if isFirstUpdate {
					isFirstUpdate = false
					continue
				}

				cp.lc.Infof("Updated custom configuration '%s' has been received from the Configuration Provider", sectionName)
				changedCallback(raw)
			}
		}
	}()

	cp.lc.Infof("Watching for custom configuration changes has started for `%s`", sectionName)
}

// CreateProviderClient creates and returns a configuration.Client instance and logs Client connection information
func CreateProviderClient(
	lc logger.LoggingClient,
	serviceKey string,
	configStem string,
	getAccessToken types.GetAccessTokenCallback,
	providerConfig types.ServiceConfig) (configuration.Client, error) {

	var err error

	// The passed in configStem already contains the trailing '/' in most cases so must verify and add if missing.
	if configStem[len(configStem)-1] != '/' {
		configStem = configStem + "/"
	}

	// Note: Can't use filepath.Join as it uses `\` on Windows which Consul doesn't recognize as a path separator.
	providerConfig.BasePath = fmt.Sprintf("%s%s", configStem, serviceKey)
	if getAccessToken != nil {
		providerConfig.AccessToken, err = getAccessToken()
		if err != nil {
			return nil, err
		}
		providerConfig.GetAccessToken = getAccessToken
	}

	lc.Info(fmt.Sprintf(
		"Using Configuration provider (%s) from: %s with base path of %s",
		providerConfig.Type,
		providerConfig.GetUrl(),
		providerConfig.BasePath))

	return configuration.NewConfigurationClient(providerConfig)
}

// loadConfigYamlFromFile attempts to read the specified configuration yaml file
func (cp *Processor) loadConfigYamlFromFile(yamlFile string) (map[string]any, error) {
	cp.lc.Infof("Loading configuration file from %s", yamlFile)
	contents, err := os.ReadFile(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file %s: %s", yamlFile, err.Error())
	}

	data := make(map[string]any)

	err = yaml.Unmarshal(contents, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshall configuration file %s: %s", yamlFile, err.Error())
	}
	return data, nil
}

func (cp *Processor) mergeMapWithConfig(config any, configMap map[string]any) error {
	// convert the common config passed in to a map[string]any
	var destConfigMap map[string]any
	if err := utils.ConvertToMap(config, &destConfigMap); err != nil {
		return fmt.Errorf("failed to mergre configuration: %v", err)
	}

	utils.MergeMaps(destConfigMap, configMap)

	if err := utils.ConvertFromMap(configMap, config); err != nil {
		return fmt.Errorf("failed to mergre configuration: %v", err)
	}

	return nil
}

// GetConfigFileLocation uses the environment variables and flags to determine the location of the configuration
func GetConfigFileLocation(lc logger.LoggingClient, flags flags.Common) string {
	configDir := environment.GetConfigDir(lc, flags.ConfigDirectory())
	profileDir := environment.GetProfileDir(lc, flags.Profile())
	configFileName := environment.GetConfigFileName(lc, flags.ConfigFileName())

	return configDir + pathSep + profileDir + configFileName
}

// listenForChanges leverages the Configuration Provider client's WatchForChanges() method to receive changes to and update the
// service's configuration writable sub-struct.  It's assumed the log level is universally part of the
// writable struct and this function explicitly updates the loggingClient's log level when new configuration changes
// are received.
func (cp *Processor) listenForChanges(serviceConfig interfaces.Configuration, configClient configuration.Client) {
	lc := cp.lc
	isFirstUpdate := true

	cp.wg.Add(1)
	go func() {
		defer cp.wg.Done()

		errorStream := make(chan error)
		defer close(errorStream)

		updateStream := make(chan any)
		defer close(updateStream)

		go configClient.WatchForChanges(updateStream, errorStream, serviceConfig.EmptyWritablePtr(), writableKey)

		for {
			select {
			case <-cp.ctx.Done():
				configClient.StopWatching()
				lc.Infof("Watching for '%s' configuration changes has stopped", writableKey)
				return

			case ex := <-errorStream:
				lc.Errorf("error occurred during listening to the configuration changes: %s", ex.Error())

			case raw, ok := <-updateStream:
				if !ok {
					return
				}

				// Config Provider sends an update as soon as the watcher is connected even though there are not
				// any changes to the configuration. This causes an issue during start-up if there is an
				// envVars override of one of the Writable fields, so we must ignore the first update.
				if isFirstUpdate {
					isFirstUpdate = false
					continue
				}
				cp.applyWritableUpdates(serviceConfig, raw)
			}
		}
	}()
}

// listenForCommonChanges leverages the Configuration Provider client's WatchForChanges() method to receive changes to and update the
// service's common configuration writable sub-struct.
func (cp *Processor) listenForCommonChanges(fullServiceConfig interfaces.Configuration, commonConfigClient configuration.Client,
	privateConfigClient configuration.Client) {
	lc := cp.lc
	isFirstUpdate := true

	cp.wg.Add(1)
	go func() {
		defer cp.wg.Done()

		var previousCommonWritable any

		errorStream := make(chan error)
		defer close(errorStream)

		updateStream := make(chan any)
		defer close(updateStream)

		go commonConfigClient.WatchForChanges(updateStream, errorStream, fullServiceConfig.EmptyWritablePtr(), writableKey)

		for {
			select {
			case <-cp.ctx.Done():
				commonConfigClient.StopWatching()
				lc.Infof("Watching for '%s' configuration changes has stopped", writableKey)
				return

			case ex := <-errorStream:
				lc.Errorf("error occurred during listening to the configuration changes: %s", ex.Error())

			case raw, ok := <-updateStream:
				if !ok {
					return
				}

				// Config Provider sends an update as soon as the watcher is connected even though there are not
				// any changes to the configuration. This causes an issue during start-up if there is an
				// envVars override of one of the Writable fields, so on the first update we can just save a copy of the
				// common writable for comparison for future writable updates.
				if isFirstUpdate {
					isFirstUpdate = false
					previousCommonWritable = raw
					continue
				}

				if err := cp.processCommonConfigChange(fullServiceConfig, previousCommonWritable, raw, privateConfigClient); err != nil {
					lc.Error(err.Error())
				}
				// ensure that the local copy of the common writable gets updated no matter what
				previousCommonWritable = raw
			}
		}
	}()
}

func (cp *Processor) processCommonConfigChange(fullServiceConfig interfaces.Configuration, previousCommonWritable any, raw any, privateConfigClient configuration.Client) error {
	// check if changed value is a private override
	if cp.isPrivateOverride(previousCommonWritable, raw, privateConfigClient) {
		return nil
	}

	// merge raw with fullServiceConfig and call it changedConfig
	changedConfig, err := copyConfigurationStruct(fullServiceConfig)
	if err != nil {
		return fmt.Errorf("could not copy config while watching for common config writable: %s", err.Error())
	}
	changedWritable := changedConfig.GetWritablePtr()

	if err := utils.MergeValues(changedWritable, raw); err != nil {
		return fmt.Errorf("could not merge configs while watching for common config writable: %s", err.Error())
	}

	cp.applyWritableUpdates(fullServiceConfig, changedWritable)
	return nil
}

func (cp *Processor) isPrivateOverride(previous any, updated any, privateConfigClient configuration.Client) bool {
	var changedKey string
	var previousMap, updatedMap map[string]any
	if err := utils.ConvertToMap(previous, &previousMap); err != nil {
		cp.lc.Errorf("could not convert previous interface to map: %s", err.Error())
		return true
	}
	if err := utils.ConvertToMap(updated, &updatedMap); err != nil {
		cp.lc.Errorf("could not convert updated interface to map: %s", err.Error())
		return true
	}
	changedKey = walkMapForChange(previousMap, updatedMap, "")
	if changedKey == "" {
		// look the other way around to see if an item was removed
		changedKey = walkMapForChange(updatedMap, previousMap, "")
		if changedKey == "" {
			cp.lc.Error("could not find updated writable key or an error occurred")
			return true
		}
	}
	// check to see if that setting is in the private config
	if cp.isKeyInPrivate(privateConfigClient, changedKey) {
		cp.lc.Infof("ignoring changed writable key %s overwritten in private writable", changedKey)
		return true
	}
	return false
}

func (cp *Processor) applyWritableUpdates(serviceConfig interfaces.Configuration, raw any) {

	lc := cp.lc
	previousInsecureSecrets := serviceConfig.GetInsecureSecrets()
	previousLogLevel := serviceConfig.GetLogLevel()
	previousTelemetryInterval := serviceConfig.GetTelemetryInfo().Interval

	if !serviceConfig.UpdateWritableFromRaw(raw) {
		lc.Error("ListenForChanges() type check failed")
		return
	}

	currentInsecureSecrets := serviceConfig.GetInsecureSecrets()
	currentLogLevel := serviceConfig.GetLogLevel()
	currentTelemetryInterval := serviceConfig.GetTelemetryInfo().Interval

	lc.Info("Writeable configuration has been updated from the Configuration Provider")

	// Note: Updates occur one setting at a time so only have to look for single changes
	switch {
	case currentLogLevel != previousLogLevel:
		_ = lc.SetLogLevel(serviceConfig.GetLogLevel())
		lc.Info(fmt.Sprintf("Logging level changed to %s", currentLogLevel))

	// InsecureSecrets (map) will be nil if not in the original TOML used to seed the Config Provider,
	// so ignore it if this is the case.
	case currentInsecureSecrets != nil &&
		!reflect.DeepEqual(currentInsecureSecrets, previousInsecureSecrets):
		lc.Info("Insecure Secrets have been updated")
		secretProvider := container.SecretProviderFrom(cp.dic.Get)
		if secretProvider != nil {
			// Find the updated secret's path and perform call backs.
			updatedSecrets := getSecretNamesChanged(previousInsecureSecrets, currentInsecureSecrets)
			for _, v := range updatedSecrets {
				secretProvider.SecretUpdatedAtSecretName(v)
			}
		}

	case currentTelemetryInterval != previousTelemetryInterval:
		lc.Info("Telemetry interval has been updated. Processing new value...")
		interval, err := time.ParseDuration(currentTelemetryInterval)
		if err != nil {
			lc.Errorf("update telemetry interval value is invalid time duration, using previous value: %s", err.Error())
			break
		}

		if interval == 0 {
			lc.Infof("0 specified for metrics reporting interval. Setting to max duration to effectively disable reporting.")
			interval = math.MaxInt64
		}

		metricsManager := container.MetricsManagerFrom(cp.dic.Get)
		if metricsManager == nil {
			lc.Error("metrics manager not available while updating telemetry interval")
			break
		}

		metricsManager.ResetInterval(interval)

	default:
		// Signal that configuration updates exists that have not already been processed.
		if cp.configUpdated != nil {
			cp.configUpdated <- struct{}{}
		}
	}
}

func (cp *Processor) waitForCommonConfig(configClient configuration.Client, configReadyPath string) error {
	// Wait for configuration provider to be available
	isAlive := false
	for cp.startupTimer.HasNotElapsed() {
		if configClient.IsAlive() {
			isAlive = true
			break
		}

		cp.lc.Warnf("Waiting for configuration provider to be available")

		select {
		case <-cp.ctx.Done():
			return errors.New("aborted waiting Configuration Provider to be available")
		default:
			cp.startupTimer.SleepForInterval()
			continue
		}
	}
	if !isAlive {
		return errors.New("configuration provider is not available")
	}

	// check to see if common config is loaded
	isConfigReady := false
	isCommonConfigReady := false
	for cp.startupTimer.HasNotElapsed() {
		commonConfigReady, err := configClient.GetConfigurationValueByFullPath(configReadyPath)
		if err != nil {
			cp.lc.Warn("waiting for Common Configuration to be available from config provider")
			cp.startupTimer.SleepForInterval()
			continue
		}

		isCommonConfigReady, err = strconv.ParseBool(string(commonConfigReady))
		if err != nil {
			cp.lc.Warnf("did not get boolean from config provider for %s: %s", configReadyPath, err.Error())
			isCommonConfigReady = false
		}
		if isCommonConfigReady {
			isConfigReady = true
			break
		}

		cp.lc.Warn("waiting for Common Configuration to be available from config provider")

		select {
		case <-cp.ctx.Done():
			return errors.New("aborted waiting for Common Configuration to be available")
		default:
			cp.startupTimer.SleepForInterval()
			continue
		}
	}
	if !isConfigReady {
		return errors.New("common config is not loaded - check to make sure core-common-config-bootstrapper ran")
	}
	return nil
}

// loadConfigFromProvider loads the config into the config structure
func (cp *Processor) loadConfigFromProvider(serviceConfig interfaces.Configuration, configClient configuration.Client) error {
	// pull common config and apply config to service config structure
	rawConfig, err := configClient.GetConfiguration(serviceConfig)
	if err != nil {
		return err
	}

	// update from raw
	ok := serviceConfig.UpdateFromRaw(rawConfig)
	if !ok {
		return fmt.Errorf("could not update service's configuration from raw")
	}

	return nil
}

// getSecretNamesChanged returns a slice of secretNames that have changed secrets or are new.
func getSecretNamesChanged(prevVals config.InsecureSecrets, curVals config.InsecureSecrets) []string {
	var updatedNames []string
	for key, prevVal := range prevVals {
		curVal := curVals[key]

		// Catches removed secrets
		if curVal.SecretData == nil {
			updatedNames = append(updatedNames, prevVal.SecretName)
			continue
		}

		// Catches changes to secret data or to the secret name
		if !reflect.DeepEqual(prevVal, curVal) {
			updatedNames = append(updatedNames, curVal.SecretName)

			// Catches secret name changes, so also include the previous secretName
			if prevVal.SecretName != curVal.SecretName {
				updatedNames = append(updatedNames, prevVal.SecretName)
			}
		}
	}

	for key, curVal := range curVals {
		// Catches new secrets added
		if prevVals[key].SecretData == nil {
			updatedNames = append(updatedNames, curVal.SecretName)
		}
	}

	return updatedNames
}

// copyConfigurationStruct returns a copy of the passed in configuration interface
func copyConfigurationStruct(config interfaces.Configuration) (interfaces.Configuration, error) {
	rawCopy, err := copystructure.Copy(config)
	if err != nil {
		return nil, fmt.Errorf("failed to load copy the configuration: %s", err.Error())
	}
	configCopy, ok := rawCopy.(interfaces.Configuration)
	if !ok {
		return nil, errors.New("failed to cast the copy of the configuration")
	}
	return configCopy, nil
}

func walkMapForChange(previousMap map[string]any, updatedMap map[string]any, changedKey string) string {
	for updatedKey, updatedVal := range updatedMap {
		previousVal, ok := previousMap[updatedKey]
		if !ok {
			return buildNewKey(changedKey, updatedKey)
		}
		updatedSubMap, ok := updatedVal.(map[string]any)
		// if the value is not of type map[string]any, it should be a value to compare
		if !ok {
			if updatedVal != previousVal {
				return buildNewKey(changedKey, updatedKey)
			}
			continue
		}
		previousSubMap, ok := previousVal.(map[string]any)
		if !ok {
			// handle the case where a new setting is added
			if previousSubMap == nil && updatedSubMap != nil {
				subKey := buildNewKey(changedKey, updatedKey)
				for k := range updatedSubMap {
					return buildNewKey(subKey, k)
				}
			}
			return ""
		}
		key := buildNewKey(changedKey, updatedKey)
		key = walkMapForChange(previousSubMap, updatedSubMap, key)
		if len(key) > 0 {
			return key
		}
	}
	return ""
}

func (cp *Processor) isKeyInPrivate(privateConfigClient configuration.Client, changedKey string) bool {
	keys, err := privateConfigClient.GetConfigurationKeys(writableKey)
	if err != nil {
		cp.lc.Errorf("could not get writable keys from private configuration: %s", err.Error())
		// return true because shouldn't change an overridden value
		// error means it is undetermined, so don't override to be safe
		return true
	}
	changedKey = fmt.Sprintf("%s/%s", writableKey, changedKey)

	for _, key := range keys {
		if strings.Contains(key, changedKey) {
			return true
		}
	}
	return false
}

func buildNewKey(previousKey, currentKey string) string {
	if previousKey != "" {
		return fmt.Sprintf("%s%s%s", previousKey, pathSep, currentKey)
	} else {
		return currentKey
	}
}
