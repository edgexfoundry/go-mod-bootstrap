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

package bootstrap

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/config"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/flags"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/logging"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/registration"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/di"

	"github.com/edgexfoundry/go-mod-configuration/configuration"

	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"

	"github.com/edgexfoundry/go-mod-registry/registry"
)

// fatalError logs an error and exits the application.  It's intended to be used only within the bootstrap prior to
// any go routines being spawned.
func fatalError(err error, lc logger.LoggingClient) {
	lc.Error(err.Error())
	os.Exit(1)
}

// translateInterruptToCancel spawns a go routine to translate the receipt of a SIGTERM signal to a call to cancel
// the context used by the bootstrap implementation.
func translateInterruptToCancel(ctx context.Context, wg *sync.WaitGroup, cancel context.CancelFunc) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		signalStream := make(chan os.Signal)
		defer func() {
			signal.Stop(signalStream)
			close(signalStream)
		}()
		signal.Notify(signalStream, os.Interrupt, syscall.SIGTERM)
		select {
		case <-signalStream:
			cancel()
			return
		case <-ctx.Done():
			return
		}
	}()
}

// RunAndReturnWaitGroup bootstraps an application.  It loads configuration and calls the provided list of handlers.
// Any long-running process should be spawned as a go routine in a handler.  Handlers are expected to return
// immediately.  Once all of the handlers are called this function will return a sync.WaitGroup reference to the caller.
// It is intended that the caller take whatever additional action makes sense before calling Wait() on the returned
// reference to wait for the application to be signaled to stop (and the corresponding goroutines spawned in the
// various handlers to be stopped cleanly).
func RunAndReturnWaitGroup(
	ctx context.Context,
	cancel context.CancelFunc,
	commonFlags flags.Common,
	serviceKey string,
	configStem string,
	serviceConfig interfaces.Configuration,
	startupTimer startup.Timer,
	dic *di.Container,
	handlers []interfaces.BootstrapHandler) (*sync.WaitGroup, bool) {

	lc := logging.FactoryToStdout(serviceKey)
	var err error
	var configClient configuration.Client
	var registryClient registry.Client
	var wg sync.WaitGroup
	translateInterruptToCancel(ctx, &wg, cancel)

	configFileName := commonFlags.ConfigFileName()

	// Create new ProviderInfo and initialize it from command-line flag or Environment variable
	configProviderInfo, err := config.NewProviderInfo(lc, commonFlags.ConfigProviderUrl())
	if err != nil {
		fatalError(err, lc)
	}

	// override file-based configuration with environment variables.
	bootstrapConfig := serviceConfig.GetBootstrap()
	startupInfo := config.OverrideStartupInfoFromEnvironment(lc, bootstrapConfig.Startup)

	//	Update the startup timer to reflect whatever configuration read, if anything available.
	startupTimer.UpdateTimer(startupInfo.Duration, startupInfo.Interval)

	switch configProviderInfo.UseProvider() {
	case true:
		// set up configClient; use it to load configuration from provider.
		configClient, err = config.UpdateFromProvider(
			ctx,
			startupTimer,
			configProviderInfo.ServiceConfig(),
			serviceConfig,
			configStem,
			lc,
			serviceKey,
		)
		if err != nil {
			fatalError(err, lc)
		}
		lc = logging.FactoryFromConfiguration(serviceKey, serviceConfig)
		config.ListenForChanges(ctx, &wg, serviceConfig, lc, configClient)
		lc.Info(fmt.Sprintf("Loaded configuration from %s", configProviderInfo.ServiceConfig().GetUrl()))

	case false:
		// load configuration from file.
		err = config.LoadFromFile(
			lc,
			commonFlags.ConfigDirectory(),
			commonFlags.Profile(),
			configFileName,
			serviceConfig,
		)
		if err != nil {
			fatalError(err, lc)
		}
		lc = logging.FactoryFromConfiguration(serviceKey, serviceConfig)
	}

	// setup registryClient if it is enabled
	//registryInfo := serviceConfig.GetRegistryInfo()
	if commonFlags.UseRegistry() {
		registryClient, err = registration.RegisterWithRegistry(ctx, startupTimer, serviceConfig, lc, serviceKey)
		if err != nil {
			fatalError(err, lc)
		}

		defer func() {
			lc.Info("Un-Registering service from the Registry")
			err := registryClient.Unregister()
			if err != nil {
				lc.Error("Unable to Un-Register service from the Registry", "error", err.Error())
			}
		}()
	}

	dic.Update(di.ServiceConstructorMap{
		container.ConfigurationInterfaceName: func(get di.Get) interface{} {
			return serviceConfig
		},
		container.LoggingClientInterfaceName: func(get di.Get) interface{} {
			return lc
		},
		container.RegistryClientInterfaceName: func(get di.Get) interface{} {
			return registryClient
		},
	})

	// call individual bootstrap handlers.
	startedSuccessfully := true
	for i := range handlers {
		if handlers[i](ctx, &wg, startupTimer, dic) == false {
			cancel()
			startedSuccessfully = false
			break
		}
	}

	return &wg, startedSuccessfully
}

// Run bootstraps an application.  It loads configuration and calls the provided list of handlers.  Any long-running
// process should be spawned as a go routine in a handler.  Handlers are expected to return immediately.  Once all of
// the handlers are called this function will wait for any go routines spawned inside the handlers to exit before
// returning to the caller.  It is intended that the caller stop executing on the return of this function.
func Run(
	ctx context.Context,
	cancel context.CancelFunc,
	commonFlags flags.Common,
	serviceKey string,
	configStem string,
	serviceConfig interfaces.Configuration,
	startupTimer startup.Timer,
	dic *di.Container,
	handlers []interfaces.BootstrapHandler) {

	wg, _ := RunAndReturnWaitGroup(
		ctx,
		cancel,
		commonFlags,
		serviceKey,
		configStem,
		serviceConfig,
		startupTimer,
		dic,
		handlers,
	)

	// wait for go routines to stop executing.
	wg.Wait()
}
