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
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/configuration"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/logging"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/di"

	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"

	"github.com/edgexfoundry/go-mod-registry/registry"
)

const (
	EmptyProfileDir  = ""
	DoNotUseRegistry = false
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

// Run bootstraps an application.  It loads configuration and calls the provided list of handlers.  Any long-running
// process should be spawned as a go routine in a handler.  Handlers are expected to return immediately.  Once all of
// the handlers are called this function will wait for any go routines spawned inside the handlers to exit before
// returning to the caller.  It is intended that the caller stop executing on the return of this function.
func Run(
	configDir, profileDir, configFileName string,
	useRegistry bool,
	serviceKey string,
	config interfaces.Configuration,
	startupTimer startup.Timer,
	dic *di.Container,
	handlers []interfaces.BootstrapHandler) {

	lc := logging.FactoryToStdout(serviceKey)
	var err error
	var registryClient registry.Client
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	translateInterruptToCancel(ctx, &wg, cancel)

	// load configuration from file.
	if err = configuration.LoadFromFile(configDir, profileDir, configFileName, config); err != nil {
		fatalError(err, lc)
	}

	// override file-based configuration with environment variables.
	bootstrapConfig := config.GetBootstrap()
	registryInfo, startupInfo := configuration.OverrideFromEnvironment(bootstrapConfig.Registry, bootstrapConfig.Startup)
	config.SetRegistryInfo(registryInfo)

	//	Update the startup timer to reflect whatever configuration read, if anything available.
	startupTimer.UpdateTimer(startupInfo.Duration, startupInfo.Interval)

	// set up registryClient and loggingClient; update configuration from registry if we're using a registry.
	switch useRegistry {
	case true:
		registryClient, err = configuration.UpdateFromRegistry(ctx, startupTimer, config, lc, serviceKey)
		if err != nil {
			fatalError(err, lc)
		}
		lc = logging.FactoryFromConfiguration(serviceKey, config)
		configuration.ListenForChanges(ctx, &wg, config, lc, registryClient)
	case false:
		lc = logging.FactoryFromConfiguration(serviceKey, config)
	}

	dic.Update(di.ServiceConstructorMap{
		container.ConfigurationInterfaceName: func(get di.Get) interface{} {
			return config
		},
		container.LoggingClientInterfaceName: func(get di.Get) interface{} {
			return lc
		},
		container.RegistryClientInterfaceName: func(get di.Get) interface{} {
			return registryClient
		},
	})

	// call individual bootstrap handlers.
	for i := range handlers {
		if handlers[i](ctx, &wg, startupTimer, dic) == false {
			cancel()
			break
		}
	}

	// wait for go routines to stop executing.
	wg.Wait()
}
