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

	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"github.com/edgexfoundry/go-mod-registry/registry"

	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/config"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/flags"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/logging"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/registration"
	"github.com/edgexfoundry/go-mod-bootstrap/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/di"
)

// Deferred defines the signature of a function returned by RunAndReturnWaitGroup that should be executed via defer.
type Deferred func()

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
	configUpdated config.UpdatedStream,
	startupTimer startup.Timer,
	dic *di.Container,
	handlers []interfaces.BootstrapHandler) (*sync.WaitGroup, Deferred, bool) {

	var err error
	var wg sync.WaitGroup
	deferred := func() {}

	lc := logging.FactoryToStdout(serviceKey)

	translateInterruptToCancel(ctx, &wg, cancel)

	bootstrapConfig := serviceConfig.GetBootstrap()
	environment := config.NewEnvironment()
	startupInfo := environment.OverrideStartupInfo(lc, bootstrapConfig.Startup)

	//	Update the startup timer to reflect whatever configuration read, if anything available.
	startupTimer.UpdateTimer(startupInfo.Duration, startupInfo.Interval)

	configProcessor := config.NewProcessor(lc, commonFlags, environment, startupTimer, ctx, &wg, configUpdated)
	if err := configProcessor.Process(serviceKey, configStem, serviceConfig); err != nil {
		fatalError(err, lc)
	}

	// Now the the configuration has been processed the logger has been created based on configuration.
	lc = configProcessor.Logger

	var registryClient registry.Client

	// TODO: Remove `|| config.UseRegistry()` for release V2.0.0
	if commonFlags.UseRegistry() || environment.UseRegistry() {
		// For backwards compatibility with Fuji Device Service, registry is a string that can contain a provider URL.
		// TODO: Remove registryUrl in call below for release V2.0.0
		registryClient, err = registration.RegisterWithRegistry(
			ctx,
			startupTimer,
			serviceConfig,
			commonFlags.RegistryUrl(),
			environment,
			lc,
			serviceKey)
		if err != nil {
			fatalError(err, lc)
		}

		deferred = func() {
			lc.Info("Un-Registering service from the Registry")
			err := registryClient.Unregister()
			if err != nil {
				lc.Error("Unable to Un-Register service from the Registry", "error", err.Error())
			}
		}
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

	return &wg, deferred, startedSuccessfully
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

	wg, deferred, _ := RunAndReturnWaitGroup(
		ctx,
		cancel,
		commonFlags,
		serviceKey,
		configStem,
		serviceConfig,
		nil,
		startupTimer,
		dic,
		handlers,
	)

	defer deferred()

	// wait for go routines to stop executing.
	wg.Wait()
}
