package zerotrust

import (
	"context"
	"fmt"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/config"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
	edgeapis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/openziti/sdk-golang/ziti"
	"net"
	"net/http"
	"strings"
)

const (
	OpenZitiControllerKey = "OpenZitiController"
	ConfigKey             = "zerotrust"
)

func AuthToOpenZiti(ozController, jwt string) (ziti.Context, error) {
	if !strings.Contains(ozController, "://") {
		ozController = "https://" + ozController
	}
	caPool, caErr := ziti.GetControllerWellKnownCaPool(ozController)
	if caErr != nil {
		return nil, caErr
	}

	credentials := edgeapis.NewJwtCredentials(jwt)
	credentials.CaPool = caPool

	cfg := &ziti.Config{
		ZtAPI:       ozController + "/edge/client/v1",
		Credentials: credentials,
	}
	cfg.ConfigTypes = append(cfg.ConfigTypes, "all")

	ctx, ctxErr := ziti.NewContext(cfg)
	if ctxErr != nil {
		return nil, ctxErr
	}
	if authErr := ctx.Authenticate(); authErr != nil {
		return nil, authErr
	}

	return ctx, nil
}

func isZeroTrust(secOpts map[string]string) bool {
	return secOpts != nil && secOpts["Mode"] == ConfigKey
}

func HttpTransportFromService(secretProvider interfaces.SecretProviderExt, serviceInfo config.ServiceInfo, lc logger.LoggingClient) (http.RoundTripper, error) {
	roundTripper := http.DefaultTransport
	if isZeroTrust(serviceInfo.SecurityOptions) {
		lc.Debugf("zero trust client detected for service: %s", serviceInfo.Host)
		if rt, err := createZitifiedTransport(secretProvider, serviceInfo.SecurityOptions[OpenZitiControllerKey]); err != nil {
			return nil, err
		} else {
			roundTripper = rt
		}
	}
	return roundTripper, nil
}

func HttpTransportFromClient(secretProvider interfaces.SecretProviderExt, clientInfo *config.ClientInfo, lc logger.LoggingClient) (http.RoundTripper, error) {
	roundTripper := http.DefaultTransport
	if isZeroTrust(clientInfo.SecurityOptions) {
		lc.Debugf("zero trust client detected for client: %s", clientInfo.Host)
		if rt, err := createZitifiedTransport(secretProvider, clientInfo.SecurityOptions[OpenZitiControllerKey]); err != nil {
			return nil, err
		} else {
			roundTripper = rt
		}
	}
	return roundTripper, nil
}

func createZitifiedTransport(secretProvider interfaces.SecretProviderExt, ozController string) (http.RoundTripper, error) {
	jwt, errJwt := secretProvider.GetSelfJWT()
	if errJwt != nil {
		return nil, fmt.Errorf("could not load jwt: %v", errJwt)
	}
	ctx, authErr := AuthToOpenZiti(ozController, jwt)
	if authErr != nil {
		return nil, fmt.Errorf("could not authenticate to OpenZiti: %v", authErr)
	}

	zitiContexts := ziti.NewSdkCollection()
	zitiContexts.Add(ctx)

	zitiTransport := http.DefaultTransport.(*http.Transport).Clone() // copy default transport
	zitiTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := zitiContexts.NewDialerWithFallback(ctx /*&net.Dialer{}*/, nil)
		return dialer.Dial(network, addr)
	}
	return zitiTransport, nil
}
