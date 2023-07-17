//
// Copyright (C) 2023 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"net/http"
	"strings"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/handlers"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/di"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/common"
	commonDTO "github.com/edgexfoundry/go-mod-core-contracts/v3/dtos/common"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/errors"
)

// CommonController controller for common REST APIs
type CommonController struct {
	dic         *di.Container
	serviceName string
	router      *mux.Router
	version     version
	config      config
	lc          logger.LoggingClient
}

type version struct {
	serviceVersion string
	sdkVersion     string
}

type config struct {
	configuration interfaces.Configuration
	customConfig  interfaces.UpdatableConfig
}

func NewCommonController(dic *di.Container, r *mux.Router, serviceName string, serviceVersion string) *CommonController {
	lc := container.LoggingClientFrom(dic.Get)
	secretProvider := container.SecretProviderExtFrom(dic.Get)
	authenticationHook := handlers.AutoConfigAuthenticationFunc(secretProvider, lc)
	configuration := container.ConfigurationFrom(dic.Get)
	c := CommonController{
		dic:         dic,
		serviceName: serviceName,
		router:      r,
		lc:          lc,
		version: version{
			serviceVersion: serviceVersion,
		},
		config: config{
			configuration: configuration,
		},
	}
	r.HandleFunc(common.ApiPingRoute, c.Ping).Methods(http.MethodGet) // Health check is always unauthenticated
	r.HandleFunc(common.ApiVersionRoute, authenticationHook(c.Version)).Methods(http.MethodGet)
	r.HandleFunc(common.ApiConfigRoute, authenticationHook(c.Config)).Methods(http.MethodGet)
	r.HandleFunc(common.ApiSecretRoute, authenticationHook(c.AddSecret)).Methods(http.MethodPost)

	return &c
}

// SetSDKVersion sets the service's skd version
func (c *CommonController) SetSDKVersion(sdkVersion string) {
	c.version.sdkVersion = sdkVersion
}

// SetCustomConfigInfo sets the custom configuration, which is used to include the service's custom config in the /config endpoint response.
func (c *CommonController) SetCustomConfigInfo(customConfig interfaces.UpdatableConfig) {
	c.config.customConfig = customConfig
}

// Ping handles the request to /ping endpoint. Is used to test if the service is working
// It returns a response as specified by the API swagger in the openapi directory
func (c *CommonController) Ping(writer http.ResponseWriter, request *http.Request) {
	response := commonDTO.NewPingResponse(c.serviceName)
	c.sendResponse(writer, request, response, http.StatusOK)
}

// Version handles the request to /version endpoint. Is used to request the service's versions
// It returns a response as specified by the API swagger in the openapi directory
func (c *CommonController) Version(writer http.ResponseWriter, request *http.Request) {
	var response interface{}
	if c.version.sdkVersion != "" {
		response = commonDTO.NewVersionSdkResponse(c.version.serviceVersion, c.version.sdkVersion, c.serviceName)
	} else {
		response = commonDTO.NewVersionResponse(c.version.serviceVersion, c.serviceName)
	}
	c.sendResponse(writer, request, response, http.StatusOK)
}

// Config handles the request to /config endpoint. Is used to request the service's configuration
// It returns a response as specified by the swagger in openapi/common
func (c *CommonController) Config(writer http.ResponseWriter, request *http.Request) {
	var fullConfig interface{}

	if c.config.customConfig == nil {
		// case of no custom configs
		fullConfig = c.config.configuration
	} else {
		// create a struct combining the common configuration and custom configuration sections
		fullConfig = struct {
			interfaces.Configuration
			CustomConfiguration interfaces.UpdatableConfig
		}{
			c.config.configuration,
			c.config.customConfig,
		}
	}

	response := commonDTO.NewConfigResponse(fullConfig, c.serviceName)
	c.sendResponse(writer, request, response, http.StatusOK)
}

// AddSecret handles the request to the /secret endpoint. Is used to add EdgeX Service exclusive secret to the Secret Store
// It returns a response as specified by the API swagger in the openapi directory
func (c *CommonController) AddSecret(writer http.ResponseWriter, request *http.Request) {
	defer func() {
		_ = request.Body.Close()
	}()

	secretRequest := commonDTO.SecretRequest{}
	err := json.NewDecoder(request.Body).Decode(&secretRequest)
	if err != nil {
		c.lc.Infof("%v", err.Error())
		c.sendError(writer, request, errors.KindContractInvalid, "JSON decode failed", err, common.ApiSecretRoute, "")
		return
	}

	err = addSecret(c.dic, secretRequest)
	if err != nil {
		c.sendError(writer, request, errors.Kind(err), err.Error(), err, common.ApiSecretRoute, secretRequest.RequestId)
		return
	}

	response := commonDTO.NewBaseResponse(secretRequest.RequestId, "", http.StatusCreated)
	c.sendResponse(writer, request, response, http.StatusCreated)

}

// sendResponse puts together the response packet for the APIs
func (c *CommonController) sendResponse(
	writer http.ResponseWriter,
	request *http.Request,
	response interface{},
	statusCode int) {

	correlationID := request.Header.Get(common.CorrelationHeader)

	writer.Header().Set(common.CorrelationHeader, correlationID)
	writer.Header().Set(common.ContentType, common.ContentTypeJSON)
	writer.WriteHeader(statusCode)

	if response != nil {
		data, err := json.Marshal(response)
		if err != nil {
			c.lc.Error("Unable to marshal response", "error", err.Error(), common.CorrelationHeader, correlationID)
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = writer.Write(data)
		if err != nil {
			c.lc.Error("Unable to marshal response", "error", err.Error(), common.CorrelationHeader, correlationID)
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func (c *CommonController) sendError(
	writer http.ResponseWriter,
	request *http.Request,
	errKind errors.ErrKind,
	message string,
	err error,
	api string,
	requestID string) {

	edgeXerr := errors.NewCommonEdgeX(errKind, message, err)
	c.lc.Error(edgeXerr.Error())
	c.lc.Debug(edgeXerr.DebugMessages())
	response := commonDTO.NewBaseResponse(requestID, edgeXerr.Message(), edgeXerr.Code())
	c.sendResponse(writer, request, response, edgeXerr.Code())
}

// addSecret adds EdgeX Service exclusive secret to the Secret Store
func addSecret(dic *di.Container, request commonDTO.SecretRequest) errors.EdgeX {
	secretName, secret := prepareSecret(request)

	secretProvider := container.SecretProviderFrom(dic.Get)
	if secretProvider == nil {
		return errors.NewCommonEdgeX(errors.KindServerError, "secret provider is missing. Make sure it is specified to be used in bootstrap.Run()", nil)
	}

	if err := secretProvider.StoreSecret(secretName, secret); err != nil {
		return errors.NewCommonEdgeX(errors.Kind(err), "adding secret failed", err)
	}
	return nil
}

func prepareSecret(request commonDTO.SecretRequest) (string, map[string]string) {
	var secretsKV = make(map[string]string)
	for _, secret := range request.SecretData {
		secretsKV[secret.Key] = secret.Value
	}

	secretName := strings.TrimSpace(request.SecretName)

	return secretName, secretsKV
}
