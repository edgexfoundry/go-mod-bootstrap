//
// Copyright (C) 2023 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/interfaces/mocks"
	bootstrapConfig "github.com/edgexfoundry/go-mod-bootstrap/v4/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/di"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/common"
	commonDTO "github.com/edgexfoundry/go-mod-core-contracts/v4/dtos/common"
)

var validAddSecretRequest = commonDTO.NewSecretRequest(
	"mqtt",
	[]commonDTO.SecretDataKeyValue{
		{Key: "username", Value: "username"},
		{Key: "password", Value: "password"},
	},
)

var serviceVersion = "0.0.0"

func mockDic() *di.Container {
	mockConfig := &mocks.Configuration{}
	mockProvider := &mocks.SecretProvider{}
	mockProvider.On("StoreSecret", validAddSecretRequest.SecretName, map[string]string{"password": "password", "username": "username"}).Return(nil)
	mockProvider.On("StoreSecret", "fail", map[string]string{"password": "password", "username": "username"}).Return(errors.New("add failed"))

	return di.NewContainer(di.ServiceConstructorMap{
		container.ConfigurationInterfaceName: func(get di.Get) interface{} {
			return mockConfig
		},
		container.LoggingClientInterfaceName: func(get di.Get) interface{} {
			return logger.NewMockClient()
		},
		container.SecretProviderName: func(get di.Get) interface{} {
			return mockProvider
		},
	})
}

func TestAddSecret(t *testing.T) {
	e := echo.New()
	dic := mockDic()

	target := NewCommonController(dic, e, uuid.NewString(), serviceVersion)
	assert.NotNil(t, target)

	NoPath := validAddSecretRequest
	NoPath.SecretName = ""
	validNoRequestId := validAddSecretRequest
	validNoRequestId.RequestId = ""
	badRequestId := validAddSecretRequest
	badRequestId.RequestId = "bad requestId"
	noSecrets := validAddSecretRequest
	noSecrets.SecretData = []commonDTO.SecretDataKeyValue{}
	missingSecretKey := validAddSecretRequest
	missingSecretKey.SecretData = []commonDTO.SecretDataKeyValue{
		{Key: "", Value: "username"},
	}
	missingSecretValue := validAddSecretRequest
	missingSecretValue.SecretData = []commonDTO.SecretDataKeyValue{
		{Key: "username", Value: ""},
	}
	addFailure := validAddSecretRequest
	addFailure.SecretName = "fail"

	tests := []struct {
		Name               string
		Request            commonDTO.SecretRequest
		ErrorExpected      bool
		ExpectedStatusCode int
	}{
		{"Valid - no requestId", validNoRequestId, false, http.StatusCreated},
		{"Invalid - no path", NoPath, true, http.StatusBadRequest},
		{"Invalid - bad requestId", badRequestId, true, http.StatusBadRequest},
		{"Invalid - no secrets", noSecrets, true, http.StatusBadRequest},
		{"Invalid - missing secret key", missingSecretKey, true, http.StatusBadRequest},
		{"Invalid - missing secret value", missingSecretValue, true, http.StatusBadRequest},
		{"Invalid - add failure", addFailure, true, http.StatusInternalServerError},
	}

	for _, testCase := range tests {
		t.Run(testCase.Name, func(t *testing.T) {
			jsonData, err := json.Marshal(testCase.Request)
			require.NoError(t, err)

			reader := strings.NewReader(string(jsonData))
			req, err := http.NewRequest(http.MethodPost, common.ApiSecretRoute, reader)
			require.NoError(t, err)

			recorder := httptest.NewRecorder()
			handler := echo.HandlerFunc(target.AddSecret)
			c := e.NewContext(req, recorder)
			err = handler(c)
			assert.NoError(t, err)

			actualResponse := commonDTO.BaseResponse{}
			err = json.Unmarshal(recorder.Body.Bytes(), &actualResponse)
			require.NoError(t, err)

			assert.Equal(t, testCase.ExpectedStatusCode, recorder.Result().StatusCode, "HTTP status code not as expected")
			assert.Equal(t, common.ApiVersion, actualResponse.ApiVersion, "Api Version not as expected")
			assert.Equal(t, testCase.ExpectedStatusCode, actualResponse.StatusCode, "BaseResponse status code not as expected")

			if testCase.ErrorExpected {
				assert.NotEmpty(t, actualResponse.Message, "Message is empty")
			} else {
				assert.Empty(t, actualResponse.Message, "Message not empty, as expected")
			}
		})
	}
}

func TestPingRequest(t *testing.T) {
	e := echo.New()
	serviceName := uuid.NewString()
	dic := mockDic()
	target := NewCommonController(dic, e, serviceName, serviceVersion)

	recorder := doRequest(t, http.MethodGet, common.ApiPingRoute, target.Ping, nil)

	actual := commonDTO.PingResponse{}
	err := json.Unmarshal(recorder.Body.Bytes(), &actual)
	require.NoError(t, err)

	_, err = time.Parse(time.UnixDate, actual.Timestamp)
	assert.NoError(t, err)

	assert.Equal(t, common.ApiVersion, actual.ApiVersion)
	assert.Equal(t, serviceName, actual.ServiceName)
}

func TestVersionRequest(t *testing.T) {
	e := echo.New()
	expectedSdkVersion := "1.3.1"
	serviceName := uuid.NewString()
	dic := mockDic()
	target := NewCommonController(dic, e, serviceName, serviceVersion)
	target.SetSDKVersion(expectedSdkVersion)

	recorder := doRequest(t, http.MethodGet, common.ApiVersion, target.Version, nil)

	actual := commonDTO.VersionSdkResponse{}
	err := json.Unmarshal(recorder.Body.Bytes(), &actual)
	require.NoError(t, err)

	assert.Equal(t, common.ApiVersion, actual.ApiVersion)
	assert.Equal(t, serviceVersion, actual.Version)
	assert.Equal(t, expectedSdkVersion, actual.SdkVersion)
	assert.Equal(t, serviceName, actual.ServiceName)
}

func TestConfigRequest(t *testing.T) {
	e := echo.New()
	expectedConfig := TestConfig{
		Service: bootstrapConfig.ServiceInfo{
			Host: "localhost",
			Port: 8080,
		},
	}

	serviceName := uuid.NewString()

	dic := mockDic()
	dic.Update(di.ServiceConstructorMap{
		container.ConfigurationInterfaceName: func(get di.Get) interface{} {
			return expectedConfig
		},
	})
	target := NewCommonController(dic, e, serviceName, serviceVersion)

	recorder := doRequest(t, http.MethodGet, common.ApiConfigRoute, target.Config, nil)

	actualResponse := commonDTO.ConfigResponse{}
	err := json.Unmarshal(recorder.Body.Bytes(), &actualResponse)
	require.NoError(t, err)

	assert.Equal(t, common.ApiVersion, actualResponse.ApiVersion)
	assert.Equal(t, serviceName, actualResponse.ServiceName)

	// actualResponse.Config is an interface{} so need to re-marshal/un-marshal into TestConfig
	configJson, err := json.Marshal(actualResponse.Config)
	require.NoError(t, err)
	require.Less(t, 0, len(configJson))

	actualConfig := TestConfig{}
	err = json.Unmarshal(configJson, &actualConfig)
	require.NoError(t, err)

	assert.Equal(t, expectedConfig, actualConfig)
}

func TestConfigRequest_CustomConfig(t *testing.T) {
	e := echo.New()
	expectedConfig := TestConfig{
		Service: bootstrapConfig.ServiceInfo{
			Host: "localhost",
			Port: 8080,
		},
	}

	expectedCustomConfig := TestCustomConfig{
		"test custom config",
	}

	serviceName := uuid.NewString()

	dic := mockDic()
	dic.Update(di.ServiceConstructorMap{
		container.ConfigurationInterfaceName: func(get di.Get) interface{} {
			return expectedConfig
		},
	})

	type fullConfig struct {
		TestConfig
		CustomConfiguration TestCustomConfig
	}

	expectedFullConfig := fullConfig{
		expectedConfig,
		expectedCustomConfig,
	}

	target := NewCommonController(dic, e, serviceName, serviceVersion)
	target.SetCustomConfigInfo(expectedCustomConfig)
	recorder := doRequest(t, http.MethodGet, common.ApiConfigRoute, target.Config, nil)

	actualResponse := commonDTO.ConfigResponse{}
	err := json.Unmarshal(recorder.Body.Bytes(), &actualResponse)
	require.NoError(t, err)

	assert.Equal(t, common.ApiVersion, actualResponse.ApiVersion)
	assert.Equal(t, serviceName, actualResponse.ServiceName)

	// actualResponse.Config is an interface{} so need to re-marshal/un-marshal into config.ConfigurationStruct
	configJson, err := json.Marshal(actualResponse.Config)
	require.NoError(t, err)
	require.Less(t, 0, len(configJson))

	actualConfig := fullConfig{}
	err = json.Unmarshal(configJson, &actualConfig)
	require.NoError(t, err)
	assert.Equal(t, expectedFullConfig, actualConfig)
}

func doRequest(t *testing.T, method string, api string, handler echo.HandlerFunc, body io.Reader) *httptest.ResponseRecorder {
	e := echo.New()
	req, err := http.NewRequest(method, api, body)
	require.NoError(t, err)
	expectedCorrelationId := uuid.New().String()
	req.Header.Set(common.CorrelationHeader, expectedCorrelationId)

	recorder := httptest.NewRecorder()

	c := e.NewContext(req, recorder)
	err = handler(c)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, recorder.Code, "Wrong status code")
	assert.Equal(t, common.ContentTypeJSON, recorder.Header().Get(common.ContentType), "Content type not set or not JSON")
	assert.Equal(t, expectedCorrelationId, recorder.Header().Get(common.CorrelationHeader), "CorrelationHeader not as expected")

	require.NotEmpty(t, recorder.Body.String(), "Response body is empty")

	return recorder
}

type TestConfig struct {
	Service bootstrapConfig.ServiceInfo
}

func (tc TestConfig) UpdateFromRaw(_ interface{}) bool {
	panic("should not be called")
}

func (tc TestConfig) UpdateWritableFromRaw(_ interface{}) bool {
	panic("should not be called")
}

func (tc TestConfig) EmptyWritablePtr() interface{} {
	panic("should not be called")
}

func (tc TestConfig) GetBootstrap() bootstrapConfig.BootstrapConfiguration {
	return bootstrapConfig.BootstrapConfiguration{
		Service: &tc.Service,
	}
}

func (tc TestConfig) GetLogLevel() string {
	return "TRACE"
}

func (tc TestConfig) GetRegistryInfo() bootstrapConfig.RegistryInfo {
	panic("should not be called")
}

func (tc TestConfig) GetInsecureSecrets() bootstrapConfig.InsecureSecrets {
	return nil
}

func (tc TestConfig) GetTelemetryInfo() *bootstrapConfig.TelemetryInfo {
	panic("should not be called")
}

func (tc TestConfig) GetWritablePtr() any {
	panic("should not be called")
}

type TestCustomConfig struct {
	Sample string
}

func (t TestCustomConfig) UpdateFromRaw(_ interface{}) bool {
	return true
}
