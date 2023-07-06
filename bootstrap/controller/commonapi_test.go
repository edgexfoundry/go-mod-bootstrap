//
// Copyright (C) 2023 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/interfaces/mocks"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/di"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/common"
	commonDTO "github.com/edgexfoundry/go-mod-core-contracts/v3/dtos/common"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var validAddSecretRequest = commonDTO.NewSecretRequest(
	"mqtt",
	[]commonDTO.SecretDataKeyValue{
		{Key: "username", Value: "username"},
		{Key: "password", Value: "password"},
	},
)

func mockDic() *di.Container {
	mockConfig := &mocks.Configuration{}
	mockProvider := &mocks.SecretProvider{}
	mockProvider.On("StoreSecret", validAddSecretRequest.SecretName, map[string]string{"password": "password", "username": "username"}).Return(nil)

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
	dic := mockDic()

	target := NewCommonController(dic, mux.NewRouter(), uuid.NewString(), "0.0.0")
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
	}

	for _, testCase := range tests {
		t.Run(testCase.Name, func(t *testing.T) {
			jsonData, err := json.Marshal(testCase.Request)
			require.NoError(t, err)

			reader := strings.NewReader(string(jsonData))
			req, err := http.NewRequest(http.MethodPost, common.ApiSecretRoute, reader)
			require.NoError(t, err)

			recorder := httptest.NewRecorder()
			handler := http.HandlerFunc(target.AddSecret)
			handler.ServeHTTP(recorder, req)

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
