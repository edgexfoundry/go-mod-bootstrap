//
// Copyright (C) 2022 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"encoding/json"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/common"
	commonDTO "github.com/edgexfoundry/go-mod-core-contracts/v2/dtos/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestLimitMiddleware(t *testing.T) {
	lc := logger.NewMockClient()
	payload := make([]byte, 2048)
	tests := []struct {
		name          string
		sizeLimit     int64
		errorExpected bool
	}{
		{"Valid unlimited size", int64(0), false},
		{"Valid size", int64(2), false},
		{"Invalid size", int64(1), true},
	}

	for _, testCase := range tests {
		middleware := RequestLimitMiddleware(testCase.sizeLimit, lc)
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

		reader := strings.NewReader(string(payload))
		req, err := http.NewRequest(http.MethodPost, "/", reader)
		require.NoError(t, err)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		resp := recorder.Result()

		if testCase.errorExpected {
			var res commonDTO.BaseResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &res)
			require.NoError(t, err)

			assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode, "http status code is not as expected")
			assert.Equal(t, common.ContentTypeJSON, resp.Header.Get(common.ContentType), "http header Content-Type is not as expected")
			assert.Equal(t, http.StatusRequestEntityTooLarge, int(res.StatusCode), "Response status code not as expected")
			assert.NotEmpty(t, res.Message, "Response message doesn't contain the error message")
		}
	}
}
