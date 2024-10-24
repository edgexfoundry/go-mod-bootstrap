//
// Copyright (C) 2023 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger/mocks"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/common"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var expectedCorrelationId = "927e91d3-864c-4c26-852d-b68c39492d14"

var handler = func(c echo.Context) error {
	return c.String(http.StatusOK, "OK")
}

func TestManageHeader(t *testing.T) {
	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		c.Response().Header().Set(common.CorrelationHeader, c.Request().Context().Value(common.CorrelationHeader).(string))
		c.Response().Header().Set(common.ContentType, c.Request().Context().Value(common.ContentType).(string))
		c.Response().WriteHeader(http.StatusOK)
		return nil
	})
	e.Use(ManageHeader)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(common.CorrelationHeader, expectedCorrelationId)
	expectedContentType := common.ContentTypeJSON
	req.Header.Set(common.ContentType, expectedContentType)
	res := httptest.NewRecorder()
	e.ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Equal(t, expectedCorrelationId, res.Header().Get(common.CorrelationHeader))
	assert.Equal(t, expectedContentType, res.Header().Get(common.ContentType))
}

func TestLoggingMiddleware(t *testing.T) {
	e := echo.New()
	e.GET("/", handler)
	lcMock := &mocks.LoggingClient{}
	lcMock.On("Trace", "Begin request", common.CorrelationHeader, expectedCorrelationId, "path", "/")
	lcMock.On("Trace", "Response complete", common.CorrelationHeader, expectedCorrelationId, "duration", mock.Anything)
	lcMock.On("LogLevel").Return("TRACE")
	e.Use(LoggingMiddleware(lcMock))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// lint:ignore SA1029 legacy
	// nolint:staticcheck // See golangci-lint #741
	ctx := context.WithValue(req.Context(), common.CorrelationHeader, expectedCorrelationId)
	req = req.WithContext(ctx)
	res := httptest.NewRecorder()
	e.ServeHTTP(res, req)

	lcMock.AssertCalled(t, "Trace", "Begin request", common.CorrelationHeader, expectedCorrelationId, "path", "/")
	lcMock.AssertCalled(t, "Trace", "Response complete", common.CorrelationHeader, expectedCorrelationId, "duration", mock.Anything)
	assert.Equal(t, http.StatusOK, res.Code)
}

func TestUrlDecodeMiddleware(t *testing.T) {
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()
	c := e.NewContext(req, res)
	c.SetParamNames("foo")
	c.SetParamValues("abc%2F123%25") // the decoded value is abc/123%

	lc = logger.NewMockClient()
	m := UrlDecodeMiddleware(lc)
	err := m(handler)(c)

	assert.NoError(t, err)
	assert.Equal(t, "abc/123%", c.Param("foo"))
}
