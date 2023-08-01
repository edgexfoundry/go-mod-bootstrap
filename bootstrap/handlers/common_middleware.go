//
// Copyright (C) 2023 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/common"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/models"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func ManageHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		correlationID := r.Header.Get(common.CorrelationHeader)
		if correlationID == "" {
			correlationID = uuid.New().String()
		}
		// lint:ignore SA1029 legacy
		// nolint:staticcheck // See golangci-lint #741
		ctx := context.WithValue(r.Context(), common.CorrelationHeader, correlationID)

		contentType := r.Header.Get(common.ContentType)
		// lint:ignore SA1029 legacy
		// nolint:staticcheck // See golangci-lint #741
		ctx = context.WithValue(ctx, common.ContentType, contentType)

		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func LoggingMiddleware(lc logger.LoggingClient) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if lc.LogLevel() == models.TraceLog {
				begin := time.Now()
				correlationId := FromContext(r.Context())
				lc.Trace("Begin request", common.CorrelationHeader, correlationId, "path", r.URL.Path)
				next.ServeHTTP(w, r)
				lc.Trace("Response complete", common.CorrelationHeader, correlationId, "duration", time.Since(begin).String())

			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// UrlDecodeMiddleware decode the path variables
// After invoking the router.UseEncodedPath() func, the path variables needs to decode before passing to the controller
func UrlDecodeMiddleware(lc logger.LoggingClient) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var unescapedParams []string
			// Retrieve all the url path param names
			paramNames := c.ParamNames()

			// Retrieve all the url path param values and decode
			for k, v := range c.ParamValues() {
				unescape, err := url.PathUnescape(v)
				if err != nil {
					lc.Debugf("failed to decode the %s from the value %s", paramNames[k], v)
					return err
				}
				unescapedParams = append(unescapedParams, unescape)
			}
			c.SetParamValues(unescapedParams...)
			return next(c)
		}
	}
}

func FromContext(ctx context.Context) string {
	hdr, ok := ctx.Value(common.CorrelationHeader).(string)
	if !ok {
		hdr = ""
	}
	return hdr
}
