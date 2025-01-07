//
// Copyright (C) 2025 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"net/http"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"

	"github.com/labstack/echo/v4"
)

// SecretStoreAuthenticationHandlerFunc verifies the JWT with a OpenBao-based JWT authentication check
func SecretStoreAuthenticationHandlerFunc(secretProvider interfaces.SecretProviderExt, lc logger.LoggingClient, token string, c echo.Context) error {
	r := c.Request()
	w := c.Response()

	validToken, err := secretProvider.IsJWTValid(token)
	if err != nil {
		lc.Errorf("Error checking JWT validity by the secret provider: %v ", err)
		// set Response.Committed to true in order to rewrite the status code
		w.Committed = false
		return echo.NewHTTPError(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	} else if !validToken {
		lc.Warnf("Request to '%s' UNAUTHORIZED", r.URL.Path)
		// set Response.Committed to true in order to rewrite the status code
		w.Committed = false
		return echo.NewHTTPError(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
	}
	lc.Debugf("Request to '%s' authorized", r.URL.Path)
	return nil
}
