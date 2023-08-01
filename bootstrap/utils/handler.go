//
// Copyright (C) 2023 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// WrapHandler wraps `HandlerFunc func(http.ResponseWriter, *http.Request)` into `echo.HandlerFunc`
func WrapHandler(handler func(http.ResponseWriter, *http.Request)) echo.HandlerFunc {
	return func(c echo.Context) error {
		handler(c.Response(), c.Request())
		return nil
	}
}

// WrapMiddleware wraps `HandlerFunc func(http.ResponseWriter, *http.Request)` into `echo.MiddlewareFunc`
func WrapMiddleware(handler func(http.ResponseWriter, *http.Request)) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			handler(c.Response(), c.Request())
			return next(c)
		}
	}
}

// WrapMiddlewareFunc wraps `func(http.HandlerFunc) http.HandlerFunc` into `echo.HandlerFunc`
func WrapMiddlewareFunc(handler func(http.HandlerFunc) http.HandlerFunc) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			handler(func(w http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				c.SetResponse(echo.NewResponse(w, c.Echo()))
				err = next(c)
			}).ServeHTTP(c.Response(), c.Request())
			return
		}
	}
}
