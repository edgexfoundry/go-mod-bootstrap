// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// __          __              _
// \ \        / /             (_)
//  \ \  /\  / /_ _ _ __ _ __  _ _ __   __ _
//   \ \/  \/ / _` | '__| '_ \| | '_ \ / _` |
//    \  /\  / (_| | |  | | | | | | | | (_| | : This file is generated, do not edit it.
//     \/  \/ \__,_|_|  |_| |_|_|_| |_|\__, |
//                                      __/ |
//                                     |___/

package edge_router_policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewListEdgeRouterPoliciesParams creates a new ListEdgeRouterPoliciesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListEdgeRouterPoliciesParams() *ListEdgeRouterPoliciesParams {
	return &ListEdgeRouterPoliciesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListEdgeRouterPoliciesParamsWithTimeout creates a new ListEdgeRouterPoliciesParams object
// with the ability to set a timeout on a request.
func NewListEdgeRouterPoliciesParamsWithTimeout(timeout time.Duration) *ListEdgeRouterPoliciesParams {
	return &ListEdgeRouterPoliciesParams{
		timeout: timeout,
	}
}

// NewListEdgeRouterPoliciesParamsWithContext creates a new ListEdgeRouterPoliciesParams object
// with the ability to set a context for a request.
func NewListEdgeRouterPoliciesParamsWithContext(ctx context.Context) *ListEdgeRouterPoliciesParams {
	return &ListEdgeRouterPoliciesParams{
		Context: ctx,
	}
}

// NewListEdgeRouterPoliciesParamsWithHTTPClient creates a new ListEdgeRouterPoliciesParams object
// with the ability to set a custom HTTPClient for a request.
func NewListEdgeRouterPoliciesParamsWithHTTPClient(client *http.Client) *ListEdgeRouterPoliciesParams {
	return &ListEdgeRouterPoliciesParams{
		HTTPClient: client,
	}
}

/* ListEdgeRouterPoliciesParams contains all the parameters to send to the API endpoint
   for the list edge router policies operation.

   Typically these are written to a http.Request.
*/
type ListEdgeRouterPoliciesParams struct {

	// Filter.
	Filter *string

	// Limit.
	Limit *int64

	// Offset.
	Offset *int64

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list edge router policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListEdgeRouterPoliciesParams) WithDefaults() *ListEdgeRouterPoliciesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list edge router policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListEdgeRouterPoliciesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the list edge router policies params
func (o *ListEdgeRouterPoliciesParams) WithTimeout(timeout time.Duration) *ListEdgeRouterPoliciesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list edge router policies params
func (o *ListEdgeRouterPoliciesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list edge router policies params
func (o *ListEdgeRouterPoliciesParams) WithContext(ctx context.Context) *ListEdgeRouterPoliciesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list edge router policies params
func (o *ListEdgeRouterPoliciesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list edge router policies params
func (o *ListEdgeRouterPoliciesParams) WithHTTPClient(client *http.Client) *ListEdgeRouterPoliciesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list edge router policies params
func (o *ListEdgeRouterPoliciesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the list edge router policies params
func (o *ListEdgeRouterPoliciesParams) WithFilter(filter *string) *ListEdgeRouterPoliciesParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the list edge router policies params
func (o *ListEdgeRouterPoliciesParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the list edge router policies params
func (o *ListEdgeRouterPoliciesParams) WithLimit(limit *int64) *ListEdgeRouterPoliciesParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the list edge router policies params
func (o *ListEdgeRouterPoliciesParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the list edge router policies params
func (o *ListEdgeRouterPoliciesParams) WithOffset(offset *int64) *ListEdgeRouterPoliciesParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the list edge router policies params
func (o *ListEdgeRouterPoliciesParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WriteToRequest writes these params to a swagger request
func (o *ListEdgeRouterPoliciesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Filter != nil {

		// query param filter
		var qrFilter string

		if o.Filter != nil {
			qrFilter = *o.Filter
		}
		qFilter := qrFilter
		if qFilter != "" {

			if err := r.SetQueryParam("filter", qFilter); err != nil {
				return err
			}
		}
	}

	if o.Limit != nil {

		// query param limit
		var qrLimit int64

		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := swag.FormatInt64(qrLimit)
		if qLimit != "" {

			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}
	}

	if o.Offset != nil {

		// query param offset
		var qrOffset int64

		if o.Offset != nil {
			qrOffset = *o.Offset
		}
		qOffset := swag.FormatInt64(qrOffset)
		if qOffset != "" {

			if err := r.SetQueryParam("offset", qOffset); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
