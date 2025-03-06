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

package role_attributes

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge-api/rest_model"
)

// ListEdgeRouterRoleAttributesReader is a Reader for the ListEdgeRouterRoleAttributes structure.
type ListEdgeRouterRoleAttributesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListEdgeRouterRoleAttributesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListEdgeRouterRoleAttributesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListEdgeRouterRoleAttributesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListEdgeRouterRoleAttributesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListEdgeRouterRoleAttributesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 503:
		result := NewListEdgeRouterRoleAttributesServiceUnavailable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListEdgeRouterRoleAttributesOK creates a ListEdgeRouterRoleAttributesOK with default headers values
func NewListEdgeRouterRoleAttributesOK() *ListEdgeRouterRoleAttributesOK {
	return &ListEdgeRouterRoleAttributesOK{}
}

/* ListEdgeRouterRoleAttributesOK describes a response with status code 200, with default header values.

A list of role attributes
*/
type ListEdgeRouterRoleAttributesOK struct {
	Payload *rest_model.ListRoleAttributesEnvelope
}

func (o *ListEdgeRouterRoleAttributesOK) Error() string {
	return fmt.Sprintf("[GET /edge-router-role-attributes][%d] listEdgeRouterRoleAttributesOK  %+v", 200, o.Payload)
}
func (o *ListEdgeRouterRoleAttributesOK) GetPayload() *rest_model.ListRoleAttributesEnvelope {
	return o.Payload
}

func (o *ListEdgeRouterRoleAttributesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.ListRoleAttributesEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListEdgeRouterRoleAttributesBadRequest creates a ListEdgeRouterRoleAttributesBadRequest with default headers values
func NewListEdgeRouterRoleAttributesBadRequest() *ListEdgeRouterRoleAttributesBadRequest {
	return &ListEdgeRouterRoleAttributesBadRequest{}
}

/* ListEdgeRouterRoleAttributesBadRequest describes a response with status code 400, with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type ListEdgeRouterRoleAttributesBadRequest struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ListEdgeRouterRoleAttributesBadRequest) Error() string {
	return fmt.Sprintf("[GET /edge-router-role-attributes][%d] listEdgeRouterRoleAttributesBadRequest  %+v", 400, o.Payload)
}
func (o *ListEdgeRouterRoleAttributesBadRequest) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ListEdgeRouterRoleAttributesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListEdgeRouterRoleAttributesUnauthorized creates a ListEdgeRouterRoleAttributesUnauthorized with default headers values
func NewListEdgeRouterRoleAttributesUnauthorized() *ListEdgeRouterRoleAttributesUnauthorized {
	return &ListEdgeRouterRoleAttributesUnauthorized{}
}

/* ListEdgeRouterRoleAttributesUnauthorized describes a response with status code 401, with default header values.

The supplied session does not have the correct access rights to request this resource
*/
type ListEdgeRouterRoleAttributesUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ListEdgeRouterRoleAttributesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /edge-router-role-attributes][%d] listEdgeRouterRoleAttributesUnauthorized  %+v", 401, o.Payload)
}
func (o *ListEdgeRouterRoleAttributesUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ListEdgeRouterRoleAttributesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListEdgeRouterRoleAttributesTooManyRequests creates a ListEdgeRouterRoleAttributesTooManyRequests with default headers values
func NewListEdgeRouterRoleAttributesTooManyRequests() *ListEdgeRouterRoleAttributesTooManyRequests {
	return &ListEdgeRouterRoleAttributesTooManyRequests{}
}

/* ListEdgeRouterRoleAttributesTooManyRequests describes a response with status code 429, with default header values.

The resource requested is rate limited and the rate limit has been exceeded
*/
type ListEdgeRouterRoleAttributesTooManyRequests struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ListEdgeRouterRoleAttributesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /edge-router-role-attributes][%d] listEdgeRouterRoleAttributesTooManyRequests  %+v", 429, o.Payload)
}
func (o *ListEdgeRouterRoleAttributesTooManyRequests) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ListEdgeRouterRoleAttributesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListEdgeRouterRoleAttributesServiceUnavailable creates a ListEdgeRouterRoleAttributesServiceUnavailable with default headers values
func NewListEdgeRouterRoleAttributesServiceUnavailable() *ListEdgeRouterRoleAttributesServiceUnavailable {
	return &ListEdgeRouterRoleAttributesServiceUnavailable{}
}

/* ListEdgeRouterRoleAttributesServiceUnavailable describes a response with status code 503, with default header values.

The request could not be completed due to the server being busy or in a temporarily bad state
*/
type ListEdgeRouterRoleAttributesServiceUnavailable struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ListEdgeRouterRoleAttributesServiceUnavailable) Error() string {
	return fmt.Sprintf("[GET /edge-router-role-attributes][%d] listEdgeRouterRoleAttributesServiceUnavailable  %+v", 503, o.Payload)
}
func (o *ListEdgeRouterRoleAttributesServiceUnavailable) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ListEdgeRouterRoleAttributesServiceUnavailable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
