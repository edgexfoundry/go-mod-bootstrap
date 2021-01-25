//
// Copyright (C) 2021 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"github.com/edgexfoundry/go-mod-bootstrap/v2/di"
	v2Clients "github.com/edgexfoundry/go-mod-core-contracts/v2/v2/clients/interfaces"
)

// DeviceServiceCallbackClientName contains the name of the DeviceServiceCallbackClient instance in the DIC.
var DeviceServiceCallbackClientName = "V2DeviceServiceCallbackClient"

// DeviceServiceCallbackClientFrom helper function queries the DIC and returns the DeviceServiceCallbackClientFrom instance.
func DeviceServiceCallbackClientFrom(get di.Get) v2Clients.DeviceServiceCallbackClient {
	return get(DeviceServiceCallbackClientName).(v2Clients.DeviceServiceCallbackClient)
}
