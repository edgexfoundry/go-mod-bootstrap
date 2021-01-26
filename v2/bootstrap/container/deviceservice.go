//
// Copyright (C) 2021 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"github.com/edgexfoundry/go-mod-bootstrap/v2/di"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/v2/clients/interfaces"
)

// DeviceServiceCallbackClientName contains the name of the DeviceServiceCallbackClient instance in the DIC.
var DeviceServiceCallbackClientName = di.TypeInstanceToName((*interfaces.DeviceServiceCallbackClient)(nil))

// DeviceServiceCallbackClientFrom helper function queries the DIC and returns the DeviceServiceCallbackClientFrom instance.
func DeviceServiceCallbackClientFrom(get di.Get) interfaces.DeviceServiceCallbackClient {
	client, ok := get(DeviceServiceCallbackClientName).(interfaces.DeviceServiceCallbackClient)
	if !ok {
		return nil
	}

	return client
}
