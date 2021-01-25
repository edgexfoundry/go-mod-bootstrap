//
// Copyright (C) 2021 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"github.com/edgexfoundry/go-mod-bootstrap/v2/di"
	v2Clients "github.com/edgexfoundry/go-mod-core-contracts/v2/v2/clients/interfaces"
)

// MetadataDeviceClientName contains the name of the Metadata DeviceClient instance in the DIC.
var MetadataDeviceClientName = "V2MetadataDeviceClient"

// MetadataDeviceProfileClientName contains the name of the Metadata DeviceProfileClient instance in the DIC.
var MetadataDeviceProfileClientName = "V2MetadataDeviceProfileClient"

// MetadataDeviceServiceClientName contains the name of the Metadata DeviceServiceClient instance in the DIC.
var MetadataDeviceServiceClientName = "V2MetadataDeviceServiceClient"

// MetadataProvisionWatcherClientName contains the name of the Metadata ProvisionWatcherClient instance in the DIC.
var MetadataProvisionWatcherClientName = "V2MetadataProvisionWatcherClient"

// MetadataDeviceClientFrom helper function queries the DIC and returns the Metadata DeviceClient instance.
func MetadataDeviceClientFrom(get di.Get) v2Clients.DeviceClient {
	return get(MetadataDeviceClientName).(v2Clients.DeviceClient)
}

// MetadataDeviceProfileClientFrom helper function queries the DIC and returns the Metadata DeviceProfileClient instance.
func MetadataDeviceProfileClientFrom(get di.Get) v2Clients.DeviceProfileClient {
	return get(MetadataDeviceProfileClientName).(v2Clients.DeviceProfileClient)
}

// MetadataDeviceServiceClientFrom helper function queries the DIC and returns the Metadata DeviceServiceClient instance.
func MetadataDeviceServiceClientFrom(get di.Get) v2Clients.DeviceServiceClient {
	return get(MetadataDeviceServiceClientName).(v2Clients.DeviceServiceClient)
}

// MetadataProvisionWatcherClientFrom helper function queries the DIC and returns the Metadata ProvisionWatcherClient instance.
func MetadataProvisionWatcherClientFrom(get di.Get) v2Clients.ProvisionWatcherClient {
	return get(MetadataProvisionWatcherClientName).(v2Clients.ProvisionWatcherClient)
}
