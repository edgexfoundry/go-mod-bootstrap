//
// Copyright (C) 2021 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"github.com/edgexfoundry/go-mod-bootstrap/v2/di"
	v2Clients "github.com/edgexfoundry/go-mod-core-contracts/v2/v2/clients/interfaces"
)

// DataEventClientName contains the name of the EventClient instance in the DIC.
var DataEventClientName = "V2DataEventClient"

// DataReadingClientName contains the name of the ReadingClient instance in the DIC.
var DataReadingClientName = "V2DataReadingClient"

// DataEventClientFrom helper function queries the DIC and returns the EventClient instance.
func DataEventClientFrom(get di.Get) v2Clients.EventClient {
	return get(DataEventClientName).(v2Clients.EventClient)
}

// DataReadingClientFrom helper function queries the DIC and returns the ReadingClient instance.
func DataReadingClientFrom(get di.Get) v2Clients.ReadingClient {
	return get(DataReadingClientName).(v2Clients.ReadingClient)
}
