//
// Copyright (C) 2021 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"github.com/edgexfoundry/go-mod-bootstrap/v2/di"
	v2Clients "github.com/edgexfoundry/go-mod-core-contracts/v2/v2/clients/interfaces"
)

// CommonClientName contains the name of the CommonClient instance in the DIC.
var CommonClientName = "V2CommonClient"

// CommonClientFrom helper function queries the DIC and returns the CommonClient instance.
func CommonClientFrom(get di.Get) v2Clients.CommonClient {
	return get(CommonClientName).(v2Clients.CommonClient)
}
