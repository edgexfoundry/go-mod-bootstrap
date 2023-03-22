/*******************************************************************************
 * Copyright 2023 Intel Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/

package utils

import (
	"encoding/json"
	"fmt"
)

// ConvertToMap uses json to marshal and unmarshal a target type into a map
func ConvertToMap(target any, m *map[string]any) error {
	jsonBytes, err := json.Marshal(target)
	if err != nil {
		return fmt.Errorf("could not marshal %T to JSON: %v", target, err)
	}
	if err = json.Unmarshal(jsonBytes, &m); err != nil {
		return fmt.Errorf("could not unmarshal JSON (from %T) into a map: %v", target, err)
	}
	return nil
}

// ConvertFromMap uses json to marshal and unmarshal a map into a target type
func ConvertFromMap(m map[string]any, target any) error {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("could not marshal map to JSON: %v", err)
	}

	if err := json.Unmarshal(jsonBytes, target); err != nil {
		return fmt.Errorf("could not unmarshal JSON to %T: %v", target, err)
	}

	return nil
}
