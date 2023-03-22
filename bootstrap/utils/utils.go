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
	"reflect"
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

// MergeMaps combines the src map keys and values with the dest map keys and values if the key exists
func MergeMaps(dest map[string]any, src map[string]any) {

	var exists bool

	for key, value := range src {
		_, exists = dest[key]
		if !exists {
			dest[key] = value
			continue
		}

		destVal, ok := dest[key].(map[string]any)
		if ok {
			MergeMaps(destVal, value.(map[string]any))
			continue
		}

		dest[key] = value
	}
}

// RemoveZeroValues iterates over a map and removes any zero values it may have
func RemoveZeroValues(target map[string]any) {
	var removeKeys []string
	for key, value := range target {
		sub, ok := value.(map[string]any)
		if ok {
			RemoveZeroValues(sub)
			if len(sub) == 0 {
				removeKeys = append(removeKeys, key)
			}
			continue
		}

		if value == nil || reflect.ValueOf(value).IsZero() {
			removeKeys = append(removeKeys, key)
		}

	}

	for _, key := range removeKeys {
		delete(target, key)
	}
}

// MergeValues combines src (zeros removed) with the dest
func MergeValues(dest any, src any) error {
	var destMap, srcMap map[string]any

	if err := ConvertToMap(dest, &destMap); err != nil {
		return fmt.Errorf("could not create destination map from %T: %s", dest, err.Error())
	}

	if err := ConvertToMap(src, &srcMap); err != nil {
		return fmt.Errorf("could not source create map from %T: %s", src, err.Error())
	}

	// remove zero values from the source to prevent overwriting items in the destination
	// and merge the src with dest
	RemoveZeroValues(srcMap)
	MergeMaps(destMap, srcMap)

	// convert the map back to a dest
	if err := ConvertFromMap(destMap, dest); err != nil {
		return err
	}

	return nil
}
