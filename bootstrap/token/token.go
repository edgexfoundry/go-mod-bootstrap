/*******************************************************************************
 * Copyright 2021 Intel Inc.
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

package token

import (
	"io/ioutil"
	"strings"
)

// LoadAccessToken loads an access token from the specified file path. Since the
// token may not be required, an empty token is returned if the filepath is empty
// or the token file doesn't exist.
func LoadAccessToken(filepath string) (string, error) {
	// access token file not specified means the access token is not needed.
	if len(strings.TrimSpace(filepath)) == 0 {
		return "", nil
	}

	token, err := ioutil.ReadFile(filepath)
	if err != nil {
		return "", err
	}

	return string(token), nil
}
