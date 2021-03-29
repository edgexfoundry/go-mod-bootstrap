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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadAccessToken(t *testing.T) {
	expectedToken := "UnitTestToken"
	tokenFile := "./consul-token"

	err := ioutil.WriteFile(tokenFile, []byte(expectedToken), os.ModePerm)
	defer func() { _ = os.Remove(tokenFile) }()
	require.NoError(t, err)

	tests := []struct {
		name          string
		tokenFile     string
		expectedToken string
		expectError   bool
	}{
		{"token file exists", tokenFile, expectedToken, false},
		{"token file doesn't exists", "./no-file", "", true},
		{"token file path empty", "", "", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualToken, err := LoadAccessToken(test.tokenFile)
			if test.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expectedToken, actualToken)
		})
	}
}
