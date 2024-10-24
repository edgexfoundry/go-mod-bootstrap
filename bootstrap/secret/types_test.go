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

package secret

import (
	"testing"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/dtos/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceSecrets_UnmarshalJson_Imported_false(t *testing.T) {
	expected := ServiceSecrets{
		[]ServiceSecret{
			{
				SecretName: "credentials001",
				Imported:   false,
				SecretData: []common.SecretDataKeyValue{{
					Key:   "user1",
					Value: "password1",
				}},
			},
			{
				SecretName: "credentials002",
				Imported:   false,
				SecretData: []common.SecretDataKeyValue{{
					Key:   "user2",
					Value: "password2",
				}},
			},
		},
	}

	data := ` {
    "secrets": [
        {
            "secretName": "credentials001",
            "imported": false,
            "secretData": [
                {
                    "key": "user1",
                    "value": "password1"
                }
            ]
        },
        {
            "secretName": "credentials002",
            "imported": false,
            "secretData": [
                {
                    "key": "user2",
                    "value": "password2"
                }
            ]
        }
    ]
}
`

	secrets, err := UnmarshalServiceSecretsJson([]byte(data))
	require.NoError(t, err)
	assert.Equal(t, expected, *secrets)
}

func TestServiceSecrets_UnmarshalJson_Imported_true(t *testing.T) {
	expected := ServiceSecrets{
		[]ServiceSecret{
			{
				SecretName: "credentials001",
				Imported:   true,
				SecretData: make([]common.SecretDataKeyValue, 0),
			},
			{
				SecretName: "credentials002",
				Imported:   true,
				SecretData: make([]common.SecretDataKeyValue, 0),
			},
		},
	}

	data := ` {
    "secrets": [
        {
            "secretName": "credentials001",
            "imported": true,
            "secretData": []
        },
        {
            "secretName": "credentials002",
            "imported": true,
            "secretData": []
        }
    ]
}
`

	secrets, err := UnmarshalServiceSecretsJson([]byte(data))
	require.NoError(t, err)
	assert.Equal(t, expected, *secrets)
}

func TestServiceSecrets_UnmarshalJson_Failed_Validation(t *testing.T) {
	allGood := `{"secrets": [{"secretName": "auth","imported": false,"secretData": [{"key": "user1","value": "password1"}]}]}`
	noSecretName := `{"secrets": [{"secretName": "","imported": false,"secretData": [{"key": "user1","value": "password1"}]}]}` // nolint:gosec
	//nolint: gosec
	noSecretData := `{"secrets": [{"secretName": "auth","imported": false}]}`
	//nolint: gosec
	emptySecretData := `{"secrets": [{"secretName": "auth","imported": false, "secretData": []}]}`
	missingKey := `{"secrets": [{"secretName": "auth","imported": false,"secretData": [{"value": "password1"}]}]}`
	missingValue := `{"secrets": [{"secretName": "auth","imported": false,"secretData": [{"key": "user1"}]}]}`

	tests := []struct {
		name          string
		data          string
		expectedError string
	}{
		{"All good", allGood, ""},
		{"Empty JSON", `{}`, "ServiceSecrets.Secrets field is required"},
		{"No Secrets", `{"secrets": []}`, "ServiceSecrets.Secrets field should greater than 0"},
		{"No SecretName", noSecretName, "ServiceSecrets.Secrets[0].SecretName field should not be empty string"},
		{"No SecretData", noSecretData, "ServiceSecrets.Secrets[0].SecretData field is required"},
		{"Empty SecretData", emptySecretData, "1 error occurred:\n\t* SecretData for 'auth' must not be empty when Imported=false\n\n"},
		{"Missing Key", missingKey, "ServiceSecrets.Secrets[0].SecretData[0].Key field is required"},
		{"Missing Value", missingValue, "ServiceSecrets.Secrets[0].SecretData[0].Value field is required"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := UnmarshalServiceSecretsJson([]byte(test.data))
			if len(test.expectedError) == 0 {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.EqualError(t, err, test.expectedError)
		})
	}

}

func TestServiceSecrets_MarshalJson(t *testing.T) {
	expected := `{"secrets":[{"secretName":"credentials001","imported":true,"secretData":[]},{"secretName":"credentials002","imported":true,"secretData":[]}]}`
	secrets := ServiceSecrets{
		[]ServiceSecret{
			{
				SecretName: "credentials001",
				Imported:   true,
				SecretData: make([]common.SecretDataKeyValue, 0),
			},
			{
				SecretName: "credentials002",
				SecretData: make([]common.SecretDataKeyValue, 0),
				Imported:   true,
			},
		},
	}

	data, err := secrets.MarshalJson()
	require.NoError(t, err)
	assert.Equal(t, expected, string(data))
}
