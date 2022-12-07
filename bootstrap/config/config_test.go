/*******************************************************************************
 * Copyright 2022 Intel Corp.
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
package config

import (
	"github.com/edgexfoundry/go-mod-bootstrap/v3/config"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	expectedUsername = "admin"
	expectedPassword = "password"
	expectedPath     = "redisdb"
	UsernameKey      = "username"
	PasswordKey      = "password"
)

func TestGetSecretPathsChanged(t *testing.T) {
	prevVals := config.InsecureSecrets{
		"DB": config.InsecureSecretsInfo{
			Path: expectedPath,
			Secrets: map[string]string{
				UsernameKey: "edgex",
				PasswordKey: expectedPassword,
			}}}

	curVals := config.InsecureSecrets{
		"DB": config.InsecureSecretsInfo{
			Path: expectedPath,
			Secrets: map[string]string{
				UsernameKey: expectedUsername,
				PasswordKey: expectedPassword,
			}}}

	tests := []struct {
		Name         string
		UpdatedPaths []string
		curVals      config.InsecureSecrets
		prevVals     config.InsecureSecrets
	}{
		{"Valid - No updates", nil, curVals, curVals},
		{"Valid - Secret update", []string{expectedPath}, prevVals, curVals},
		{"Valid - New Secret", []string{expectedPath}, prevVals, config.InsecureSecrets{
			"DB": config.InsecureSecretsInfo{
				Path: expectedPath,
				Secrets: map[string]string{
					UsernameKey: expectedUsername,
					PasswordKey: expectedPassword,
					"attempts":  "1",
				}}}},
		{"Valid - Deleted Secret", []string{expectedPath}, prevVals, config.InsecureSecrets{
			"DB": config.InsecureSecretsInfo{
				Path: expectedPath,
				Secrets: map[string]string{
					UsernameKey: expectedUsername,
				}}}},
		{"Valid - Path update", []string{"redisdb", "message-bus"}, curVals,
			config.InsecureSecrets{
				"DB": config.InsecureSecretsInfo{
					Path: "message-bus",
					Secrets: map[string]string{
						UsernameKey: expectedUsername,
						PasswordKey: expectedPassword,
					}}}},
		{"Valid - Path delete", []string{expectedPath}, config.InsecureSecrets{
			"DB": config.InsecureSecretsInfo{}}, prevVals},
		{"Valid - No updates, unsorted keys", nil, curVals, config.InsecureSecrets{
			"DB": config.InsecureSecretsInfo{
				Path: expectedPath,
				Secrets: map[string]string{
					PasswordKey: expectedPassword,
					UsernameKey: expectedUsername,
				}}}},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			updatedPaths := getSecretPathsChanged(tc.prevVals, tc.curVals)
			assert.Equal(t, tc.UpdatedPaths, updatedPaths)
		})
	}
}
