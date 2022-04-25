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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTelemetryInfo_MetricEnabled(t *testing.T) {
	target := TelemetryInfo{}

	manyMetrics := map[string]bool{
		"OtherMetric":     false,
		"YourMetric":      false,
		"MyMetricSpecial": false,
		"MyMetric":        true,
	}

	tests := []struct {
		Name              string
		Metrics           map[string]bool
		ServiceMetricName string
		Expected          bool
	}{
		{"Simple Match", manyMetrics, "MyMetric", true},
		{"Has Prefix Match", manyMetrics, "MyMetric-1234", true},
		{"No Match", manyMetrics, "1234-MyMetric", false},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			target.Metrics = test.Metrics
			actual := target.MetricEnabled(test.ServiceMetricName)
			assert.Equal(t, test.Expected, actual)
		})
	}
}
