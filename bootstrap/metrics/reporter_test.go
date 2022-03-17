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

package metrics

import (
	"encoding/json"
	"fmt"
	"testing"

	gometrics "github.com/rcrowley/go-metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/dtos"
	"github.com/edgexfoundry/go-mod-messaging/v2/messaging/mocks"
	"github.com/edgexfoundry/go-mod-messaging/v2/pkg/types"
)

func TestNewMessageBusReporter(t *testing.T) {
	expectedServiceName := "test-service"
	baseTopic := "metrics"
	expectedBaseTopic := "metrics/test-service"

	expectedSingleTag := []dtos.MetricTag{{
		Name:  serviceNameTagKey,
		Value: expectedServiceName,
	}}

	expectedMultiTags := append(expectedSingleTag, dtos.MetricTag{
		Name:  "gateway",
		Value: "my-gateway",
	})

	gatewayTag := map[string]string{expectedMultiTags[1].Name: expectedMultiTags[1].Value}

	tests := []struct {
		Name                string
		ExpectedServiceName string
		Tags                map[string]string
		ExpectedTags        []dtos.MetricTag
	}{
		{"Happy path no additional tags", "test-service", nil, expectedSingleTag},
		{"Happy path with additional tags", "test-service", gatewayTag, expectedMultiTags},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var reporter interface{}
			reporter = NewMessageBusReporter(logger.NewMockClient(), test.ExpectedServiceName, nil, baseTopic, nil)
			actual := reporter.(*messageBusReporter)
			assert.NotNil(t, actual)
			assert.Equal(t, expectedServiceName, actual.serviceName)
			assert.Equal(t, expectedBaseTopic, actual.baseTopic)
			assert.Equal(t, 1, len(actual.serviceTags))
			assert.Equal(t, serviceNameTagKey, actual.serviceTags[0].Name)
			assert.Equal(t, expectedServiceName, actual.serviceTags[0].Value)
		})
	}

}

func TestMessageBusReporter_Report(t *testing.T) {
	expectedServiceName := "test-service"
	expectedMetricName := "test-metric"
	baseTopic := "metrics"
	expectedTopic := fmt.Sprintf("%s/%s/%s", baseTopic, expectedServiceName, expectedMetricName)
	expectedTags := []dtos.MetricTag{
		{
			Name:  serviceNameTagKey,
			Value: expectedServiceName,
		},
	}
	intValue := int64(50)
	expectedCounterMetric, err := dtos.NewMetric(expectedMetricName,
		dtos.MetricField{
			Name:  counterName,
			Value: float64(intValue), // Has to be a float64 since the JSON un-marshaling of the interface sets it as a float64
		},
		nil,
		expectedTags)
	require.NoError(t, err)

	reg := gometrics.DefaultRegistry

	counter := gometrics.NewCounter()
	counter.Inc(intValue)

	gauge := gometrics.NewGauge()
	gauge.Update(intValue)
	expectedGaugeMetric := expectedCounterMetric
	expectedGaugeMetric.Field.Name = gaugeName

	floatValue := 50.55
	expectedGaugeFloat64Metric := expectedCounterMetric
	expectedGaugeFloat64Metric.Field.Name = gaugeFloat64Name
	expectedGaugeFloat64Metric.Field.Value = floatValue
	gaugeFloat64 := gometrics.NewGaugeFloat64()
	gaugeFloat64.Update(floatValue)

	expectedTimerMetric := expectedCounterMetric
	expectedTimerMetric.Field.Name = timerName
	expectedTimerMetric.Field.Value = float64(0)
	expectedTimerMetric.AdditionalFields = []dtos.MetricField{
		{Name: "min", Value: float64(0)},
		{Name: "max", Value: float64(0)},
		{Name: "mean", Value: float64(0)},
		{Name: "stddev", Value: float64(0)},
		{Name: "variance", Value: float64(0)},
	}
	timer := gometrics.NewTimer()

	tests := []struct {
		Name           string
		Metric         interface{}
		ExpectedMetric *dtos.Metric
		ExpectError    bool
	}{
		{"Happy path - Counter", counter, &expectedCounterMetric, false},
		{"Happy path - Gauge", gauge, &expectedGaugeMetric, false},
		{"Happy path - GaugeFloat64", gaugeFloat64, &expectedGaugeFloat64Metric, false},
		{"Happy path - Timer", timer, &expectedTimerMetric, false},
		{"No Metrics", nil, nil, false},
		{"Unsupported Metric", gometrics.NewMeter(), nil, true},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			mockClient := &mocks.MessageClient{}
			mockClient.On("Publish", mock.Anything, mock.Anything).Return(nil).Run(func(args mock.Arguments) {
				metricArg := args.Get(0)
				require.NotNil(t, metricArg)
				message, ok := metricArg.(types.MessageEnvelope)
				require.True(t, ok)
				actual := dtos.Metric{}
				err := json.Unmarshal(message.Payload, &actual)
				require.NoError(t, err)
				actual.Timestamp = test.ExpectedMetric.Timestamp
				assert.Equal(t, *test.ExpectedMetric, actual)
				topicArg := args.Get(1)
				require.NotNil(t, topicArg)
				assert.Equal(t, expectedTopic, topicArg)
			})

			target := NewMessageBusReporter(logger.NewMockClient(), expectedServiceName, mockClient, baseTopic, nil)

			if test.Metric != nil {
				err = reg.Register(expectedMetricName, test.Metric)
				require.NoError(t, err)
				defer reg.Unregister(expectedMetricName)
			}

			err := target.Report(reg, nil)

			if test.ExpectError {
				require.Error(t, err)
				mockClient.AssertNotCalled(t, "Publish")
				return
			}

			require.NoError(t, err)

			if test.ExpectedMetric == nil {
				mockClient.AssertNotCalled(t, "Publish")

			}
		})
	}
}
