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
	"os"
	"testing"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/common"
	gometrics "github.com/rcrowley/go-metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/dtos"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/config"
	"github.com/edgexfoundry/go-mod-bootstrap/v4/di"

	"github.com/edgexfoundry/go-mod-messaging/v4/messaging/mocks"
	"github.com/edgexfoundry/go-mod-messaging/v4/pkg/types"
)

func TestNewMessageBusReporter(t *testing.T) {
	expectedServiceName := "test-service"
	expectedBaseTopic := common.BuildTopic(common.DefaultBaseTopic, common.MetricsPublishTopic, expectedServiceName)

	expectedTelemetryConfig := &config.TelemetryInfo{
		Interval: "30s",
		Metrics: map[string]bool{
			"MyMetric": true,
		},
		Tags: nil,
	}

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
			r := NewMessageBusReporter(logger.NewMockClient(), common.DefaultBaseTopic, test.ExpectedServiceName, nil, expectedTelemetryConfig)
			actual := r.(*messageBusReporter)
			assert.NotNil(t, actual)
			assert.Equal(t, expectedServiceName, actual.serviceName)
			assert.Equal(t, expectedTelemetryConfig, actual.config)
			assert.Equal(t, expectedBaseTopic, actual.baseMetricsTopic)
		})
	}

}

func TestMessageBusReporter_Report(t *testing.T) {
	expectedServiceName := "test-service"
	expectedMetricName := "test-metric"
	unexpectedMetricName := "disabled-metric"
	expectedTopic := common.BuildTopic(common.DefaultBaseTopic, common.MetricsPublishTopic, expectedServiceName, expectedMetricName)

	expectedTelemetryConfig := &config.TelemetryInfo{
		Interval: "30s",
		Metrics: map[string]bool{
			expectedMetricName:   true,
			unexpectedMetricName: false,
		},
		Tags: nil,
	}

	expectedTags := []dtos.MetricTag{
		{
			Name:  serviceNameTagKey,
			Value: expectedServiceName,
		},
	}
	intValue := int64(50)
	expectedCounterMetric, err := dtos.NewMetric(expectedMetricName,
		[]dtos.MetricField{
			{
				Name:  counterCountName,
				Value: intValue,
			}},
		expectedTags)
	require.NoError(t, err)

	reg := gometrics.NewRegistry()

	counter := gometrics.NewCounter()
	counter.Inc(intValue)

	disabledCounter := gometrics.NewCounter()
	disabledCounter.Inc(intValue)
	err = reg.Register(unexpectedMetricName, disabledCounter)
	require.NoError(t, err)

	gauge := gometrics.NewGauge()
	gauge.Update(intValue)
	expectedGaugeMetric := expectedCounterMetric
	expectedGaugeMetric.Fields = []dtos.MetricField{
		{
			Name:  gaugeValueName,
			Value: intValue,
		}}

	floatValue := 50.55
	expectedGaugeFloat64Metric := expectedCounterMetric
	expectedGaugeFloat64Metric.Fields = []dtos.MetricField{
		{
			Name:  gaugeFloat64ValueName,
			Value: floatValue,
		}}
	gaugeFloat64 := gometrics.NewGaugeFloat64()
	gaugeFloat64.Update(floatValue)

	expectedTimerMetric := expectedCounterMetric
	copy(expectedTimerMetric.Fields, expectedCounterMetric.Fields)
	expectedTimerMetric.Fields = []dtos.MetricField{
		{
			Name:  timerCountName,
			Value: int64(0),
		}}
	expectedTimerMetric.Fields = append(expectedTimerMetric.Fields,
		[]dtos.MetricField{
			{Name: timerMinName, Value: int64(0)},
			{Name: timerMaxName, Value: int64(0)},
			{Name: timerMeanName, Value: float64(0)},
			{Name: timerStddevName, Value: float64(0)},
			{Name: timerVarianceName, Value: float64(0)},
		}...)
	timer := gometrics.NewTimer()

	expectedHistogramMetric := expectedCounterMetric
	copy(expectedHistogramMetric.Fields, expectedCounterMetric.Fields)
	expectedHistogramMetric.Fields = []dtos.MetricField{
		{
			Name:  histogramCountName,
			Value: int64(0),
		}}
	expectedHistogramMetric.Fields = append(expectedHistogramMetric.Fields,
		[]dtos.MetricField{
			{Name: histogramMinName, Value: int64(0)},
			{Name: histogramMaxName, Value: int64(0)},
			{Name: histogramMeanName, Value: float64(0)},
			{Name: histogramStddevName, Value: float64(0)},
			{Name: histogramVarianceName, Value: float64(0)},
		}...)
	histogram := gometrics.NewHistogram(gometrics.NewUniformSample(1028))

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
		{"Happy path - Histogram", histogram, &expectedHistogramMetric, false},
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
				//actual := dtos.Metric{}
				actual, err := types.GetMsgPayload[dtos.Metric](message)
				require.NoError(t, err)
				assert.Equal(t, expectedMetricName, actual.Name)
				actual.Timestamp = test.ExpectedMetric.Timestamp
				assert.Equal(t, *test.ExpectedMetric, actual)
				topicArg := args.Get(1)
				require.NotNil(t, topicArg)
				assert.Equal(t, expectedTopic, topicArg)
			})

			dic := di.NewContainer(di.ServiceConstructorMap{
				container.MessagingClientName: func(get di.Get) interface{} {
					return mockClient
				},
			})

			target := NewMessageBusReporter(logger.NewMockClient(), common.DefaultBaseTopic, expectedServiceName, dic, expectedTelemetryConfig)

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

func TestMessageBusReporter_ReportWithEnv(t *testing.T) {
	_ = os.Setenv("EDGEX_MSG_BASE64_PAYLOAD", common.ValueTrue)
	defer os.Setenv("EDGEX_MSG_BASE64_PAYLOAD", common.ValueFalse)

	expectedServiceName := "test-service"
	expectedMetricName := "test-metric"
	unexpectedMetricName := "disabled-metric"
	expectedTopic := common.BuildTopic(common.DefaultBaseTopic, common.MetricsPublishTopic, expectedServiceName, expectedMetricName)

	expectedTelemetryConfig := &config.TelemetryInfo{
		Interval: "30s",
		Metrics: map[string]bool{
			expectedMetricName:   true,
			unexpectedMetricName: false,
		},
		Tags: nil,
	}

	expectedTags := []dtos.MetricTag{
		{
			Name:  serviceNameTagKey,
			Value: expectedServiceName,
		},
	}
	intValue := int64(50)
	expectedCounterMetric, err := dtos.NewMetric(expectedMetricName,
		[]dtos.MetricField{
			{
				Name:  counterCountName,
				Value: float64(intValue), // Has to be a float64 since the JSON un-marshaling of the interface sets it as a float64
			}},
		expectedTags)
	require.NoError(t, err)

	reg := gometrics.NewRegistry()

	counter := gometrics.NewCounter()
	counter.Inc(intValue)

	disabledCounter := gometrics.NewCounter()
	disabledCounter.Inc(intValue)
	err = reg.Register(unexpectedMetricName, disabledCounter)
	require.NoError(t, err)

	gauge := gometrics.NewGauge()
	gauge.Update(intValue)
	expectedGaugeMetric := expectedCounterMetric
	expectedGaugeMetric.Fields = []dtos.MetricField{
		{
			Name:  gaugeValueName,
			Value: float64(intValue), // Has to be a float64 since the JSON un-marshaling of the interface sets it as a float64
		}}

	floatValue := 50.55
	expectedGaugeFloat64Metric := expectedCounterMetric
	expectedGaugeFloat64Metric.Fields = []dtos.MetricField{
		{
			Name:  gaugeFloat64ValueName,
			Value: floatValue,
		}}
	gaugeFloat64 := gometrics.NewGaugeFloat64()
	gaugeFloat64.Update(floatValue)

	expectedTimerMetric := expectedCounterMetric
	copy(expectedTimerMetric.Fields, expectedCounterMetric.Fields)
	expectedTimerMetric.Fields = []dtos.MetricField{
		{
			Name:  timerCountName,
			Value: float64(0),
		}}
	expectedTimerMetric.Fields = append(expectedTimerMetric.Fields,
		[]dtos.MetricField{
			{Name: timerMinName, Value: float64(0)},
			{Name: timerMaxName, Value: float64(0)},
			{Name: timerMeanName, Value: float64(0)},
			{Name: timerStddevName, Value: float64(0)},
			{Name: timerVarianceName, Value: float64(0)},
		}...)
	timer := gometrics.NewTimer()

	expectedHistogramMetric := expectedCounterMetric
	copy(expectedHistogramMetric.Fields, expectedCounterMetric.Fields)
	expectedHistogramMetric.Fields = []dtos.MetricField{
		{
			Name:  histogramCountName,
			Value: float64(0),
		}}
	expectedHistogramMetric.Fields = append(expectedHistogramMetric.Fields,
		[]dtos.MetricField{
			{Name: histogramMinName, Value: float64(0)},
			{Name: histogramMaxName, Value: float64(0)},
			{Name: histogramMeanName, Value: float64(0)},
			{Name: histogramStddevName, Value: float64(0)},
			{Name: histogramVarianceName, Value: float64(0)},
		}...)
	histogram := gometrics.NewHistogram(gometrics.NewUniformSample(1028))

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
		{"Happy path - Histogram", histogram, &expectedHistogramMetric, false},
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
				actual, err := types.GetMsgPayload[dtos.Metric](message)
				require.NoError(t, err)
				assert.Equal(t, expectedMetricName, actual.Name)
				actual.Timestamp = test.ExpectedMetric.Timestamp
				assert.Equal(t, *test.ExpectedMetric, actual)
				topicArg := args.Get(1)
				require.NotNil(t, topicArg)
				assert.Equal(t, expectedTopic, topicArg)
			})

			dic := di.NewContainer(di.ServiceConstructorMap{
				container.MessagingClientName: func(get di.Get) interface{} {
					return mockClient
				},
			})

			target := NewMessageBusReporter(logger.NewMockClient(), common.DefaultBaseTopic, expectedServiceName, dic, expectedTelemetryConfig)

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
