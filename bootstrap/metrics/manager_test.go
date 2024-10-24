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
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	gometrics "github.com/rcrowley/go-metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	mocks2 "github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger/mocks"

	"github.com/edgexfoundry/go-mod-bootstrap/v4/bootstrap/interfaces/mocks"
)

func TestNewManager(t *testing.T) {

}

func TestMessageBusReporter_Register(t *testing.T) {
	loggerMock := logger.NewMockClient()
	expectedInterval := time.Second * 5
	reporterMock := &mocks.MetricsReporter{}
	m := NewManager(loggerMock, expectedInterval, reporterMock)
	actual := m.(*manager)
	assert.Equal(t, expectedInterval, actual.interval)
	assert.Equal(t, loggerMock, actual.lc)
	assert.Equal(t, reporterMock, actual.reporter)
	assert.NotNil(t, actual.registry)
	assert.NotNil(t, actual.metricTags)
}

func TestManager_Get(t *testing.T) {
	mockLogger := &mocks2.LoggingClient{}
	target := NewManager(mockLogger, time.Second*5, nil)
	name := "my-metric"

	tests := []struct {
		Name       string
		TargetType interface{}
		WrongType  interface{}
		Expected   interface{}
	}{
		{"Happy path Counter", gometrics.NewCounter(), nil, gometrics.NewCounter()},
		{"Not registered Counter", gometrics.NewCounter(), nil, nil},
		{"Wrong type Counter", gometrics.NewCounter(), gometrics.NewGauge(), nil},
		{"Happy path Gauge", gometrics.NewGauge(), nil, gometrics.NewGauge()},
		{"Not registered Gauge", gometrics.NewGauge(), nil, nil},
		{"Wrong type Gauge", gometrics.NewGauge(), gometrics.NewCounter(), nil},
		{"Happy path GaugeFloat64", gometrics.NewGaugeFloat64(), nil, gometrics.NewGaugeFloat64()},
		{"Not registered GaugeFloat64", gometrics.NewGaugeFloat64(), nil, nil},
		{"Wrong type GaugeFloat64", gometrics.NewGaugeFloat64(), gometrics.NewCounter(), nil},
		{"Happy path Timer", gometrics.NewTimer(), nil, gometrics.NewTimer()},
		{"Not registered Timer", gometrics.NewTimer(), nil, nil},
		{"Wrong type Timer", gometrics.NewTimer(), gometrics.NewGauge(), nil},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.WrongType != nil {
				// Manager currently doesn't support Get for histogram, so using it as the wrong type
				err := target.Register(name, test.WrongType, nil)
				require.NoError(t, err)
				mockLogger.On("Warnf", mock.Anything, mock.Anything)
			} else if test.Expected != nil {
				err := target.Register(name, test.Expected, nil)
				require.NoError(t, err)
			}
			defer target.Unregister(name)

			var actual interface{}

			switch test.TargetType.(type) {
			case gometrics.Counter:
				actual = target.GetCounter(name)
			case gometrics.Gauge:
				actual = target.GetGauge(name)
			case gometrics.GaugeFloat64:
				actual = target.GetGaugeFloat64(name)
			case gometrics.Timer:
				actual = target.GetTimer(name)
			default:
				require.Fail(t, "unexpected metric type")
			}

			assert.Equal(t, test.Expected, actual)
			if test.WrongType != nil {
				mockLogger.AssertExpectations(t)
			}
		})
	}
}

func TestManager_Register_Unregister(t *testing.T) {
	expectedName := "my-counter"
	expectedTags := map[string]string{"my-tag": "my-value"}
	m := NewManager(logger.NewMockClient(), time.Second*5, &mocks.MetricsReporter{})
	target := m.(*manager)

	expectedMetric := gometrics.NewCounter()
	err := target.Register(expectedName, expectedMetric, expectedTags)
	require.NoError(t, err)
	assert.Equal(t, expectedMetric, target.registry.Get(expectedName))
	assert.Equal(t, expectedTags, target.metricTags[expectedName])

	expectedTags = nil
	target.Unregister(expectedName)
	assert.Equal(t, nil, target.registry.Get(expectedName))
	assert.Equal(t, expectedTags, target.metricTags[expectedName])
}

func TestManager_Register_Error(t *testing.T) {
	target := NewManager(logger.NewMockClient(), time.Second*5, &mocks.MetricsReporter{})

	// Error for invalid metric name
	err := target.Register("  ", gometrics.NewCounter(), nil)
	assert.Error(t, err)

	// Error for invalid Tag name
	err = target.Register("my-counter", gometrics.NewCounter(), map[string]string{"  ": "value"})
	assert.Error(t, err)

	// Error for Duplicate
	err = target.Register("my-counter", gometrics.NewCounter(), nil)
	assert.NoError(t, err)
	err = target.Register("my-counter", gometrics.NewCounter(), nil)
	assert.Error(t, err)
}

func TestManager_Run(t *testing.T) {
	mockReporter := &mocks.MetricsReporter{}

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	m := NewManager(logger.NewMockClient(), time.Millisecond*1, mockReporter)
	target := m.(*manager)

	mockReporter.On("Report", target.registry, target.metricTags).Return(nil)

	target.Run(ctx, wg)
	time.Sleep(time.Millisecond * 100)

	mockReporter.AssertExpectations(t)

	runExited := false
	go func() {
		wg.Wait()
		runExited = true
	}()

	cancel()
	time.Sleep(time.Millisecond * 100)
	assert.True(t, runExited)
}

func TestManager_Run_Error(t *testing.T) {
	mockReporter := &mocks.MetricsReporter{}
	mockLogger := &mocks2.LoggingClient{}

	m := NewManager(mockLogger, time.Millisecond*1, mockReporter)
	target := m.(*manager)

	mockReporter.On("Report", target.registry, target.metricTags).Return(errors.New("failed"))
	mockLogger.On("Errorf", "failed", mock.Anything)
	mockLogger.On("Infof", mock.Anything, mock.Anything)
	target.Run(context.Background(), &sync.WaitGroup{})
	time.Sleep(time.Millisecond * 100)

	mockReporter.AssertExpectations(t)
	mockLogger.AssertExpectations(t)
}

func TestManager_ResetInterval(t *testing.T) {
	mockReporter := &mocks.MetricsReporter{}
	mockLogger := &mocks2.LoggingClient{}

	expected := time.Millisecond * 1

	m := NewManager(mockLogger, expected, mockReporter)
	target := m.(*manager)
	assert.Equal(t, expected, target.interval)

	expected = time.Millisecond * 5
	target.ResetInterval(expected)
	assert.Equal(t, expected, target.interval)
}
