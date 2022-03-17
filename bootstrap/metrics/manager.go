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
	"sync"
	"time"

	gometrics "github.com/rcrowley/go-metrics"

	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/dtos"
)

type manager struct {
	lc         logger.LoggingClient
	metricTags map[string]map[string]string
	registry   gometrics.Registry
	reporter   interfaces.MetricsReporter
	interval   time.Duration
}

// NewManager creates a new metrics manager
func NewManager(lc logger.LoggingClient, interval time.Duration, reporter interfaces.MetricsReporter) interfaces.MetricsManager {
	m := &manager{
		lc:         lc,
		registry:   gometrics.DefaultRegistry,
		reporter:   reporter,
		interval:   interval,
		metricTags: make(map[string]map[string]string),
	}

	return m
}

// Register registers a go-metric metric item which must be one of the
func (m *manager) Register(name string, item interface{}, tags map[string]string) error {
	if err := dtos.ValidateMetricName(name, "metric"); err != nil {
		return err
	}

	if len(tags) > 0 {
		if err := m.setMetricTags(name, tags); err != nil {
			return err
		}
	}

	if err := m.registry.Register(name, item); err != nil {
		return err
	}

	return nil
}

// Unregister unregisters a metric item
func (m *manager) Unregister(name string) {
	m.registry.Unregister(name)
	m.metricTags[name] = nil
	return
}

// Run periodically (based on configured interval) reports the collected metrics using the configured MetricsReporter.
func (m *manager) Run(ctx context.Context, wg *sync.WaitGroup) {
	ticker := time.Tick(m.interval)

	wg.Add(1)
	defer wg.Done()

	go func() {
		for {
			select {
			case <-ctx.Done():
				m.lc.Info("Exited Metrics Manager Run...")
				return

			case <-ticker:
				if err := m.reporter.Report(m.registry, m.metricTags); err != nil {
					m.lc.Errorf(err.Error())
					continue
				}

				m.lc.Debug("Reported metrics...")
			}
		}
	}()
}

// GetCounter retrieves the specified registered Counter
// Returns nil if named item not registered or not a Counter
func (m *manager) GetCounter(name string) gometrics.Counter {
	metric := m.registry.Get(name)
	if metric == nil {
		return nil
	}

	counter, ok := metric.(gometrics.Counter)
	if !ok {
		m.lc.Warnf("Unable to get Counter metric by name '%s': Registered metric by that name is not a Counter", name)
		return nil
	}

	return counter
}

// GetGauge retrieves the specified registered Gauge
// Returns nil if named item not registered or not a Gauge
func (m *manager) GetGauge(name string) gometrics.Gauge {
	metric := m.registry.Get(name)
	if metric == nil {
		return nil
	}

	gauge, ok := metric.(gometrics.Gauge)
	if !ok {
		m.lc.Warnf("Unable to get Gauge metric by name '%s': Registered metric by that name is not a Gauge", name)
		return nil
	}

	return gauge
}

// GetGaugeFloat64 retrieves the specified registered GaugeFloat64
// Returns nil if named item not registered or not a GaugeFloat64
func (m *manager) GetGaugeFloat64(name string) gometrics.GaugeFloat64 {
	metric := m.registry.Get(name)
	if metric == nil {
		return nil
	}

	gaugeFloat64, ok := metric.(gometrics.GaugeFloat64)
	if !ok {
		m.lc.Warnf("Unable to get GaugeFloat64 metric by name '%s': Registered metric by that name is not a GaugeFloat64", name)
		return nil
	}

	return gaugeFloat64
}

// GetTimer retrieves the specified registered Timer
// Returns nil if named item not registered or not a Timer
func (m *manager) GetTimer(name string) gometrics.Timer {
	metric := m.registry.Get(name)
	if metric == nil {
		return nil
	}

	timer, ok := metric.(gometrics.Timer)
	if !ok {
		m.lc.Warnf("Unable to get Timer metric by name '%s': Registered metric by that name is not a Timer", name)
		return nil
	}

	return timer
}

func (m *manager) setMetricTags(metricName string, tags map[string]string) error {
	for tagName := range tags {
		if err := dtos.ValidateMetricName(tagName, "Tag"); err != nil {
			return err
		}
	}

	m.metricTags[metricName] = tags
	return nil
}
