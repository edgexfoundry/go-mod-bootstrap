/*******************************************************************************
 * Copyright 2019 Dell Inc.
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

package container

import (
	"fmt"
	"io"

	"github.com/sirupsen/logrus"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/di"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
)

// LoggingClientInterfaceName contains the name of the logger.LoggingClient implementation in the DIC.
var LoggingClientInterfaceName = di.TypeInstanceToName((*logger.LoggingClient)(nil))

// LoggingClientFrom helper function queries the DIC and returns the logger.loggingClient implementation.
func LoggingClientFrom(get di.Get) logger.LoggingClient {
	loggingClient, ok := get(LoggingClientInterfaceName).(logger.LoggingClient)
	if !ok {
		return nil
	}

	return loggingClient
}

type LogrusAdaptor struct {
	lc logger.LoggingClient
}

func (f *LogrusAdaptor) Format(entry *logrus.Entry) ([]byte, error) {
	// Implement your custom formatting logic here
	return []byte(fmt.Sprintf("[%s] %s\n", entry.Level, entry.Message)), nil
}

func (f *LogrusAdaptor) Levels() []logrus.Level {
	return logrus.AllLevels
}

const OPENZITI_LOG_FORMAT = "openziti: %s"
const OPENZITI_DEFAULT_LOG_FORMAT = "default openziti: %s"

func (f *LogrusAdaptor) Fire(e *logrus.Entry) error {
	switch e.Level {
	case logrus.DebugLevel:
		f.lc.Debugf(OPENZITI_LOG_FORMAT, e.Message)
	case logrus.InfoLevel:
		f.lc.Infof(OPENZITI_LOG_FORMAT, e.Message)
	case logrus.WarnLevel:
		f.lc.Warnf(OPENZITI_LOG_FORMAT, e.Message)
	case logrus.ErrorLevel:
		f.lc.Errorf(OPENZITI_LOG_FORMAT, e.Message)
	case logrus.FatalLevel:
		f.lc.Errorf(OPENZITI_LOG_FORMAT, e.Message)
	case logrus.PanicLevel:
		f.lc.Errorf(OPENZITI_LOG_FORMAT, e.Message)
	default:
		f.lc.Errorf(OPENZITI_DEFAULT_LOG_FORMAT, e.Message)
	}

	return nil
}

func AdaptLogrusBasedLogging(dic *di.Container) {
	l := LoggingClientFrom(dic.Get)
	// Create a new logger instance
	hook := &LogrusAdaptor{
		lc: l,
	}
	logrus.AddHook(hook)
	logrus.SetFormatter(&logrus.TextFormatter{
		DisableColors: true,
	})
	logrus.SetOutput(io.Discard)
}
