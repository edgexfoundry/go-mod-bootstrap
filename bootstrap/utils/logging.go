package utils

import (
	"fmt"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
	"github.com/sirupsen/logrus"
)

type LogrusAdaptor struct {
	Logger logger.LoggingClient
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
		f.Logger.Debugf(OPENZITI_LOG_FORMAT, e.Message)
	case logrus.InfoLevel:
		f.Logger.Infof(OPENZITI_LOG_FORMAT, e.Message)
	case logrus.WarnLevel:
		f.Logger.Warnf(OPENZITI_LOG_FORMAT, e.Message)
	case logrus.ErrorLevel:
		f.Logger.Errorf(OPENZITI_LOG_FORMAT, e.Message)
	case logrus.FatalLevel:
		f.Logger.Errorf(OPENZITI_LOG_FORMAT, e.Message)
	case logrus.PanicLevel:
		f.Logger.Errorf(OPENZITI_LOG_FORMAT, e.Message)
	default:
		f.Logger.Errorf(OPENZITI_DEFAULT_LOG_FORMAT, e.Message)
	}

	return nil
}
