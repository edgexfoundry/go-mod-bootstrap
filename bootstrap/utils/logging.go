package utils

import (
	"fmt"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v3/di"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
	"github.com/sirupsen/logrus"
	"io"
)

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
	l := container.LoggingClientFrom(dic.Get)
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
