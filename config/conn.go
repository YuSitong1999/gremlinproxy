// Package config 实际上是配置的结果 Some constants and globally accessible vars that remain constants once configured
package config

import (
	log "github.com/sirupsen/logrus"
	"os"
)

const OK = "OK"

//const ERROR = "ERROR"
const NAME = "gremlinproxy"

var TrackingHeader string
var ProxyFor string

// GlobalLogger 全局日志:输出到本地stderr的日志,其实应该叫本地日志
var GlobalLogger = &log.Logger{
	Out:       os.Stderr,
	Formatter: new(log.TextFormatter),
	Hooks:     make(log.LevelHooks),
	Level:     log.WarnLevel,
}

// ProxyLogger 发送到logstash的日志
var ProxyLogger = &log.Logger{
	Out:       os.Stderr,
	Formatter: new(log.JSONFormatter),
	Hooks:     make(log.LevelHooks),
	Level:     log.InfoLevel,
}
