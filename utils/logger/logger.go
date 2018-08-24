package logger

import (
	"log"
	"os"
	"fmt"
	"time"
	"io/ioutil"
	"strings"
)

var (
	Debug *log.Logger
	Info  *log.Logger
	Warn  *log.Logger
	Error *log.Logger
)

type Level int
const (
	EnvLogLevel = "STS_LOG_LEVEL"
)
const (
	CRITICAL Level = iota
	ERROR
	WARNING
	NOTICE
	INFO
	DEBUG
)

var levelNames = []string{
	"CRITICAL",
	"ERROR",
	"WARNING",
	"NOTICE",
	"INFO",
	"DEBUG",
}

func init() {
	//errFile, err := os.OpenFile("errors.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	//if err != nil {
	//	log.Fatalln("打开日志文件失败：", err)
	//}

	Debug = log.New(os.Stdout, "DEBUG\t| ", log.Lshortfile)
	Debug.SetOutput(new(logWriter))

	Info = log.New(os.Stdout, "INFO\t| ", log.Lshortfile)
	Info.SetOutput(new(logWriter))

	Warn = log.New(os.Stdout, "WARN\t| ", log.Lshortfile)
	Warn.SetOutput(new(logWriter))

	//Error = log.New(io.MultiWriter(os.Stderr, errFile), "ERR\t\t| ", log.Lshortfile)
	Error = log.New(os.Stderr, "Err\t\t| ", log.Lshortfile)
	Error.SetOutput(new(logWriter))

	logLevelStr := os.Getenv(EnvLogLevel)

	logLevel := ERROR
	for i, name := range levelNames {
		if strings.EqualFold(name, logLevelStr) {
			logLevel = Level(i)
		}
	}

	switch logLevel {
	case CRITICAL:
		Error.SetOutput(ioutil.Discard)
		fallthrough
	case ERROR:
		Warn.SetOutput(ioutil.Discard)
		fallthrough
	case WARNING | NOTICE:
		Info.SetOutput(ioutil.Discard)
		fallthrough
	case INFO:
		Debug.SetOutput(ioutil.Discard)
		fallthrough
	case DEBUG:
	default:

	}

}

type logWriter struct {
}

func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().Format("2006-01-02 15:04:05 ") + string(bytes))
}
