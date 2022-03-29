package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/exporter"
	"github.com/everoute/everoute/pkg/utils"
)

var (
	kafkaHosts string
)

func main() {
	flag.StringVar(&kafkaHosts, "host", "192.168.24.37:30991", "Kafka hosts")
	flag.Parse()

	stopChan := make(chan struct{})

	exp := exporter.NewExporter(exporter.NewKafkaUploader(kafkaHosts, utils.CurrentAgentName(), stopChan))
	go exp.StartExporter(nil, stopChan)

	// catch exit signal
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
	go func() {
		<-signals
		klog.Info("Wait For Cleaning Everoute Exporter")
		close(stopChan)
	}()

	<-stopChan
	time.Sleep(time.Second * 2)
}
