/*
Copyright 2021 The Everoute Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package command

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/everoute/everoute/tests/e2e/framework"
	"github.com/everoute/everoute/tests/e2e/framework/model"
)

func NewReachCommand(f *framework.Framework) *cobra.Command {
	var port, timeout, maxGoroutines int
	var watch, color bool
	var protocol = "TCP"

	ac := &cobra.Command{
		Use:   "reach [protocol] [options]",
		Short: "Reach test between endpoints",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				protocol = strings.ToUpper(args[0])
			}
			klog.InitFlags(flag.CommandLine)
			flag.Parse()
			flag.Set("logtostderr", "false")
			klog.SetOutput(ioutil.Discard)
			return runReach(f, protocol, port, &reachOptions{timeout, maxGoroutines, watch, color})
		},
	}

	var flagSet = ac.PersistentFlags()

	flagSet.IntVarP(&port, "port", "p", 0, "destination port, only allow when protocol is TCP or UDP")
	flagSet.IntVarP(&timeout, "timeout", "t", 0, "timeout seconds, the default 0 is no timeout")
	flagSet.BoolVarP(&color, "color", "c", false, "if print truth table with color")
	flagSet.BoolVarP(&watch, "watch", "w", false, "watch reachable truth table changes")
	flagSet.IntVarP(&maxGoroutines, "max-goroutines", "g", 10, "limit ssh session goroutine numbers")

	return ac
}

type reachOptions struct {
	timeout       int
	maxGoroutines int
	watch         bool
	color         bool
}

// runReach will check reachable between endpoint, and dynamic display
func runReach(f *framework.Framework, protocol string, port int, options *reachOptions) error {
	if protocol != "TCP" && protocol != "UDP" && protocol != "ICMP" && protocol != "FTP" {
		return fmt.Errorf("unsupport protocol %s", protocol)
	}

	var wg = &sync.WaitGroup{}
	var limitChan = make(chan struct{}, options.maxGoroutines)

	var printQueue = workqueue.New()
	defer printQueue.ShutDown()

	var epList, err = listEndpoint(f)
	if err != nil {
		return err
	}
	var truthTable = model.NewTruthTableFromItems(epList, nil)

	for _, dstEp := range epList {
		for _, srcEp := range epList {
			wg.Add(1)

			go func(srcEp, dstEp string) {
				defer wg.Done()

				for run := true; run; run = options.watch {
					limitChan <- struct{}{}

					reachable, err := f.EndpointManager().Reachable(context.TODO(), srcEp, dstEp, protocol, port)
					if err == nil {
						truthTable.Set(srcEp, dstEp, reachable)
						printQueue.Add("reach")
					}

					<-limitChan
					time.Sleep(100 * time.Millisecond)
				}

			}(srcEp, dstEp)
		}
	}

	fmt.Print("\033[?25l")       // hidden mouse
	defer fmt.Print("\033[?25h") // show mouse

	setTerminalEcho(os.Stdin.Fd(), true)        // lock echo
	defer setTerminalEcho(os.Stdin.Fd(), false) // unlock echo

	go func() {
		var backToTop = ""

		for printFromQueue(printQueue, truthTable, backToTop, options.color) {
			backToTop = fmt.Sprintf("\033[%dA\r", len(epList)+1)
		}
	}()

	select {
	case <-waitForEnter(os.Stdin):
	case <-waitGroupChan(wg):
	case <-time.Tick(time.Duration(options.timeout) * time.Second):
	}

	return nil
}

func waitForEnter(reader io.Reader) <-chan struct{} {
	var buf [1]byte
	var waitChan = make(chan struct{})

	go func() {
		reader.Read(buf[:]) // read for enter
		waitChan <- struct{}{}
	}()

	return waitChan
}

func printFromQueue(q workqueue.Interface, table *model.TruthTable, prefix string, color bool) bool {
	item, down := q.Get()
	if down {
		return false
	}
	defer q.Done(item)

	fmt.Println(prefix, table.PrettyPrint(color))
	return true
}

func waitGroupChan(wg *sync.WaitGroup) <-chan struct{} {
	var waitChan = make(chan struct{})
	go func() { wg.Wait(); waitChan <- struct{}{} }()
	return waitChan
}

func setTerminalEcho(fd uintptr, lock bool) {
	termios, _ := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	newState := *termios

	if lock {
		newState.Lflag &^= unix.ECHO
	} else {
		newState.Lflag += unix.ECHO
	}

	unix.IoctlSetTermios(int(fd), unix.TCSETS, &newState)
}

func listEndpoint(f *framework.Framework) ([]string, error) {
	epList, err := f.EndpointManager().List(context.TODO())
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(epList))
	for _, ep := range epList {
		names = append(names, ep.Name)
	}

	return names, nil
}
