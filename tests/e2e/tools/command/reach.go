/*
Copyright 2021 The Lynx Authors.

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
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"k8s.io/client-go/util/workqueue"

	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/tests/e2e/framework"
)

func NewReachCommand(f *framework.Framework) *cobra.Command {
	var port, timeout, maxGoroutines int
	var watch, color bool
	var procotol = "TCP"

	ac := &cobra.Command{
		Use:   "reach [protocol] [options]",
		Short: "Reach test between vms or groups",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				procotol = strings.ToUpper(args[0])
			}
			return runReach(f, procotol, port, &reachOptions{timeout, maxGoroutines, watch, color})
		},
	}

	var flagSet = ac.PersistentFlags()

	flagSet.IntVarP(&port, "port", "p", 0, "destination port, only allow when protocol is TCP or UDP")
	flagSet.IntVarP(&timeout, "timeout", "t", 0, "timeout seconds, the default 0 is no timeout")
	flagSet.BoolVarP(&color, "color", "c", false, "if print truth table with color")
	flagSet.BoolVarP(&watch, "watch", "w", false, "watch reachable truth table changes")
	flagSet.IntVarP(&maxGoroutines, "max-goroutines", "g", 200, "limit ssh connection goroutine numbers")

	return ac
}

type reachOptions struct {
	timeout       int
	maxGoroutines int
	watch         bool
	color         bool
}

func runReach(f *framework.Framework, procotol string, port int, options *reachOptions) error {
	if procotol != "TCP" && procotol != "UDP" && procotol != "ICMP" {
		return fmt.Errorf("unsupport protocol %s", procotol)
	}

	var wg = &sync.WaitGroup{}
	var limitChan = make(chan struct{}, options.maxGoroutines)

	var printQueue = workqueue.New()
	defer printQueue.ShutDown()

	var cache, err = newVMCache(f)
	if err != nil {
		return err
	}
	var truthTable = NewTruthTable(cache.getNames(), cache.getNames(), nil)

	for _, dstVMName := range cache.getNames() {
		for _, srcVMName := range cache.getNames() {
			wg.Add(1)

			go func(srcVMName, dstVMName string) {
				defer wg.Done()

				for run := true; run; run = options.watch {
					var srcVM, dstVM = cache.get(srcVMName), cache.get(dstVMName)
					limitChan <- struct{}{}

					reachable, err := f.ReachableWithPort(srcVM, dstVM, procotol, port)
					if err == nil {
						truthTable.Set(srcVM.Name, dstVM.Name, reachable)
						printQueue.Add("reach")
					}

					<-limitChan
					time.Sleep(100 * time.Millisecond)
				}

			}(srcVMName, dstVMName)
		}
	}

	fmt.Print("\033[?25l")       // hidden mouse
	defer fmt.Print("\033[?25h") // show mouse

	setTerminalEcho(os.Stdin.Fd(), true)        // lock echo
	defer setTerminalEcho(os.Stdin.Fd(), false) // unlock echo

	go func() {
		var backToTop = ""

		for printFromQueue(printQueue, truthTable, backToTop, options.color) {
			backToTop = fmt.Sprintf("\033[%dA\r", truthTable.PrintLength())
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

func printFromQueue(q workqueue.Interface, table *TruthTable, prefix string, color bool) bool {
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

type vmCache struct {
	names []string

	lock sync.RWMutex
	vms  map[string]*framework.VM
}

func newVMCache(f *framework.Framework) (*vmCache, error) {
	var cache = &vmCache{vms: make(map[string]*framework.VM)}

	err := cache.refresh(f)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			_ = cache.refresh(f)
		}
	}()

	return cache, nil
}

func (m *vmCache) get(name string) *framework.VM {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return m.vms[name]
}

func (m *vmCache) refresh(f *framework.Framework) error {
	var epList securityv1alpha1.EndpointList

	err := f.GetClient().List(context.TODO(), &epList)
	if err != nil {
		return err
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	m.names = nil

	for _, ep := range epList.Items {
		m.vms[ep.Name] = toVM(ep)
		m.names = append(m.names, ep.Name)
	}

	return nil
}

func (m *vmCache) getNames() []string {
	m.lock.RLock()
	defer m.lock.RUnlock()

	names := make([]string, len(m.names))
	copy(names, m.names)

	return names
}

func toVM(ep securityv1alpha1.Endpoint) *framework.VM {
	vm := &framework.VM{
		Name:   ep.Name,
		Labels: mapJoin(ep.Labels, "=", ","),
	}

	if len(ep.Status.IPs) == 0 {
		framework.SetVM(vm, ep.Annotations["Agent"], ep.Annotations["Netns"], "")
	} else {
		framework.SetVM(vm, ep.Annotations["Agent"], ep.Annotations["Netns"], ep.Status.IPs[0].String())
	}

	vm.UDPPort, _ = strconv.Atoi(ep.Annotations["UDPPort"])
	vm.TCPPort, _ = strconv.Atoi(ep.Annotations["TCPPort"])

	return vm
}
