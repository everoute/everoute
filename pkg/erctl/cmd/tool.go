package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/everoute/everoute/pkg/erctl"
)

var (
	fileWriter *os.File
	fileOnce   sync.Once
)

func getRuleMapsFromSomewhere() (lower, original []map[string]interface{}, err error) {
	in := io.Reader(os.Stdin)
	if infile != "" {
		in, err = os.Open(infile)
		if err != nil {
			return nil, nil, err
		}
	}
	if nextInput != nil {
		in = nextInput
	}
	bytes, err := io.ReadAll(in)
	if err != nil {
		return nil, nil, err
	}
	rules := []map[string]interface{}{}
	err = json.Unmarshal(bytes, &rules)
	if err != nil {
		return nil, nil, err
	}
	small := make([]map[string]interface{}, len(rules))
	for i := 0; i < len(rules); i++ {
		small[i] = mapKeyToLower(rules[i])
	}

	return small, rules, nil
}

func mapKeyToLower(input map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range input {
		if nextv, ok := v.(map[string]interface{}); ok {
			v = mapKeyToLower(nextv)
		}
		out[strings.ToLower(k)] = v
	}
	return out
}

func setOutput() (io.Writer, error) {
	var err error
	out := io.Writer(os.Stdout)
	if nextInput != nil {
		out = nextInput
	} else if outfile != "" {
		fileOnce.Do(func() {
			fileWriter, err = os.Create(outfile)
		})
		if err != nil {
			return nil, err
		}
		out = fileWriter
	}
	return out, nil
}

func printz(out io.Writer, something interface{}) error {
	rulebytes, err := json.MarshalIndent(something, "", "\t")
	if err != nil {
		return err
	}
	n, err := fmt.Fprintln(out, string(rulebytes))
	if err != nil {
		return err
	}
	if n != len(rulebytes)+1 {
		return fmt.Errorf("print %d bytes, but len of rules is %d", n, len(rulebytes))
	}
	return nil
}

type checkFunc func(map[string]interface{}) bool

type check struct {
	checkFunc []checkFunc
}

func (c *check) check(rule map[string]interface{}) bool {
	i := 0
	for i < len(c.checkFunc) && c.checkFunc[i](rule) {
		i++
	}
	return i == len(c.checkFunc)
}

func (c *check) add(fun checkFunc) {
	c.checkFunc = append(c.checkFunc, fun)
}

func newCheck() *check {
	return &check{checkFunc: []checkFunc{}}
}

func getCheckFunc(k, v, way string) checkFunc {
	k = strings.ToLower(k)
	ks := strings.Split(k, ".")
	// special tuple （they are intervals）
	if len(ks) == 2 {
		switch ks[1] {
		case "srcipaddr":
			return checkIPFun("srcipaddr", v)
		case "dstipaddr":
			return checkIPFun("dstipaddr", v)
		case "dstport":
			return checkPortFun("dstport", v)
		case "srcport":
			return checkPortFun("srcport", v)
		}
	}

	return func(m map[string]interface{}) bool {
		var vofk interface{} = m

		for i := 0; i < len(ks)-1; i++ {
			nextvofk, ok := vofk.(map[string]interface{})
			if !ok {
				return false
			}
			vofk = nextvofk[ks[i]]
		}
		lastk := ks[len(ks)-1]
		mp, ok := vofk.(map[string]interface{})
		if !ok {
			return false
		}
		if way == "delete" {
			delete(mp, lastk)
			return true
		}
		vofk = mp[lastk]
		switch value := vofk.(type) {
		case string:
			if way == "==" {
				return value == v
			}
			return value != v
		case float64:
			float, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return false
			}
			if way == "==" {
				return value == float
			}
			return value != float
		default:
			return false
		}
	}
}

func getSetCheckFun(k string, result []map[string]interface{}) checkFunc {
	k = strings.ToLower(k)
	ks := strings.Split(k, ".")
	now := 0
	f := func(m map[string]interface{}) bool {
		getOnly := result[now] // getOnly means the only show's new map
		now++
		var vofk interface{} = m // value of key
		for i := 0; i < len(ks)-1; i++ {
			nextvofk, ok := vofk.(map[string]interface{})
			if !ok {
				return false
			}
			getOnly[ks[i]] = map[string]interface{}{}
			getOnly = getOnly[ks[i]].(map[string]interface{})
			vofk = nextvofk[ks[i]]
		}
		mp, ok := vofk.(map[string]interface{})
		if !ok {
			return false
		}
		lastk := ks[len(ks)-1]
		getOnly[lastk] = mp[lastk]
		return true
	}
	return f
}

func checkIPFun(k, v string) checkFunc {
	return func(m map[string]interface{}) bool {
		if errule, ok := m["everoutepolicyrule"]; ok {
			if ruleip, ok := errule.(map[string]interface{})[k]; ok {
				ipnet := erctl.GetIPNet(ruleip.(string))
				// zero ip net contains all ips
				if ipnet == nil {
					return true
				}
				return ipnet.Contains(net.ParseIP(v))
			}
		}
		return true
	}
}

func checkPortFun(k, v string) checkFunc {
	intv, err := strconv.Atoi(v)
	if err != nil {
		return func(_ map[string]interface{}) bool {
			return false
		}
	}
	return func(m map[string]interface{}) bool {
		if errule, ok := m["everoutepolicyrule"]; ok {
			var port interface{}
			if port, ok = errule.(map[string]interface{})[k]; !ok {
				return true
			}
			var portMast interface{}
			if portMast, ok = errule.(map[string]interface{})[k+"mask"]; !ok {
				return int(port.(float64)) == intv
			}
			return int(portMast.(float64))&int(port.(float64)) == int(portMast.(float64))&intv
		}
		return true
	}
}
