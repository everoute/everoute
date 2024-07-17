package datapath

import (
	"os"
	"path"
	"sync"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/everoute/everoute/pkg/constants"
)

type GroupIDAllocator struct {
	lock    sync.Mutex
	iter    uint32
	offset  uint32
	release []uint32
}

func NewGroupIDAllocate(iter uint32) *GroupIDAllocator {
	if iter > constants.MaxGroupIter {
		return nil
	}
	return &GroupIDAllocator{
		iter:    iter,
		release: make([]uint32, 0),
	}
}

func (g *GroupIDAllocator) Allocate() uint32 {
	g.lock.Lock()
	defer g.lock.Unlock()

	if len(g.release) > 0 {
		gID := g.release[0]
		g.release = g.release[1:]
		return gID
	}

	if g.offset+1 < 1<<(32-constants.BitWidthGroupIter) {
		g.offset++
		return g.iter<<(32-constants.BitWidthGroupIter) + g.offset
	}

	return InvalidGroupID
}

func (g *GroupIDAllocator) Release(gID uint32) {
	g.lock.Lock()
	defer g.lock.Unlock()
	g.release = append(g.release, gID)
}

func (g *GroupIDAllocator) Max() uint32 {
	maxOffset := 1<<(32-constants.BitWidthGroupIter) - 1
	return g.iter<<(32-constants.BitWidthGroupIter) + uint32(maxOffset)
}

func (g *GroupIDAllocator) GetIter() uint32 {
	return g.iter
}

type GroupIDInfo struct {
	// key is iter, value is the end groupid
	Exists map[uint32]uint32 `yaml:"exists"`
}

func (e *GroupIDInfo) GetNextIter() uint32 {
	if e.Exists == nil {
		return 0
	}
	for i := uint32(0); i <= constants.MaxGroupIter; i++ {
		if _, ok := e.Exists[i]; !ok {
			return i
		}
	}
	return constants.MaxGroupIter + 1
}

func (e *GroupIDInfo) Clone() *GroupIDInfo {
	if e == nil {
		return nil
	}
	res := &GroupIDInfo{}
	if e.Exists == nil {
		return res
	}
	res.Exists = make(map[uint32]uint32, len(e.Exists))
	for k, v := range e.Exists {
		res.Exists[k] = v
	}
	return res
}

func GetGroupIDInfo(brName string) (*GroupIDInfo, error) {
	file := getGroupIDFile(brName)
	data, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		log.Errorf("Failed to read file %s, err: %s", file, err)
		return nil, err
	}
	existsGroupID := &GroupIDInfo{}
	if data != nil {
		err := yaml.Unmarshal(data, existsGroupID)
		if err != nil {
			log.Errorf("Failed to unmarshal ExistsGroupID, err: %s", err)
			return nil, err
		}
	}
	return existsGroupID, nil
}

func SetGroupIDInfo(brName string, gpIDs *GroupIDInfo) error {
	file := getGroupIDFile(brName)
	if gpIDs == nil {
		gpIDs = &GroupIDInfo{}
	}
	data, err := yaml.Marshal(gpIDs)
	if err != nil {
		log.Errorf("Failed to marshal ExistsGroupID %v, err: %s", gpIDs, err)
		return err
	}
	err = os.WriteFile(file, data, 0600)
	if err != nil {
		log.Errorf("Failed to write data %v to file %s, err: %s", gpIDs, file, err)
		return err
	}
	return nil
}

func getGroupIDFile(brName string) string {
	fileName := brName + constants.GroupIDFileSuffix
	return path.Join(ovsVswitchdUnixDomainSockPath, fileName)
}
