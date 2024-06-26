package pcrbruteforcer

import (
	"sync"
)

type registerHashCache struct {
	m sync.Map
}

func newRegisterHashCache() *registerHashCache {
	return &registerHashCache{}
}

func (c *registerHashCache) Get(reg uint64) (hash []byte) {
	if hashI, ok := c.m.Load(reg); ok {
		return hashI.([]byte)
	}
	return nil
}

func (c *registerHashCache) Set(reg uint64, hash []byte) {
	c.m.Store(reg, hash)
}
