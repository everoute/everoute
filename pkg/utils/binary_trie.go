package utils

import "sync"

type BinaryTrieNode[V any] struct {
	Value     V
	ZeroChild *BinaryTrieNode[V]
	OneChild  *BinaryTrieNode[V]
}

type BinaryTrieNodeAllocator[V any] interface {
	Allocate() *BinaryTrieNode[V]
	Deallocate(*BinaryTrieNode[V])
}

func NewSyncPoolBinaryTrieNodeAllocator[V any]() BinaryTrieNodeAllocator[V] {
	return (*binaryTrieNodeAllocator[V])(&sync.Pool{
		New: func() any {
			return &BinaryTrieNode[V]{}
		},
	})
}

type binaryTrieNodeAllocator[V any] sync.Pool

func (p *binaryTrieNodeAllocator[V]) Allocate() *BinaryTrieNode[V] {
	return (*sync.Pool)(p).Get().(*BinaryTrieNode[V])
}

func (p *binaryTrieNodeAllocator[V]) Deallocate(node *BinaryTrieNode[V]) {
	(*sync.Pool)(p).Put(node)
}

type noopBinaryTrieNodeAllocator[V any] struct{}

func (a noopBinaryTrieNodeAllocator[V]) Allocate() *BinaryTrieNode[V] {
	return &BinaryTrieNode[V]{}
}

func (a noopBinaryTrieNodeAllocator[V]) Deallocate(_ *BinaryTrieNode[V]) {
	// do nothing
}

func NoopBinaryTrieNodeAllocator[V any]() BinaryTrieNodeAllocator[V] {
	return noopBinaryTrieNodeAllocator[V]{}
}

const defaultSlabChunkSize = 8192

// SlabBinaryTrieNodeAllocator allocates nodes from chunks to reduce malloc count.
// Each chunk allocates once for many nodes. Use when building large tries.
// The allocator (or its chunks) must outlive the trie; store it in the trie owner.
func NewSlabBinaryTrieNodeAllocator[V any](chunkSize int) BinaryTrieNodeAllocator[V] {
	if chunkSize <= 0 {
		chunkSize = defaultSlabChunkSize
	}
	return &SlabBinaryTrieNodeAllocator[V]{chunkSize: chunkSize}
}

type SlabBinaryTrieNodeAllocator[V any] struct {
	chunks    [][]BinaryTrieNode[V]
	chunkSize int
	curChunk  int
	curIndex  int
}

func (s *SlabBinaryTrieNodeAllocator[V]) Allocate() *BinaryTrieNode[V] {
	if s.curChunk >= len(s.chunks) || s.curIndex >= len(s.chunks[s.curChunk]) {
		s.chunks = append(s.chunks, make([]BinaryTrieNode[V], s.chunkSize))
		s.curChunk = len(s.chunks) - 1
		s.curIndex = 0
	}
	n := &s.chunks[s.curChunk][s.curIndex]
	s.curIndex++
	return n
}

func (s *SlabBinaryTrieNodeAllocator[V]) Deallocate(*BinaryTrieNode[V]) {
	// Slab does not reclaim individual nodes; chunks are GC'd with the allocator
}

func FreeBinaryTrie[V any](node *BinaryTrieNode[V], allocator BinaryTrieNodeAllocator[V]) {
	nodes := []*BinaryTrieNode[V]{node}
	for len(nodes) > 0 {
		node := nodes[len(nodes)-1]
		nodes = nodes[:len(nodes)-1]
		if node.ZeroChild != nil {
			nodes = append(nodes, node.ZeroChild)
		}
		if node.OneChild != nil {
			nodes = append(nodes, node.OneChild)
		}
		if allocator != nil {
			allocator.Deallocate(node)
		}
	}
}

func FreeBinaryTrieNoAlloc[V any](node *BinaryTrieNode[V], allocator BinaryTrieNodeAllocator[V]) {
	if node.ZeroChild != nil {
		FreeBinaryTrieNoAlloc(node.ZeroChild, allocator)
	}
	if node.OneChild != nil {
		FreeBinaryTrieNoAlloc(node.OneChild, allocator)
	}
	if allocator != nil {
		allocator.Deallocate(node)
	}
}

func TraverseBinaryTrie[V any](node *BinaryTrieNode[V], visit func(node *BinaryTrieNode[V])) {
	if node.ZeroChild != nil {
		TraverseBinaryTrie(node.ZeroChild, visit)
	}
	if node.OneChild != nil {
		TraverseBinaryTrie(node.OneChild, visit)
	}
	visit(node)
}

func GetBinaryTrieNode[V any](
	node *BinaryTrieNode[V],
	key []byte,
	bits int,
	allocator BinaryTrieNodeAllocator[V],
) *BinaryTrieNode[V] {
	for i := 0; i < bits; i++ {
		bit := (key[i/8] >> (7 - i%8)) & 1
		if bit == 0 {
			if node.ZeroChild == nil {
				if allocator != nil {
					node.ZeroChild = allocator.Allocate()
				} else {
					return nil
				}
			}
			node = node.ZeroChild
		} else {
			if node.OneChild == nil {
				if allocator != nil {
					node.OneChild = allocator.Allocate()
				} else {
					return nil
				}
			}
			node = node.OneChild
		}
	}
	return node
}

func VisitBinaryTriePrefixes[V any](node *BinaryTrieNode[V], prefix []byte, bits int, visit func(node *BinaryTrieNode[V]) (exit bool)) {
	// visit {bits+1} times, including the root node
	for i := 0; i < bits; i++ {
		if exit := visit(node); exit {
			return
		}
		bit := (prefix[i/8] >> (7 - i%8)) & 1
		if bit == 0 {
			if node.ZeroChild == nil {
				return
			}
			node = node.ZeroChild
		} else {
			if node.OneChild == nil {
				return
			}
			node = node.OneChild
		}
	}
	// visit the last node
	visit(node)
}
