package nsec3walker

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	rbt "github.com/emirpasic/gods/trees/redblacktree"
)

type HashTree struct {
	tree  *rbt.Tree
	mutex sync.RWMutex
}

type RangeIndex struct {
	index              *HashTree
	cntEndWithoutStart atomic.Int64
	ignoreChanges      bool
	addMutex           sync.Mutex
}

func NewHashTree() (hashTree *HashTree) {
	hashTree = &HashTree{
		tree: rbt.NewWithStringComparator(),
	}
	return
}

func NewRangeIndex() (rangeIndex *RangeIndex) {
	rangeIndex = &RangeIndex{
		index: NewHashTree(),
	}
	return
}

func (ht *HashTree) Add(key, val string) {
	ht.mutex.Lock()
	defer ht.mutex.Unlock()
	ht.tree.Put(key, val)
}

func (ht *HashTree) Get(key string) (value string, exists bool) {
	ht.mutex.RLock()
	defer ht.mutex.RUnlock()
	valInterface, exists := ht.tree.Get(key)
	if exists {
		value = valInterface.(string)
	}
	return
}

func (ht *HashTree) GetLastRange() (key, val string) {
	ht.mutex.RLock()
	defer ht.mutex.RUnlock()
	lastNode := ht.tree.Right()
	if lastNode != nil {
		return lastNode.Key.(string), lastNode.Value.(string)
	}
	return
}

func (ht *HashTree) PrintAll() {
	ht.mutex.RLock()
	defer ht.mutex.RUnlock()
	iterator := ht.tree.Iterator()
	for iterator.Next() {
		log.Printf("Range %s => %s", iterator.Key().(string), iterator.Value().(string))
	}
}

func (ht *HashTree) allRangesComplete() bool {
	ht.mutex.RLock()
	defer ht.mutex.RUnlock()
	iterator := ht.tree.Iterator()
	firstHash := ""
	lastEndHash := ""
	for iterator.Next() {
		startHash := iterator.Key().(string)
		endHash := iterator.Value().(string)
		if firstHash == "" {
			firstHash = startHash
		} else if startHash != lastEndHash {
			return false
		}
		if endHash == "" {
			return false
		}
		lastEndHash = endHash
	}
	// if we get here all ranges have an end
	// we just need to check the last range wraps around (which it will unless the last hash is zzzzzzzzzzzzz)
	return lastEndHash == firstHash
}

// returns range that starts with the largest key that is less than the input hash
func (ht *HashTree) ClosestBefore(input string) (startHash string, endHash string, found bool) {
	// TODO: Why cant we use range and built in iterator?
	ht.mutex.RLock()
	defer ht.mutex.RUnlock()
	iterator := ht.tree.Iterator()
	for iterator.Next() {
		if iterator.Key().(string) >= input {
			break
		}
	}
	if iterator.Prev() {
		startHash = iterator.Key().(string)
		endHash = iterator.Value().(string)
		found = true
	}
	return
}

func (ri *RangeIndex) PrintAll() {
	ri.index.PrintAll()
}

func (ri *RangeIndex) Add(hashStart string, hashEnd string) (existsStart bool, existsEnd bool, err error) {
	/**
	If hashStart key already exists, check the value didn't change (hashEnd)
	If hashEnd does not exists, add it with empty value
	*/
	ri.addMutex.Lock() // this mutex is for ensuring correct values of cntChains and cntEndWithoutStart
	existingStartValAsStart, existsStart := ri.index.Get(hashStart)
	_, existsEnd = ri.index.Get(hashEnd)

	// !existsStart = adding full chain from start to end
	// !existsEnd adding end of chan as start with empty end

	// existsAndDifferentEnd = start exists and end is different
	existsAndDifferentEnd := existsStart && existingStartValAsStart != "" && existingStartValAsStart != hashEnd
	if existsAndDifferentEnd {
		msg := "range starting %s already exists with different hashEnd! Existing: %s | New: %s"
		err = fmt.Errorf(msg, hashStart, existingStartValAsStart, hashEnd)

		if !ri.ignoreChanges {
			ri.addMutex.Unlock()

			return
		}
	}

	// existsStartWithEmptyEnd = start exists and end is empty, from being End before
	existsStartWithEmptyEnd := existsStart && existingStartValAsStart == ""
	setFull := !existsStart || existsStartWithEmptyEnd

	if existsStartWithEmptyEnd {
		ri.cntEndWithoutStart.Add(-1)
	}

	if setFull {
		ri.index.Add(hashStart, hashEnd)
	}

	if !existsEnd {
		ri.cntEndWithoutStart.Add(1)
		ri.index.Add(hashEnd, "")
	}

	ri.addMutex.Unlock()

	return
}

// isHashInRange determines whether a given hash falls within any of the stored hash ranges.
func (ri *RangeIndex) isHashInRange(hash string) (inRange bool, exactRange string) {
	// first check edge case of hash being between last and first hash
	lastHash, lastVal := ri.index.GetLastRange()
	if lastVal != "" && lastVal < lastHash && (hash < lastVal || hash > lastHash) {
		exactRange = lastHash + "=" + lastVal

		return true, exactRange
	}

	closestStart, closestEnd, hasClosest := ri.index.ClosestBefore(hash)
	if hasClosest {
		if hash <= closestEnd {
			exactRange = closestStart + "=" + closestEnd

			return true, exactRange
		}
	}

	return
}

func (ri *RangeIndex) isFinished() (isFinished bool) {
	if ri.cntEndWithoutStart.Load() == 0 {
		if ri.index.allRangesComplete() {
			isFinished = true
		}
	}

	return
}
