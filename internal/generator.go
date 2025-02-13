package nsec3walker

import (
	"runtime"
)

const (
	charset       = "abcdefghijklmnopqrstuvwxyz0123456789"
	cntChanDomain = 2_000
)

type DomainGenerator struct {
	chanDomain  chan *Domain
	ranges      *RangeIndex
	out         *Output
	nsec3Domain string
	nsec3Salt   string
	nsec3Iter   uint16
	counter     []int8
	chars       []rune
	len         int8
}

type Domain struct {
	Domain string
	Hash   string
}

func NewDomainGenerator(
	nsec3Domain string,
	nsec3Salt string,
	nsec3Iter uint16,
	ranges *RangeIndex,
	output *Output,
) *DomainGenerator {
	return &DomainGenerator{
		chanDomain:  make(chan *Domain, cntChanDomain),
		ranges:      ranges,
		out:         output,
		nsec3Domain: nsec3Domain,
		nsec3Salt:   nsec3Salt,
		nsec3Iter:   nsec3Iter,
		counter:     []int8{0, 0, 0, 0}, // "aaaa"
		chars:       []rune(charset),
		len:         int8(len(charset)),
	}
}

func (dg *DomainGenerator) Run(chanOut chan *Domain) {
	go dg.generateDomains()

	for i := 0; i < runtime.NumCPU(); i++ {
		go dg.hashWorker(chanOut)
	}
}

func (dg *DomainGenerator) hashWorker(chanOut chan *Domain) {
	var err error

	for domain := range dg.chanDomain {
		domain.Hash, err = CalculateNSEC3(domain.Domain, dg.nsec3Salt, dg.nsec3Iter)

		if err != nil {
			dg.out.Log("Error calculating NSEC3 hash for domain " + domain.Domain + ": " + err.Error())

			continue
		}

		inRange, _ := dg.ranges.isHashInRange(domain.Hash)

		if !inRange {
			chanOut <- &Domain{Domain: domain.Domain, Hash: domain.Hash}
		}
	}
}

func (dg *DomainGenerator) generateDomains() {
	suffix := "." + dg.nsec3Domain

	for {
		dg.chanDomain <- &Domain{Domain: dg.toString() + suffix}
		dg.next()
	}
}

func (dg *DomainGenerator) increment(index int8) (flipped bool) {
	dg.counter[index]++

	if dg.counter[index] >= dg.len {
		dg.counter[index] = 0
		flipped = true
	}

	return
}

func (dg *DomainGenerator) next() {
	flipped := true
	var index int8 = 0

	for index < dg.positions() {
		flipped = dg.increment(index)

		if !flipped {
			return
		}

		index++
	}

	dg.counter = make([]int8, dg.positions()+1)
}

func (dg *DomainGenerator) positions() int8 {
	return int8(len(dg.counter))
}

func (dg *DomainGenerator) toString() string {
	result := make([]rune, len(dg.counter))

	for i, idx := range dg.counter {
		result[i] = dg.chars[idx]
	}

	return string(result)
}
