package nsec3walker

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	WaitMs         = 100
	sizeChanDomain = 500
)

type NSec3Walker struct {
	config Config
	stats  *Stats
	ranges *RangeIndex
	out    *Output
	nsec   Nsec3Params

	chanDomain      chan *Domain
	chanHashesFound chan Nsec3Record
	chanHashesNew   chan string
}

type Nsec3Params struct {
	domain     string
	salt       string
	iterations uint16
}

type Nsec3Record struct {
	Start string
	End   string
	Types []uint16
}

func NewNSec3Walker(config Config, output *Output) (nsecWalker *NSec3Walker) {
	stats := NewStats(output)

	nsecWalker = &NSec3Walker{
		config:          config,
		chanHashesFound: make(chan Nsec3Record, 1000),
		ranges:          NewRangeIndex(),
		out:             output,
		stats:           stats,
	}

	nsecWalker.nsec.domain = config.Domain

	return
}

func (nw *NSec3Walker) RunDebug(domain string) (err error) {
	nw.out.Log("Showing debug data for domain: " + domain)
	nw.out.Log(fmt.Sprintf("NS servers to walk: %v", nw.config.DomainDnsServers))

	for _, ns := range nw.config.DomainDnsServers {
		r, err := getNsResponse(domain, ns)

		fmt.Printf("querying %s via %s\n===Err===\n%v\n\n===Response===\n%s\n\n\n", domain, ns, err, r)

		if err != nil {
			continue
		}

		for _, rr := range r.Ns {
			if nsec3, ok := rr.(*dns.NSEC3); ok {

				first := strings.Split(nsec3.Header().Name, ".")[0]
				fmt.Println(first + ";" + strings.ToLower(nsec3.NextDomain))
			}
		}
	}

	return
}

func (nw *NSec3Walker) Run() (err error) {
	nw.out.Log("Starting NSEC3 walker for domain [" + nw.nsec.domain + "]")
	nw.out.Log(fmt.Sprintf("NS servers to walk: %v", nw.config.DomainDnsServers))

	err = nw.initNsec3Values()

	if err != nil {
		return
	}

	nw.chanDomain = make(chan *Domain, sizeChanDomain)
	dg := NewDomainGenerator(nw.nsec.domain, nw.nsec.salt, nw.nsec.iterations, nw.ranges, nw.out)
	dg.Run(nw.chanDomain)

	for _, ns := range nw.config.DomainDnsServers {
		go nw.workerForAuthNs(ns)
	}

	go nw.stats.logCounterChanges(time.Second*time.Duration(nw.config.LogCounterIntervalSec), nw.config.QuitAfterMin)

	err = nw.processHashes()

	return
}

func (nw *NSec3Walker) processHashes() (err error) {
	var startExists, endExists bool

	for hash := range nw.chanHashesFound {
		startExists, endExists, err = nw.ranges.Add(hash.Start, hash.End)

		if err != nil {
			if nw.config.StopOnChange {
				return // The error message will be printed by the caller
			}

			// If the zone changes, and we don't quit, we can't determine if the chain is complete,
			// so will need to rely on the timeout
			nw.out.Log(err.Error())
		}

		nw.stats.gotHash(startExists, endExists)

		if !startExists {
			nw.out.Hash(hash.Start, nw.nsec)
			nw.out.Map(hash, nw.nsec.salt, nw.nsec.iterations)
		}

		if !endExists {
			nw.out.Hash(hash.End, nw.nsec)
		}

		if nw.ranges.isFinished() {
			// TODO this will be removed, see .map file
			if nw.config.Verbose {
				nw.ranges.PrintAll()
			}

			nw.out.Log(fmt.Sprintf("Finished with %d hashes", nw.stats.hashes.Load()))

			return
		}
	}

	return
}

func (nw *NSec3Walker) initNsec3Values() (err error) {
	// TODO user NSEC3PARAM
	for _, ns := range nw.config.DomainDnsServers {
		randomDomain := fmt.Sprintf("%d-%d.%s", time.Now().UnixMilli(), rand.Uint32(), nw.nsec.domain)
		err = nw.extractNSEC3Hashes(randomDomain, ns)

		if err == nil {
			return
		}

		nw.out.Log(err.Error())
	}

	return fmt.Errorf("could not get NSEC3 values from any of the DNS servers")
}

func (nw *NSec3Walker) extractNSEC3Hashes(domain string, authNsServer string) (err error) {
	r, err := getNsResponse(domain, authNsServer)

	if err != nil {
		return
	}

	for _, rr := range r.Ns {
		if nsec, ok := rr.(*dns.NSEC); ok {
			if strings.HasPrefix(nsec.NextDomain, "\\000") {
				return errors.New("Black lies detected on " + authNsServer + ", skipping this name server")
			}
		}

		if nsec3, ok := rr.(*dns.NSEC3); ok {
			err = nw.setNsec3Values(nsec3.Salt, nsec3.Iterations)

			if err != nil {
				// salt or iterations changed, we need to start over
				nw.out.Fatal(err)
			}

			hashStart := strings.ToLower(strings.Split(nsec3.Header().Name, ".")[0])
			hashEnd := strings.ToLower(nsec3.NextDomain)

			if hashStart[:len(hashStart)-1] == hashEnd[:len(hashStart)-1] {
				return errors.New("White lies detected on " + authNsServer + ", skipping this name server")
			}

			nw.chanHashesFound <- Nsec3Record{hashStart, hashEnd, nsec3.TypeBitMap}
		}
	}

	return
}

func (nw *NSec3Walker) setNsec3Values(salt string, iterations uint16) (err error) {
	if nw.nsec.salt == salt && nw.nsec.iterations == iterations {
		return
	}

	if nw.nsec.salt != "" && nw.nsec.salt != salt {
		return fmt.Errorf("NSEC3 salt changed from %s to %s", nw.nsec.salt, salt)
	}

	if nw.nsec.iterations != 0 && nw.nsec.iterations != iterations {
		return fmt.Errorf("NSEC3 iterations changed from %d to %d", nw.nsec.iterations, iterations)
	}

	nw.nsec.salt = salt
	nw.nsec.iterations = iterations

	return
}

func (nw *NSec3Walker) workerForAuthNs(ns string) {
	for domain := range nw.chanDomain {
		if nw.isDomainInRange(domain) {
			continue
		}

		time.Sleep(time.Millisecond * WaitMs)

		err := nw.extractNSEC3Hashes(domain.Domain, ns)
		nw.stats.didQuery()

		if err != nil {
			if errNoConnection(err) {
				nw.logVerbose(fmt.Sprintf("DNS server %s don't wanna talk with us, let's wait a while", ns))
				time.Sleep(time.Second * 3)

				continue
			}

			nw.out.Log(fmt.Sprintf("Error querying %s: %v", domain, err))

			continue
		}
	}
}

func (nw *NSec3Walker) logVerbose(text string) {
	if nw.config.Verbose {
		nw.out.Log(text)
	}
}

func (nw *NSec3Walker) isDomainInRange(domain *Domain) (inRange bool) {
	inRange, where := nw.ranges.isHashInRange(domain.Hash)

	if inRange {
		nw.logVerbose(fmt.Sprintf("Domain in range [%s] <= %s (%s)", where, domain.Hash, domain.Domain))
	}

	return
}
