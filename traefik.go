package traefik

import (
	"context"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("traefik")

type TraefikConfigEntry struct {
	cname string
	ttl   uint32
}

type TraefikConfigEntryMap map[string]*TraefikConfigEntry

type TraefikConfig struct {
	baseUrl         *url.URL
	a               net.IP
	cname           string
	ttl             uint32
	refreshInterval uint32
	hostMatcher     *regexp.Regexp
}

type Traefik struct {
	Next          plugin.Handler
	Config        *TraefikConfig
	TraefikClient *TraefikClient

	mappings TraefikConfigEntryMap
	ready    bool
	mutex    sync.RWMutex
}

func (t *Traefik) Name() string { return "traefik" }

func (t *Traefik) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	if state.QClass() != dns.ClassINET || state.QType() != dns.TypeA {
		log.Debugf("Ignoring class %q, type %q", state.QClass(), state.QType())
		return plugin.NextOrFailure(t.Name(), t.Next, ctx, w, r)
	}

	requestCount.WithLabelValues(metrics.WithServer(ctx)).Inc()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	rtype := dns.TypeCNAME
	if t.Config.a != nil {
		rtype = dns.TypeA
	}

	hdr := dns.RR_Header{Name: state.QName(), Rrtype: rtype, Class: dns.ClassINET, Ttl: t.Config.ttl}

	for _, q := range state.Req.Question {
		find := strings.ToLower(q.Name[:len(q.Name)-1])
		result := t.getEntry(find)
		if result != nil {
			if t.Config.a != nil {
				m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: t.Config.a}}
			} else {
				m.Answer = []dns.RR{&dns.CNAME{Hdr: hdr, Target: t.Config.cname}}
			}
			w.WriteMsg(m)

			return dns.RcodeSuccess, nil
		}
	}

	return plugin.NextOrFailure(t.Name(), t.Next, ctx, w, r)
}

func (t *Traefik) start() error {
	log.Info("Starting!")
	t.refresh()

	uptimeTicker := time.NewTicker(time.Duration(t.Config.refreshInterval) * time.Second)

	for {
		select {
		case <-uptimeTicker.C:
			log.Debug("Refreshing sites")
			err := t.refresh()
			if err != nil {
				log.Warningf("Error updating sites: %v", err)
			}
		}
	}
}

func (t *Traefik) getEntry(host string) *TraefikConfigEntry {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	value, foundIt := t.mappings[host]
	if !foundIt {
		return nil
	}

	return value
}

func (t *Traefik) refresh() error {
	routers, err := t.TraefikClient.GetHttpRouters()
	if err != nil {
		return err
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	adds, deletes := 0, 0
	fromTraefik := map[string]struct{}{}
	for _, s := range *routers {
		strs := t.Config.hostMatcher.FindAllStringSubmatch(s.Rule, -1)
		for _, s := range strs {
			if len(s) == 3 {
				host := strings.ToLower(s[2])
				fromTraefik[host] = struct{}{}

				if host != t.Config.cname {
					_, exists := t.mappings[host]
					if !exists {
						var target string
						if t.Config.a != nil {
							target = t.Config.a.String()
						} else {
							target = t.Config.cname
						}
						log.Infof("+ %s -> %s", host, target)
						t.mappings[host] = &TraefikConfigEntry{
							cname: t.Config.cname,
							ttl:   t.Config.ttl,
						}
						adds += 1
					}
				}
			}
		}
	}

	toDelete := map[string]struct{}{}
	for cachedHost := range t.mappings {
		_, stillExists := fromTraefik[cachedHost]
		if !stillExists {
			var target string
			if t.Config.a != nil {
				target = t.Config.a.String()
			} else {
				target = t.Config.cname
			}
			log.Infof("- %s -> %s", cachedHost, target)
			toDelete[cachedHost] = struct{}{}
			deletes += 1
		}
	}

	for del := range toDelete {
		delete(t.mappings, del)
	}

	if adds > 0 && deletes > 0 {
		log.Infof("Added %d, deleted %d entries", adds, deletes)
	} else if adds > 0 {
		log.Infof("Added %d entries", adds)
	} else if deletes > 0 {
		log.Infof("Deleted %d entries", deletes)
	} else {
		log.Debug("No changes detected")
	}

	t.ready = true
	return nil
}
