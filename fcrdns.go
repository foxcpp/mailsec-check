package main

import (
	"context"
	"fmt"
	"strings"
)

func evaluateFCRDNS(domain string, res *Results) error {
	_, mxs, err := extR.AuthLookupMX(context.Background(), domain)
	if err != nil {
		return fmt.Errorf("lookup mx %v: %w", domain, err)
	}

	allUnmatched := true
	allMatched := true

	levelDown := func(to Level) {
		if res.fcrdns > to {
			res.fcrdns = to
		}
	}

	for _, mx := range mxs {
		_, addrs, err := extR.AuthLookupHost(context.Background(), mx.Host)
		if err != nil {
			allMatched = false
			levelDown(LevelMissing)
			res.fcrdnsDesc += fmt.Sprintf("lookup error %v: %v; ", mx.Host, err)
		}

		for _, addr := range addrs {
			_, names, err := extR.AuthLookupAddr(context.Background(), addr)
			if err != nil {
				allMatched = false
				levelDown(LevelMissing)
				res.fcrdnsDesc += fmt.Sprintf("lookup error %v: %v; ", addr, err)
			}

			if len(names) == 0 {
				allMatched = false
				levelDown(LevelMissing)
				res.fcrdnsDesc += fmt.Sprintf("no rDNS for %s; ", addr)
				continue
			}

			match := false
			for _, name := range names {
				if strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(mx.Host, ".")) {
					match = true
				}
			}

			if !match {
				allMatched = false
				levelDown(LevelInsecure)
				res.fcrdnsDesc += fmt.Sprintf("%s [%s] != %s; ", names[0], addr, mx.Host)
			} else {
				allUnmatched = false
			}
		}
	}

	if allUnmatched {
		res.fcrdns = LevelMissing
		res.fcrdnsDesc = "no MXs with forward-confirmed rDNS"
	} else if allMatched {
		res.fcrdns = LevelSecure
		res.fcrdnsDesc = "all MXs have forward-confirmed rDNS"
	}
	return nil
}
