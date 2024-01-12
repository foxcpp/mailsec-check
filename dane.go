package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/emersion/go-smtp"
	"github.com/miekg/dns"
)

func evaluateDANE(domain string, res *Results) error {
	res.dane = LevelSecure

	_, mxs, err := extR.AuthLookupMX(context.Background(), domain)
	if err != nil {
		return err
	}
	if len(mxs) == 0 {
		return errors.New("domain does not have any MX records")
	}

	levelDown := func(to Level) {
		if res.dane > to {
			res.dane = to
		}
	}

	allAD := true
	allValid := true
	allPresent := true
	for _, mx := range mxs {
		ad, recs, err := extR.AuthLookupTLSA(context.Background(), "_25._tcp."+mx.Host)
		if err != nil {
			allPresent = false
			levelDown(LevelMissing)
			res.daneDesc += fmt.Sprintf("no record for %s; ", mx.Host)
			continue
		}
		if !ad {
			allAD = false
		}
		if len(recs) == 0 {
			allPresent = false
			levelDown(LevelMissing)
			res.daneDesc += fmt.Sprintf("no record for %s; ", mx.Host)
			continue
		}
		for _, rec := range recs {
			res.daneRec += rec.String() + "\n"
		}

		if !(*active) {
			continue
		}

		for _, mx := range mxs {
			if ok := checkTLSA(mx.Host, recs, res); !ok {
				allValid = false
			}
		}
	}

	if allPresent {
		res.daneDesc += "present for all MXs; "
	}

	if !allAD {
		levelDown(LevelInvalid)
		res.daneDesc += "no DNSSEC; "
	} else {
		res.daneDesc += "DNSSEC-signed; "
	}

	if !(*active) {
		res.daneDesc += "no validity check done; "
		return nil
	}

	if allValid {
		res.daneDesc += "valid for all MXs; "
	}

	return nil
}

func checkTLSA(mx string, recs []dns.TLSA, res *Results) bool {
	levelDown := func(to Level) {
		if res.dane > to {
			res.dane = to
		}
	}

	cl, err := smtp.Dial(mx + ":25")
	if err != nil {
		levelDown(LevelUnknown)
		res.daneDesc += fmt.Sprintf("can't connect to %s: %v; ", mx, err)
		return false
	}
	defer cl.Close()

	if ok, _ := cl.Extension("STARTTLS"); !ok {
		levelDown(LevelInvalid)
		res.daneDesc += fmt.Sprintf("%s doesn't support STARTTLS; ", mx)
		return false
	}

	if err := cl.StartTLS(nil); err != nil {
		levelDown(LevelInvalid)
		res.daneDesc += err.Error()
		return false
	}

	state, ok := cl.TLSConnectionState()
	if !ok {
		panic("No TLS state returned after STARTTLS")
	}

	cert := state.PeerCertificates[0]
	match := false
	for _, rec := range recs {
		if rec.Verify(cert) == nil {
			match = true
		}
	}

	if !match {
		levelDown(LevelInvalid)
		res.daneDesc += fmt.Sprintf("%v uses wrong cert; ", mx)
	}

	return true
}
