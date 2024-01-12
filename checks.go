package main

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/emersion/go-msgauth/dmarc"
	"github.com/foxcpp/mailsec-check/dns"
)

var extR *dns.ExtResolver

type Level int

const (
	LevelUnknown Level = iota
	LevelInvalid
	LevelMissing
	LevelInsecure
	LevelSecure
)

type Results struct {
	dkim     Level
	dkimDesc string

	spf     Level
	spfDesc string
	spfRec  string

	dmarc     Level
	dmarcDesc string
	dmarcRec  string

	mtasts     Level
	mtastsDesc string
	mtastsRec  string

	dane     Level
	daneDesc string
	daneRec  string

	dnssecMX     Level
	dnssecMXDesc string

	fcrdns     Level
	fcrdnsDesc string
}

func evaluateAll(domain string) (Results, error) {
	res := Results{}

	wg := sync.WaitGroup{}

	wg.Add(7)
	go func() { evaluateDKIM(domain, &res); wg.Done() }()
	go func() { evaluateSPF(domain, &res); wg.Done() }()
	go func() { evaluateDMARC(domain, &res); wg.Done() }()
	go func() { evaluateMTASTS(domain, &res); wg.Done() }()
	go func() { evaluateDANE(domain, &res); wg.Done() }()
	go func() { evaluateDNSSEC(domain, &res); wg.Done() }()
	go func() { evaluateFCRDNS(domain, &res); wg.Done() }()

	wg.Wait()

	return res, nil
}

func evaluateDNSSEC(domain string, res *Results) error {
	ad, addrs, err := extR.AuthLookupHost(context.Background(), domain)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return errors.New("domain does not resolve to an IP addr")
	}
	if !ad {
		res.dnssecMX = LevelInsecure
		res.dnssecMXDesc = "A/AAAA records are not signed;"
		return nil
	}

	ad, mxs, err := extR.AuthLookupMX(context.Background(), domain)
	if err != nil {
		return err
	}
	if len(mxs) == 0 {
		return errors.New("domain does not have any MX records")
	}
	if !ad {
		res.dnssecMX = LevelInsecure
		res.dnssecMXDesc = "MX records are not signed;"
		return nil
	}

	res.dnssecMX = LevelSecure
	res.dnssecMXDesc = "A/AAAA and MX records are signed;"
	return nil
}

func evaluateDKIM(domain string, res *Results) error {
	ad, _, err := extR.AuthLookupTXT(context.Background(), "_domainkey."+domain)
	if err == dns.ErrNxDomain {
		res.dkim = LevelMissing
		res.dkimDesc = "no _domainkey subdomain;"
		return nil
	} else if err != nil {
		res.dkim = LevelInvalid
		res.dkimDesc = "domain query error: " + err.Error() + ";"
		return err
	}

	res.dkim = LevelSecure
	res.dkimDesc += "_domainkey subdomain present; "

	if !ad {
		res.dkim = LevelInsecure
		res.dkimDesc += "no DNSSEC; "
	} else {
		res.dkimDesc += "DNSSEC-signed; "
	}

	return nil
}

func evaluateDMARC(domain string, res *Results) error {
	res.dmarc = LevelSecure

	ad, txts, err := extR.AuthLookupTXT(context.Background(), "_dmarc."+domain)
	if err == dns.ErrNxDomain {
		res.dmarc = LevelMissing
		res.dmarcDesc = "no _dmarc subdomain;"
		return nil
	} else if err != nil {
		res.dmarc = LevelInvalid
		res.dmarcDesc = "domain query error: " + err.Error() + ";"
		return err
	}

	txt := strings.Join(txts, "")
	res.dmarcRec = txt
	rec, err := dmarc.Parse(txt)
	if err != nil {
		res.dmarc = LevelInvalid
		res.dmarcDesc = "policy parse error: " + err.Error()
		return nil
	}

	res.dmarcDesc += "present; "

	if rec.Policy == dmarc.PolicyNone {
		res.dmarc = LevelMissing
		res.dmarcDesc += "no-op; "
	} else if rec.Percent != nil && *rec.Percent != 100 {
		res.dmarc = LevelMissing
		res.dmarcDesc += "applied partially; "
	} else {
		res.dmarcDesc += "strict; "
	}
	if !ad {
		res.dmarc = LevelInsecure
		res.dmarcDesc += "no DNSSEC; "
	} else {
		res.dmarcDesc += "DNSSEC-signed; "
	}

	return nil
}
