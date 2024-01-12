package main

import (
	"context"
	"errors"
	"strings"

	"github.com/foxcpp/mailsec-check/dns"
	"github.com/foxcpp/mailsec-check/mtasts"
)

func evaluateMTASTS(domain string, res *Results) error {
	res.mtasts = LevelSecure

	_, txts, err := extR.AuthLookupTXT(context.Background(), "_mta-sts."+domain)
	if err == dns.ErrNxDomain {
		res.mtasts = LevelMissing
		res.mtastsDesc = "no _mta-sts subdomain;"
		return nil
	} else if err != nil {
		res.mtasts = LevelInvalid
		res.mtastsDesc = "domain query error: " + err.Error() + ";"
		return err
	}
	txt := strings.Join(txts, "")

	if strings.TrimSpace(txt) == "" {
		res.mtasts = LevelMissing
		res.mtastsDesc = "no policy;"
		return nil
	}

	levelDown := func(to Level) {
		if res.mtasts > to {
			res.mtasts = to
		}
	}

	_, err = mtasts.ReadDNSRecord(txt)
	if err != nil {
		res.mtasts = LevelInvalid
		res.mtastsDesc = "malformed record: " + err.Error() + ";"
		return nil
	}

	policy, err := mtasts.DownloadPolicy(domain)
	if err != nil {
		res.mtasts = LevelInvalid
		res.mtastsDesc = "policy fetch error: " + err.Error() + ";"
		return nil
	}

	_, mxs, err := extR.AuthLookupMX(context.Background(), domain)
	if err != nil {
		return err
	}
	if len(mxs) == 0 {
		return errors.New("domain does not have any MX records")
	}

	allMatched := true
	allUnmatched := false

	for _, mx := range mxs {
		if policy.Match(mx.Host) {
			allUnmatched = false
		} else {
			levelDown(LevelInvalid)
			res.mtastsDesc += mx.Host + " does not match the policy"
			allMatched = false
		}
	}

	if policy.Mode != mtasts.ModeEnforce {
		levelDown(LevelInsecure)
		res.mtastsDesc += "not enforced; "
	} else {
		levelDown(LevelSecure)
		res.mtastsDesc += "enforced; "
	}

	if allMatched {
		levelDown(LevelSecure)
		res.mtastsDesc += "all MXs match policy; "
	} else if allUnmatched {
		levelDown(LevelInvalid)
		res.mtastsDesc += "no MXs match policy; "
	}
	return nil
}
