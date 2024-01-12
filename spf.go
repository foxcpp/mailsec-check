package main

import (
	"context"
	"strings"

	"github.com/foxcpp/mailsec-check/dns"
)

func evaluateSPF(domain string, res *Results) error {
	res.spf = LevelSecure

	ad, txts, err := extR.AuthLookupTXT(context.Background(), domain)
	if err == dns.ErrNxDomain {
		res.spf = LevelMissing
		res.spfDesc = "no domain;"
		return nil
	} else if err != nil {
		res.spf = LevelInvalid
		res.spfDesc = "domain query error: " + err.Error() + ";"
		return err
	}

	spfRecPresent := false
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			spfRecPresent = true
			res.spfDesc += "present; "
			if err := evalSPFRecord(txt, res); err != nil {
				return err
			}
		}
	}

	if !spfRecPresent {
		res.spf = LevelMissing
		res.spfDesc += "no policy;"
		return nil
	}

	if res.spfDesc == "present; " {
		res.spfDesc += "strict; "
	}

	if !ad {
		res.spf = LevelInsecure
		res.spfDesc += "no DNSSEC; "
	} else {
		res.spfDesc += "DNSSEC-signed; "
	}

	return nil
}

func evalSPFRecord(txt string, res *Results) error {
	parts := strings.Split(txt, " ")

	if len(parts) == 0 {
		res.spf = LevelMissing
		res.spfDesc += "missing policy;"
	}

	for _, part := range parts {
		if strings.HasPrefix(part, "redirect=") {
			_, txts, err := extR.AuthLookupTXT(context.Background(), strings.TrimPrefix(part, "redirect="))
			if err != nil {
				return err
			}
			newTxt := strings.Join(txts, "")
			return evalSPFRecord(newTxt, res)
		}

		switch part {
		case "+all", "all":
			res.spf = LevelInsecure
			res.spfDesc += "policy allows any host; "
		case "?all":
			res.spf = LevelInsecure
			res.spfDesc += "policy defines neutral result as default; "
		}
	}

	return nil
}
