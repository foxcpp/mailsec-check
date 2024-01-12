// The mtasts policy implements parsing, caching and checking of
// MTA-STS (RFC 8461) policies.
package mtasts

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type MalformedDNSRecordError struct {
	// Additional description of the error.
	Desc string
}

func (e MalformedDNSRecordError) Error() string {
	return fmt.Sprintf("mtasts: malformed DNS record: %s", e.Desc)
}

func ReadDNSRecord(raw string) (id string, err error) {
	parts := strings.Split(raw, ";")
	versionPresent := false
	for _, part := range parts {
		part = strings.TrimSpace(part)
		// handle k=v;k=v;
		//				 ^
		if part == "" {
			continue
		}
		kv := strings.Split(part, "=")
		if len(kv) != 2 {
			return "", MalformedDNSRecordError{Desc: "invalid record part: " + part}
		}

		if strings.ContainsAny(kv[0], " \t") || strings.ContainsAny(kv[1], " \t") {
			return "", MalformedDNSRecordError{Desc: "whitespace is not allowed in name or value"}
		}

		switch kv[0] {
		case "v":
			if kv[1] != "STSv1" {
				return "", MalformedDNSRecordError{Desc: "unsupported version: " + kv[1]}
			}
			versionPresent = true
		case "id":
			id = kv[1]
		}
	}
	if !versionPresent {
		return "", MalformedDNSRecordError{Desc: "missing version value"}
	}
	if id == "" {
		return "", MalformedDNSRecordError{Desc: "missing id value"}
	}
	return
}

type MalformedPolicyError struct {
	// Additional description of the error.
	Desc string
}

func (e MalformedPolicyError) Error() string {
	return fmt.Sprintf("mtasts: malformed policy: %s", e.Desc)
}

type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeTesting Mode = "testing"
	ModeNone    Mode = "none"
)

type Policy struct {
	Mode   Mode
	MaxAge int
	MX     []string
}

func readPolicy(contents io.Reader) (*Policy, string, error) {
	contentsBytes, err := io.ReadAll(contents)
	if err != nil {
		return nil, "", err
	}
	rawContents := string(contentsBytes)
	contentsReader := bytes.NewReader(contentsBytes)
	scnr := bufio.NewScanner(contentsReader)
	policy := Policy{}

	present := make(map[string]struct{})

	for scnr.Scan() {
		fieldParts := strings.Split(scnr.Text(), ":")
		if len(fieldParts) != 2 {
			return nil, rawContents, MalformedPolicyError{Desc: "invalid field: " + scnr.Text()}
		}

		// Arbitrary whitespace after colon:
		//	sts-policy-field-delim   = ":" *WSP
		fieldName := fieldParts[0]
		fieldValue := strings.TrimSpace(fieldParts[1])
		switch fieldName {
		case "version":
			if fieldValue != "STSv1" {
				return nil, rawContents, MalformedPolicyError{Desc: "unsupported policy version: " + fieldValue}
			}
		case "mode":
			switch Mode(fieldValue) {
			case ModeEnforce, ModeTesting, ModeNone:
				policy.Mode = Mode(fieldValue)
			default:
				return nil, rawContents, MalformedPolicyError{Desc: "invalid mode value: " + fieldValue}
			}
		case "max_age":
			var err error
			policy.MaxAge, err = strconv.Atoi(fieldValue)
			if err != nil {
				return nil, rawContents, MalformedPolicyError{Desc: "invalid max_age value: " + err.Error()}
			}
		case "mx":
			policy.MX = append(policy.MX, fieldValue)
		}
		present[fieldName] = struct{}{}
	}
	if err := scnr.Err(); err != nil {
		return nil, rawContents, err
	}

	if _, ok := present["version"]; !ok {
		return nil, rawContents, MalformedPolicyError{Desc: "version field required"}
	}
	if _, ok := present["mode"]; !ok {
		return nil, rawContents, MalformedPolicyError{Desc: "mode field required"}
	}
	if _, ok := present["max_age"]; !ok {
		return nil, rawContents, MalformedPolicyError{Desc: "max_age field required"}
	}

	if policy.Mode != ModeNone && len(policy.MX) == 0 {
		return nil, rawContents, MalformedPolicyError{Desc: "at least one mx field required when mode is not none"}
	}

	return &policy, rawContents, nil
}

func (p Policy) Match(mx string) bool {
	mx = strings.TrimSuffix(mx, ".")

	for _, mxRecord := range p.MX {
		if strings.HasPrefix(mxRecord, "*.") {
			if mx[strings.Index(mx, "."):] == mxRecord[1:] {
				return true
			}
			continue
		}

		if mxRecord == mx {
			return true
		}
	}
	return false
}
