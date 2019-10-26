mailsec-check
===============

Another utility to analyze state of deployment of security-related email
protocols.

Compilation
--------------

Needs [Go](https://golang.org) toolchain.

```
go get github.com/foxcpp/mailsec-check
```

Usage
-------

```
mailsec-check example.org
```

Example
---------

```
$ mailsec-check protonmail.com
-- Source forgery protection
[+] DKIM:    _domainkey subdomain present; DNSSEC-signed; 
[+] SPF:     present; strict; DNSSEC-signed; 
[+] DMARC:   present; strict; DNSSEC-signed; 

-- TLS enforcement
[+] MTA-STS: enforced; all MXs match policy; 
[+] DANE:    present for all MXs; DNSSEC-signed; no validity check done; 

-- DNS consistency
[+] FCrDNS:     all MXs have forward-confirmed rDNS
[+] DNSSEC:     A/AAAA and MX records are signed;

$ mailsec-check disroot.org
-- Source forgery protection
[+] DKIM:   _domainkey subdomain present; DNSSEC-signed; 
[+] SPF:    present; strict; DNSSEC-signed; 
[ ] DMARC:  present; no-op; DNSSEC-signed; 

-- TLS enforcement
[ ] MTA-STS: not enforced; all MXs match policy; 
[+] DANE:    present for all MXs; DNSSEC-signed; no validity check done; 

-- DNS consistency
[ ] FCrDNS:     no MXs with forward-confirmed rDNS
[+] DNSSEC:     A/AAAA and MX records are signed;
```
