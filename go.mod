module github.com/foxcpp/mailsec-check

go 1.13

require (
	github.com/emersion/go-msgauth v0.0.0-00010101000000-000000000000
	github.com/emersion/go-smtp v0.11.2
	github.com/miekg/dns v1.1.22
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db
)

replace github.com/emersion/go-msgauth => github.com/foxcpp/go-msgauth v0.2.1-0.20191025182424-14b58d8c56d2
