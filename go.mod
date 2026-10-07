// A collage plugin that stops form spam without a CAPTCHA: a decoy field people
// never see, and a signed timestamp, put into cached pages on the way out, that
// refuses a form sent back too soon or too late.
module github.com/Elagoht/collage-honeypot

go 1.26

require github.com/Elagoht/collage v0.50.0

retract v0.4.1 // tagged at v0.4.0's commit by mistake
