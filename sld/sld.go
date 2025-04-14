package sld

import (
	"strings"
	"golang.org/x/net/publicsuffix"
)

func ExtractSLD(fqdn string, withTLD bool) string {
	fqdn = strings.ToLower(strings.TrimSpace(fqdn))
	fqdn = strings.TrimSuffix(fqdn, ".")
	if fqdn == "" || strings.ContainsAny(fqdn, " \t\n\r") {
		return ""
	}

	/*
	parts := strings.Split(fqdn, ".")
	n := len(parts)
	if n < 2 {
		return fqdn
	}

	sld := parts[n-2]
	tld := parts[n-1]

	// Avoid weird generated subdomains like UUIDs
    if len(sld) > 63 || !isValidLabel(sld) {
        return ""
    }

	if withTLD {
        return sld + "." + tld
    }
	
	return sld*/

	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(fqdn)
	if err != nil {
		return ""
	}
	return eTLDPlusOne
}

func isValidLabel(s string) bool {
    for _, r := range s {
        if r < 'a' || r > 'z' {
            if r < '0' || r > '9' {
                if r != '-' {
                    return false
                }
            }
        }
    }
    return true
}
