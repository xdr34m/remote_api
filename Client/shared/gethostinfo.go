package shared

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"go.uber.org/zap"
)

var (
	OSFacts = make(map[string]string)
)

func SetClientFacts() error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("error getting hostname: %v", err)
	}
	// Get the FQDN
	fqdn, err := getFQDN(hostname)
	if err != nil {
		//return fmt.Errorf("error getting FQDN: %v", err) - only doable if fqdn is there
		Log.Warn("error getting FQDN, going with unsigned", zap.Error(err))
	}
	os := runtime.GOOS

	if os == "linux" {
		OSFacts["signed"] = "false"
	} else if strings.HasSuffix(fqdn, ".de") {
		OSFacts["signed"] = "true"
	} else {
		OSFacts["signed"] = "false"
	}
	OSFacts["os"] = os
	OSFacts["hostname"] = hostname
	return nil
}

// getFQDN returns the Fully Qualified Domain Name (FQDN) for the current hostname
func getFQDN(hostname string) (string, error) {
	// Look up the addresses for the hostname
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return "", fmt.Errorf("failed to look up host: %v", err)
	}

	// Check if there are any addresses found
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses found for hostname: %s", hostname)
	}

	// Get the first address
	addr := addrs[0]

	// Look up the FQDN for this address
	names, err := net.LookupAddr(addr)
	if err != nil {
		return "", fmt.Errorf("failed to look up address: %v", err)
	}

	// Return the first FQDN found
	if len(names) > 0 {
		return names[0], nil
	}

	return "", fmt.Errorf("no FQDN found for address: %s", addr)
}
