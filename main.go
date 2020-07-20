package main

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/Epictetus24/gowebscan/scan"
	"github.com/fatih/color"
)

func lookup(host scan.Host) (hostip scan.Host) {
	addr, err := net.LookupIP(host.Hostname)
	if err != nil {
		os.Exit(1)
	}

	addrstr := addr[0].String()

	if host.IP == "" {
		color.Yellow("No ip set for host %s, adding DNS resolved IP: %s \n", host.Hostname, addrstr)
		host.IP = addrstr
	}

	if addrstr != host.IP {
		color.Red("\n[!] Supplied IP Address for %s does not match what was resolved by DNS.\n Supplied IP: %s\n Resolved IP: %s\n", host.Hostname, host.IP, addr)

	}
	hostip = host
	hostip.IP = addrstr

	return hostip

}

func populate(file string) scan.Targets {
	// Part 1: open the file and scan it.
	f, _ := os.Open(file)
	scanner := bufio.NewScanner(f)
	var targets scan.Targets

	// Part 2: call Scan in a for-loop.
	for scanner.Scan() {
		line := scanner.Text()

		// Split the line on commas.
		parts := strings.Split(line, "\n")

		for i := range parts {
			var host scan.Host
			deets := strings.Split(parts[i], ":")
			if len(deets) < 2 {
				color.Green("Hostname %s added to list with whatever IP resolves\n", deets[0])
				host.Hostname = deets[0]
			} else {
				color.Green("Hostname %s added to list with ip %s\n", deets[0], deets[1])
				host.Hostname = deets[0]
				host.IP = deets[1]
			}
			host = lookup(host)
			targets.Hostlist = append(targets.Hostlist, host)

		}
		// Loop over the parts from the string.
	}
	return targets
}

func intenseChecks(host scan.Host, wg *sync.WaitGroup) {
	defer wg.Done()
	scan.Whatweb(host)
	scan.Nikto(host)
	scan.Testssl(host)
	scan.Gobust(host)
	scan.Nmap(host)

}

func simpleChecks(host scan.Host, wg *sync.WaitGroup) {
	defer wg.Done()
	scan.Methods(host)
}

func main() {

	file := os.Args[1]

	var wg sync.WaitGroup

	targets := populate(file)

	hl := targets.Hostlist

	for i, s := range hl {

		color.Yellow("Host tests for %s commencing\n", s.Hostname)
		wg.Add(1)
		go intenseChecks(hl[i], &wg)
		wg.Add(1)
		go simpleChecks(hl[i], &wg)

	}

	wg.Wait()

}
