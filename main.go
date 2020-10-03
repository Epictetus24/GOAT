package main

import (
	"bufio"
	"encoding/csv"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/Epictetus24/gowebscan/reporting"
	"github.com/Epictetus24/gowebscan/scan"
	"github.com/Epictetus24/gowebscan/tools"
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
				color.Green("Hostname %s added to list with port %s\n", deets[0], deets[1])
				host.Hostname = deets[0]
				host.IP = deets[1]
			}
			//host = lookup(host)
			targets.Hostlist = append(targets.Hostlist, host)

		}
		// Loop over the parts from the string.
	}
	return targets
}

func toolChecks(host scan.Host, wg *sync.WaitGroup) {

	defer wg.Done()
	tools.Toolarmoury(host)

}

func simpleChecks(host scan.Host, wg *sync.WaitGroup, csvFile *os.File) {
	defer csvFile.Close()
	defer wg.Done()
	var Headervulns reporting.Vulncollect
	Headervulns = scan.CheckHeaders(host)
	scan.Methods(host)
	scan.CheckHostFuckery(host)

	csvwriter := csv.NewWriter(csvFile)

	vl := Headervulns.Vulnlist
	for i := range vl {
		vd := vl[i]
		riskrating := strconv.Itoa(vd.Riskrating)
		headings := []string{"Name", "Risk_rating", "Summary", "Technical_details", "Recommendation"}
		csvwriter.Write(headings)
		vulnRow := []string{vd.Name, riskrating, vd.Summary, vd.Technicaldetails, vd.Recommendation}
		csvwriter.Write(vulnRow)

	}

	csvwriter.Flush()

}

func main() {

	file := os.Args[1]

	var wg sync.WaitGroup

	targets := populate(file)

	hl := targets.Hostlist

	for i, s := range hl {

		color.Yellow("Host tests for %s commencing\n", s.Hostname)
		path := s.Hostname + "_output"
		reportpath := "report_" + s.Hostname + ".csv"
		os.Mkdir(path, 0755)
		csvFile, err := os.Create(reportpath)

		if err != nil {
			log.Fatalf("failed creating file: %s", err)
		}

		//wg.Add(1)
		//go toolChecks(hl[i], &wg)
		wg.Add(1)
		go simpleChecks(hl[i], &wg, csvFile)
	}

	wg.Wait()

}
