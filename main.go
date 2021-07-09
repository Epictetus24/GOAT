package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Epictetus24/GOAT/reporting"
	"github.com/Epictetus24/GOAT/scan"
	"github.com/Epictetus24/GOAT/tools"
	"github.com/fatih/color"
)

func Lookup(host scan.Host) (hostip scan.Host) {
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

func Populate(file string) scan.Targets {
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
				color.Green("Hostname %s added to test list with whatever IP resolves\n", deets[0])
				host.Hostname = deets[0]
				host.Port = "443"
			} else if len(deets) > 2 {
				host.Hostname = deets[0]
				host.IP = deets[1]
				host.Port = deets[2]

			} else {
				color.Green("Hostname %s added to test list with IP %s\n", deets[0], deets[1])
				host.Hostname = deets[0]
				host.IP = deets[1]
				host.Port = "443"
			}
			//host = lookup(host)
			seconds := 10
			timeOut := time.Duration(seconds) * time.Second

			_, err := net.DialTimeout("tcp", host.Hostname+":"+host.Port, timeOut)

			if err == nil {
				color.Green("Host %s:%s is live, will add to targets.\n", host.Hostname, host.Port)
				targets.Hostlist = append(targets.Hostlist, host)
			} else {
				fmt.Println(err)
				color.Red("Host %s couldn't be reached, not adding to target list.\n", host.Hostname)
			}

		}
		// Loop over the parts from the string.
	}
	return targets
}

func ToolChecks(host scan.Host, wg *sync.WaitGroup) {

	defer wg.Done()
	tools.Toolarmoury(host)

}

func SimpleChecks(host scan.Host, wg *sync.WaitGroup, csvFile *os.File) {
	defer csvFile.Close()
	defer wg.Done()
	var Headervulns reporting.Vulncollect
	Headervulns = scan.CheckHeaders(host)
	scan.Methods(host)
	scan.CheckHostFuckery(host)

	csvwriter := csv.NewWriter(csvFile)

	vl := Headervulns.Vulnlist
	headings := []string{"name", "risk_rating", "summary", "technical_details", "recommendation", "finding", "affected_hosts"}
	csvwriter.Write(headings)
	for i := range vl {
		vd := vl[i]
		riskrating := strconv.Itoa(vd.Riskrating)
		vulnRow := []string{vd.Name, riskrating, vd.Summary, vd.Technicaldetails, vd.Recommendation, host.Hostname}
		csvwriter.Write(vulnRow)

	}

	csvwriter.Flush()

}

func main() {

	file := os.Args[1]

	var wg sync.WaitGroup

	targets := Populate(file)

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

		wg.Add(1)
		go ToolChecks(hl[i], &wg)
		wg.Add(1)
		go SimpleChecks(hl[i], &wg, csvFile)
	}

	wg.Wait()

}
