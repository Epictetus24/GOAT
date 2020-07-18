package scan

import (
	"fmt"
	"os/exec"
	"sync"

	"github.com/fatih/color"
)

//Host stores each application hostname and IP address
type Host struct {
	Hostname string
	IP       string
}

//Targets stores all the hosts in a slice
type Targets struct {
	Hostlist []Host
}

func Nikto(host Host, wg *sync.WaitGroup) {

	defer wg.Done()
	filename := host.Hostname + "-nikto_output.txt"

	args := []string{"nikto", "-host", "hostname", "-output", "filename", "-port", "443"}
	args[2] = host.Hostname
	args[4] = filename

	nikto := exec.Command("/bin/bash", args[0:]...)
	if err := nikto.Start(); err != nil {
		color.Red("Failed to start nikto: %v", err)
		return
	}

	color.Cyan("Nikto running against host %s on port 443\n", host.Hostname)

	if err := nikto.Wait(); err != nil {
		color.Red("nikto returned error: %v", err)
	}

	color.Green("Nikto finished, file for %s saved as %s\n", host.Hostname, filename)

}

func Testssl(host Host, wg *sync.WaitGroup) {

	defer wg.Done()

	args := []string{"/opt/testssl.sh/testssl.sh", "--html", "--log", "hostname"}
	args[3] = host.Hostname

	testssl := exec.Command("/bin/bash", args[0:]...)
	if err := testssl.Start(); err != nil {
		color.Red("Failed to start testssl: %v", err)
		return
	}

	color.Blue("testssl running against host %s\n", host.Hostname)

	if err := testssl.Wait(); err != nil {
		color.Red("testssl returned error: %v", err)
	}

	color.Green("testssl finished, file for %s saved.\n", host.Hostname)
}

func Gobust(host Host, wg *sync.WaitGroup) {

	defer wg.Done()

	args := []string{"dir", "-u", "hostname", "-w", "/opt/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt", "-o", "hostname-gobuster"}
	args[2] = host.Hostname
	filename := host.Hostname + "-gobust.txt"
	args[6] = filename
	fmt.Println(args)

	gobust := exec.Command("/usr/bin/gobuster", args[0:]...)
	if err := gobust.Start(); err != nil {
		color.Red("Failed to start gobuster: %v", err)
		return
	}

	color.Blue("gobust running against host %s\n", host.Hostname)

	if err := gobust.Wait(); err != nil {
		color.Red("gobust returned error: %v", err)
	}

	color.Green("gobust finished, file for %s saved as %s.\n", host.Hostname, args[7])
}

func Whatweb(host Host) {

	args := []string{"-v", "-a", "4", "host", "--log-verbose="}
	args[3] = host.Hostname
	filename := "--log-verbose=" + host.Hostname + "-gobust.txt"
	args[4] = filename

	gobust := exec.Command("/usr/bin/whatweb", args[0:]...)
	if err := gobust.Start(); err != nil {
		color.Red("Failed to start whatweb: %v", err)
		return
	}

	color.Blue("whatweb running against host %s\n", host.Hostname)

	if err := gobust.Wait(); err != nil {
		color.Red("whatweb returned error: %v", err)
	}

	color.Green("gobust finished, file for %s saved as %s.\n", host.Hostname, args[7])
}

func Nmap(host Host) {

	args := []string{"-vv", "-n", "-sV", "-Pn", "-O", "-oA", "full_tcp", "-p0-", "IP_ADDRESS"}
	args[8] = host.IP
	filename := "fulltcp_nmap_" + host.Hostname
	args[6] = filename

	gobust := exec.Command("/usr/bin/nmap", args[0:]...)
	if err := gobust.Start(); err != nil {
		color.Red("Failed to start nmap: %v", err)
		return
	}

	color.Blue("nmap full tcp running against host %s\n", host.Hostname)

	if err := gobust.Wait(); err != nil {
		color.Red("nmap returned error: %v", err)
	}

	color.Green("nmap finished, file for %s saved as %s.\n", host.Hostname, args[7])
}
