package scan

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os/exec"

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

type Tool struct {
	Args   []string
	Fileid int
	hostid int
}

//CheckHeaders performs checks for security headers, or headers which might reveal more information
func CheckHeaders(host Host) {

	url := "https://"
	url = url + host.Hostname

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		client := &http.Client{Transport: tr}
		resp, err = client.Do(request)
		if err != nil {
			log.Println(err)
		}
	}

	color.Cyan("Checking Security headers for %s", host)

	secheaders := []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"}

	for i := range secheaders {
		if resp.Header.Get(secheaders[i]) == "" {
			color.Red("%s is missing from response\n", secheaders[i])

		} else {
			color.Green("%s is set\n", secheaders[i])
			color.Green("%s: %s\n", secheaders[i], resp.Header.Get(secheaders[i]))

		}
	}

	detailheaders := []string{"Server", "X-Powered-By", "X-AspNet-Version"}

	color.Cyan("Checking Details/Verbose headers for %s", host)

	for i := range detailheaders {
		if resp.Header.Get(detailheaders[i]) == "" {
			color.Green("%s header not found\n", detailheaders[i])

		} else {
			color.Red("%s is set\n", detailheaders[i])
			color.Yellow("%s: %s\n", detailheaders[i], resp.Header.Get(detailheaders[i]))

		}
	}

	color.Blue("\n Headers returned:\n")

	for k, v := range resp.Header {
		fmt.Print(k)
		fmt.Print(" : ")
		fmt.Println(v)
	}

}

//CheckMethods - Requests with supplied method and returns the status code.
func CheckMethods(method string, host Host) int {

	url := "https://"
	url = url + host.Hostname

	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		log.Println(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		client := &http.Client{Transport: tr}
		resp, err = client.Do(request)
		if err != nil {
			log.Println(err)
		}
	}

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		fmt.Printf("HTTP Status for %s with method %s is in the 2xx range: Code: %d\n", host, method, resp.StatusCode)
	}

	return resp.StatusCode
}

//Methods iterates through potential methods and gets the status code for each, before printing to console.
func Methods(host Host) {

	m := make(map[string]int)

	methods := []string{"GET", "POST", "PUT", "TRACE", "CONNECT", "DELETE", "OPTIONS", "HEAD"}

	for i := range methods {

		m[methods[i]] = CheckMethods(methods[i], host)

	}
	fmt.Printf("\n %s Method Results:\n", host.Hostname)
	fmt.Printf("%v\n", m)
	color.Green("Method checks for %s, finished.\n\n", host.Hostname)

}

//Nikto runs nikto
func Nikto(host Host) {

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

//Testssl runs testssl
func Testssl(host Host) {

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

//Gobust runs gobuster with raft-small-words
func Gobust(host Host) {

	args := []string{"dir", "-u", "hostname", "-w", "/opt/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt", "-o", "hostname-gobuster", "-t4"}
	args[2] = host.Hostname
	filename := host.Hostname + "-gobust.txt"
	args[6] = filename

	gobust := exec.Command("/usr/bin/gobuster", args[0:]...)
	if err := gobust.Start(); err != nil {
		color.Red("Failed to start gobuster: %v", err)
		return
	}

	color.Yellow("gobust running against host %s\n", host.Hostname)

	if err := gobust.Wait(); err != nil {
		color.Red("gobust returned error: %v", err)
	}

	color.Green("gobust finished, file for %s saved as %s.\n", host.Hostname, args[6])
}

//Whatweb runs whatweb in an aggressive and verbose manner
func Whatweb(host Host) {

	args := []string{"-v", "-a", "4", "host", "--log-verbose="}
	args[3] = host.Hostname
	filename := "--log-verbose=" + host.Hostname + "-whatweb.txt"
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

	color.Green("whatweb finished, file for %s saved as %s.\n", host.Hostname, args[4])
}

//Nmap does a nmap version scan of the host through all tcp ports and outputs all formats
func Nmap(host Host) {

	args := []string{"-sV", "-O", "-Pn", "host.co.uk", "-p0-", "-oA", "full_tcp", "-T3", "-vv"}
	args[3] = host.Hostname
	filename := "fulltcp_nmap_" + host.Hostname
	args[6] = filename

	gobust := exec.Command("/usr/bin/nmap", args[0:]...)
	if err := gobust.Start(); err != nil {
		color.Red("Failed to start nmap: %v", err)
		return
	}

	color.Green("nmap full tcp running against host %s\n", host.Hostname)

	if err := gobust.Wait(); err != nil {
		color.Red("nmap returned error: %v", err)
	}

	color.Green("nmap finished, file for %s saved as %s.\n", host.Hostname, args[6])
}
