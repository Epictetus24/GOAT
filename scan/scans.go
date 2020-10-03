package scan

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

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

	color.Cyan("\n\nChecking Security headers for %s", host)

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

	color.Blue("\nHeaders returned:\n")

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
