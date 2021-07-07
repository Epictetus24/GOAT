package scan

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/Epictetus24/GOAT/reporting"
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

type deetheaders struct {
}

func resptostring(resp *http.Response) string {

	var toolout string

	var headerString string
	for k, v := range resp.Header {
		headerString = headerString + k
		headerString = headerString + ": "
		headerString = headerString + v[0]
		headerString = headerString + "\n"

	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	bodyString := string(bodyBytes)

	toolout = headerString + bodyString

	return toolout

}

//CheckHeaders performs checks for security headers, or headers which might reveal more information
func CheckHeaders(host Host) reporting.Vulncollect {

	var headervulns reporting.Vulncollect

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

	secheaders := []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection"}

	for i := range secheaders {
		if resp.Header.Get(secheaders[i]) == "" && secheaders[i] != "X-Frame-Options" {
			var vuln reporting.Vuln
			vuln.Name = "Application missing " + secheaders[i] + " Header."
			vuln.Summary = reporting.Hsecsummaries[i]
			vuln.Finding = reporting.Hsecfindings[i]
			vuln.Recommendation = reporting.Hsecrecommendations[i]
			if secheaders[i] == "Strict-Transport-Security" {
				vuln.Riskrating = 2
			} else {
				vuln.Riskrating = 1
			}

			vuln.Technicaldetails = "The host was missing the " + secheaders[i] + " from its response."
			vuln.Technicaldetails = vuln.Technicaldetails + "Example response:\n" + resptostring(resp) + "\n"

			headervulns.Vulnlist = append(headervulns.Vulnlist, vuln)

			color.Red("%s is missing from response\n", secheaders[i])

		} else if secheaders[i] == "X-Frame-Options" && resp.Header.Get(secheaders[i]) == "" {
			color.Yellow("X-Frame-Options is missing, will generate clickjack poc\n")
			poc := clickjack(host)
			var vuln reporting.Vuln
			vuln.Name = "Cross-Site Framing"
			vuln.Summary = reporting.Hsecsummaries[i]
			vuln.Finding = reporting.Hsecfindings[i]
			vuln.Recommendation = reporting.Hsecrecommendations[i]
			vuln.Riskrating = 1

			vuln.Technicaldetails = "The host was missing the " + secheaders[i] + " from its response."
			vuln.Technicaldetails = vuln.Technicaldetails + "Example response:\n" + resptostring(resp) + "\n"
			vuln.Technicaldetails = vuln.Technicaldetails + "\n The following html code can be used to test if the website can be embedded in an Iframe."
			vuln.Technicaldetails = vuln.Technicaldetails + "\n" + poc

			headervulns.Vulnlist = append(headervulns.Vulnlist, vuln)

		} else {
			color.Green("%s is set\n", secheaders[i])
			if secheaders[i] == "Strict-Transport-Security" && resp.Header.Get(secheaders[i]) != "max-age=31536000" {
				color.Yellow("Max-Age may not be correct or around one year\n")
				color.Yellow("%s: %s\n", secheaders[i], resp.Header.Get(secheaders[i]))

			} else {
				color.Green("%s: %s\n", secheaders[i], resp.Header.Get(secheaders[i]))

			}

		}
	}

	detailheaders := []string{"Server", "X-Powered-By", "X-AspNet-Version"}

	color.Cyan("Checking Details/Verbose headers for %s", host)

	var presentdetailHeaders []string

	for i := range detailheaders {
		if resp.Header.Get(detailheaders[i]) == "" {
			color.Green("%s header not found\n", detailheaders[i])

		} else {
			color.Red("%s is set\n", detailheaders[i])
			color.Yellow("%s: %s\n", detailheaders[i], resp.Header.Get(detailheaders[i]))
			headerfound := detailheaders[i] + ": " + resp.Header.Get(detailheaders[i])
			presentdetailHeaders = append(presentdetailHeaders, headerfound)

		}
	}

	if len(presentdetailHeaders) > 0 {
		var vuln reporting.Vuln
		vuln.Name = "HTTP Headers reveal potentially sensitive information"
		vuln.Summary = "One or more HTTP headers revealed information which could help an attacker enumerate the application software in use."
		vuln.Recommendation = "Rootshell recommends removing or obscuring any headers which may help an attacker identify application software."
		vuln.Technicaldetails = "The application returned the following headers, which may help identify software:\n"
		var headersfound string
		for v := range presentdetailHeaders {
			headersfound = headersfound + presentdetailHeaders[v]
			headersfound = headersfound + "\n"
		}
		vuln.Riskrating = 1
		vuln.Technicaldetails = vuln.Technicaldetails + headersfound
		headervulns.Vulnlist = append(headervulns.Vulnlist, vuln)
	}

	color.Blue("\nHeaders returned:\n")

	for k, v := range resp.Header {
		fmt.Print(k)
		fmt.Print(" : ")
		fmt.Println(v)
	}

	return headervulns

}

func clickjack(host Host) string {
	var x = `
<!doctype html>
<html>
 <title>Crossframe Demo: {{.}}</title>
 <h1>Cross Frame test for site {{.}}</h1>
  <iframe src="https://{{.}}" width="1280" height="720"> </iframe>
  <br>
  <body> If webcontent is displayed above, the site is vulnerable to Clickjacking/Cross-Frame Scripting </body>
</html>
`
	t, err := template.New("crossframe").Parse(x)

	// Create the file
	path := host.Hostname + "_output"
	os.Chdir(path)
	filename := host.Hostname + "_crossframe.html"
	f, err := os.Create(filename)
	if err != nil {
		// handle error
	}

	// Execute the template to the file.
	err = t.Execute(f, host.Hostname)
	if err != nil {
		// handle error
	}

	// Close the file when done.
	f.Close()
	os.Chdir("..")
	var tpl bytes.Buffer
	if err := t.Execute(&tpl, host.Hostname); err != nil {
		//do something probably err
	}

	poc := tpl.String()
	return poc
}

//CheckHostFuckery will mess with the host name if a redirect occurs, and check if the redirect takes it to a new website.
func CheckHostFuckery(host Host) {

	url := "https://"
	url = url + host.Hostname
	url = url + ""

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	var i int
	for i < 100 {
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}}

		resp, err := client.Do(request)

		if err != nil {
			fmt.Println(err)
		}
		if resp == nil {
			return
		}

		if resp.StatusCode == 200 {
			fmt.Println("Host Header Check Done!")
			break
		} else {
			url = resp.Header.Get("Location")
			i++
		}
		if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			color.Yellow("\nRecieved %d status code from host %s\nWants to Redirect to %s", resp.StatusCode, host.Hostname, resp.Header.Get("Location"))
			request.Host = "google.com"
			redirfuckery, err := client.Do(request)
			if err != nil {
				client := &http.Client{Transport: tr}
				redirfuckery, err = client.Do(request)
				if err != nil {
					log.Println(err)
				}
			}
			color.Yellow("\nAttempted to pollute Host header with %s on host: %s \n", request.Host, host.Hostname)
			color.Yellow("Location header became: %s ", redirfuckery.Header.Get("Location"))
			if redirfuckery.Header.Get("Location") != resp.Header.Get("Location") {
				color.Red("Redirects based on host header!\n")
			}
			request.Host = host.Hostname
			request.Header.Set("Referer", "google.com")
			redirfuckery, err = client.Do(request)
			if err != nil {
				client := &http.Client{Transport: tr}
				redirfuckery, err = client.Do(request)
				if err != nil {
					log.Println(err)
				}
			}
			color.Yellow("\nAttempted to pollute Referer header with %s on host: %s \n", request.Header.Get("Referer"), host.Hostname)
			color.Yellow("Location header became: %s ", redirfuckery.Header.Get("Location"))
			if redirfuckery.Header.Get("Location") != resp.Header.Get("Location") && redirfuckery.Header.Get("Location") != "" {
				color.Red("Redirects based on Referer header!\n")
			} else {
				color.Green("Does not redirect based on Referer header")
			}

			return
		} else {
			color.Green("\nHost %s did not redirect\n", host.Hostname)
			return
		}
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
	if resp == nil {
		return 0
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
