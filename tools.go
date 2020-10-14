package tools

import (
	"os/exec"

	"github.com/Epictetus24/GOAT/scan"

	"github.com/fatih/color"
)

//Tool stores the tool arguments, fileid and hostid
type Tool struct {
	Name   string
	Path   string
	Args   []string
	Fileid int
	Hostid int
}

//Toolkit stores a slice of the tools on offer.
type Toolkit struct {
	Toollist []Tool
}

//Toolarmoury iterates through a defined armoury of tools
func Toolarmoury(host scan.Host) {
	var toolkit Toolkit

	var Nikto Tool
	Nikto.Name = "Nikto"
	Nikto.Path = "/usr/local/bin/nikto"
	Nikto.Args = []string{"-host", "hostname", "-output", "filename", "-port", "443"}
	Nikto.Hostid = 1
	Nikto.Fileid = 3
	toolkit.Toollist = append(toolkit.Toollist, Nikto)

	var Nmap Tool
	Nmap.Args = []string{"-sV", "-Pn", "host.co.uk", "-p0-", "-oA", "full_tcp", "-T3", "-vv"}
	Nmap.Name = "nmap"
	Nmap.Path = "/usr/bin/nmap"
	Nmap.Hostid = 2
	Nmap.Fileid = 5
	toolkit.Toollist = append(toolkit.Toollist, Nmap)

	var Testssl Tool
	Testssl.Name = "Testssl"
	Testssl.Args = []string{"/opt/testssl.sh/testssl.sh", "--html", "--log", "hostname"}
	Testssl.Path = "/bin/bash"
	Testssl.Hostid = 3
	toolkit.Toollist = append(toolkit.Toollist, Testssl)

	for i := range toolkit.Toollist {
		tool := toolkit.Toollist[i]
		color.Cyan("\n Running Check %d: %s", (i + 1), tool.Name)
		Toolrun(host, toolkit.Toollist[i])
	}
}

//Toolrun takes a tool.Tool template and runs it.
func Toolrun(host scan.Host, tool Tool) {

	args := tool.Args
	args[tool.Hostid] = host.Hostname

	if tool.Fileid != 0 {
		args[tool.Fileid] = host.Hostname + "_output/" + host.Hostname + "_" + tool.Name
	}

	cmd := tool.Path

	toolrun := exec.Command(cmd, args[0:]...)
	if err := toolrun.Start(); err != nil {
		color.Red("Failed to start %s: %v", tool.Name, err.Error)
		return
	}

	color.Blue("%s running against host %s\n", tool.Name, host.Hostname)

	if err := toolrun.Wait(); err != nil {
		color.Red("%s returned error: %v", tool.Name, err)
	}

	color.Green("%s finished, file for %s saved.\n", tool.Name, host.Hostname)
}
