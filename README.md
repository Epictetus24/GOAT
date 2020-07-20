# gowebscan
Simple Automator for web security tests.

Really basic web scanner that just automates some common tools that are usually deployed at the start of web application test.
Ideally with the aim of saving some time to focus on the more manual testing :) 

Currently it automates the following tools:
* nmap
* whatweb
* gobuster
* nikto
* testssl.sh

It is reliant on your tools being in the same path, so check your tool locations with "which" and see if they match the ones in scan.go. Gobuster also uses SecLists for the raft-small wordlist.

It also now checks for HTTP methods by itself, and will supply a map with the response code for whether or not it was successful.



# Warning
It now only works concurrently for multiple hosts/domain names so it's less Denial of Service triggering, also it won't work if there's an empty newline in the targets file.

# Usage
```sh

gowebscan target.txt

```

Targets file should look either like this:
```
target1.com:192.168.0.1
target2.com:192.168.0.2
```
or:
```
target1.com
target2.com
```
You can also mix and match both above formats, but anything else will cause issues.
