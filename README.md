# GOAT - GO Application Tester
Simple Automator for web security tests.

Really basic web scanner that just automates some common tools that are usually deployed at the start of web application test.
Ideally with the aim of saving some time to focus on the more manual testing :) 

Currently it automates the following tools:
* nmap
* nikto
* testssl.sh

Internally it checks the following:

* Which Security headers are returned
* Any headers which have useful info (Server, X-Powered-By, will add more as I go)
* Methods which are allowed - but it only checks this on "/" so you will need to still test this elsewhere in the application.
* If a website redirects "/" for example google does this, then it will attempt to modify the host and referer headers and check if the redirect is poisoned.

![GOAT Example](https://github.com/Epictetus24/GOAT/blob/master/GOAT-Example.png "What it currently looks like")

# Warning
It now only works concurrently for multiple hosts/domain names so it's less Denial of Servicey, also it won't work if there's an empty newline in the targets file.
Tool Paths are hardcoded, you may need to modify the path in tools.go to suit your system. 

# Usage
```sh

GOAT target.txt

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
