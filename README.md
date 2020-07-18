# gowebscan
Simple Automator for web security tests.

Really basic web scanner that just automates some common tools that are usually deployed at the start of web application test.
Ideally with the aim of saving some time to focus on the more manual testing :) 

# Warning
Running this many tools concurrently against a host might be a bit of a DOS on both the target and your cpu...

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
