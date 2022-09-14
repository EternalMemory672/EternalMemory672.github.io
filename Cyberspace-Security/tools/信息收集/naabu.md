## naabu
#信息收集 
```
Usage:
  ./naabu [flags]

INPUT:
   -host string[]              hosts to scan ports for (comma-separated)
   -list, -l string            list of hosts to scan ports (file)
   -exclude-hosts, -eh string  hosts to exclude from the scan (comma-separated)
   -exclude-file, -ef string   list of hosts to exclude from scan (file)

PORT:
   -port, -p string            ports to scan (80,443, 100-200)
   -top-ports, -tp string      top ports to scan (default 100)
   -exclude-ports, -ep string  ports to exclude from scan (comma-separated)
   -ports-file, -pf string     list of ports to scan (file)
   -exclude-cdn, -ec           skip full port scans for CDN's (only checks for 80,443)
   -display-cdn, -cdn          display cdn in use

RATE-LIMIT:
   -c int     general internal worker threads (default 25)
   -rate int  packets to send per second (default 1000)

OUTPUT:
   -o, -output string  file to write output to (optional)
   -json               write output in JSON lines format
   -csv                write output in csv format

CONFIGURATION:
   -scan-all-ips, -sa                  scan all the IP's associated with DNS record
   -ip-version, -iv string[]           ip version to scan of hostname (4,6) - (default 4)
   -scan-type, -s string               type of port scan (SYN/CONNECT) (default "s")
   -source-ip string                   source ip and port (x.x.x.x:yyy)
   -interface-list, -il                list available interfaces and public ip
   -interface, -i string               network Interface to use for port scan
   -nmap                               invoke nmap scan on targets (nmap must be installed) - Deprecated
   -nmap-cli string                    nmap command to run on found results (example: -nmap-cli 'nmap -sV')
   -r string                           list of custom resolver dns resolution (comma separated or from file)
   -proxy string                       socks5 proxy (ip[:port] / fqdn[:port]
   -proxy-auth string                  socks5 proxy authentication (username:password)
   -resume                             resume scan using resume.cfg
   -stream                             stream mode (disables resume, nmap, verify, retries, shuffling, etc)
   -passive                            display passive open ports using shodan internetdb api
   -irt, -input-read-timeout duration  timeout on input read (default 3m0s)
   -no-stdin                           Disable Stdin processing

HOST-DISCOVERY:
   -sn, -host-discovery           Run Host Discovery scan
   -ps, -probe-tcp-syn string[]   TCP SYN Ping (host discovery needs to be enabled)
   -pa, -probe-tcp-ack string[]   TCP ACK Ping (host discovery needs to be enabled)
   -pe, -probe-icmp-echo          ICMP echo request Ping (host discovery needs to be enabled)
   -pp, -probe-icmp-timestamp     ICMP timestamp request Ping (host discovery needs to be enabled)
   -pm, -probe-icmp-address-mask  ICMP address mask request Ping (host discovery needs to be enabled)
   -arp, -arp-ping                ARP ping (host discovery needs to be enabled)
   -nd, -nd-ping                  IPv6 Neighbor Discovery (host discovery needs to be enabled)

OPTIMIZATION:
   -retries int       number of retries for the port scan (default 3)
   -timeout int       millisecond to wait before timing out (default 1000)
   -warm-up-time int  time in seconds between scan phases (default 2)
   -ping              ping probes for verification of host
   -verify            validate the ports again with TCP verification

DEBUG:
   -health-check, -hc        run diagnostic check up
   -debug                    display debugging information
   -verbose, -v              display verbose output
   -no-color, -nc            disable colors in CLI output
   -silent                   display only results in output
   -version                  display version of naabu
   -stats                    display stats of the running scan
   -si, -stats-interval int  number of seconds to wait between showing a statistics update (default 5)
```