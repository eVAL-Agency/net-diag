# Network Diagnostics

Collection of network diagnostic scripts, useful for technicians.


## Network Discover (SNMP)

Options:

* --ip (REQUIRED): Starting IP (usually gateway or a core switch)
* --community: SNMP community string (default: public)
* --format: Output format, either "json" or "csv" (default: json)
* --debug: Include to print debug information on stderr
* --single: Only scan a single host (useful for debugging)

Example usage:

```bash
network_discover --ip 10.10.10.1 --community public --format csv > network.csv

# Generates output to stderr (some omitted for brevity)
[1 of 1] - Scanning details for 10.10.10.1
[1 of 1] - Retrieving neighbors from ARP table on 10.10.10.1
[2 of 31] - Scanning details for 1.2.3.4
[3 of 31] - Scanning details for 1.2.3.5
[17 of 31] - Scanning details for 10.10.10.13
[18 of 31] - Scanning details for 10.10.10.14
[19 of 31] - Scanning details for 10.10.10.21
[23 of 31] - Scanning details for 10.10.10.102
[23 of 31] - Retrieving neighbors from ARP table on 10.10.10.102
[24 of 31] - Scanning details for 10.10.10.106
[24 of 31] - Retrieving neighbors from ARP table on 10.10.10.106
[25 of 31] - Scanning details for 10.10.10.120

# Generates CSV file with the following contents
ip,mac,hostname,contact,floor,location,type,manufacturer,model,os_version,descr
10.10.10.1,00:11:22:33:44:55,Unifi-Rack,Charlie Powell,02,Server Room,,,,,Linux eVAL-Rack 4.19.152-ui-alpine #4.19.152 SMP Mon Oct 14 10:40:15 CST 2024 aarch64
1.2.3.4,00:11:22:33:44:56,,,,,,,,,
1.2.3.5,00:11:22:33:44:57,,,,,,,,,
10.10.10.13,00:11:22:33:44:58,,,,,,,,,
10.10.10.14,00:11:22:33:44:59,,,,,,,,,
10.10.10.21,00:11:22:33:44:60,,,,,,,,,
10.10.10.102,00:11:22:33:44:61,US24,,02,Server Room,,,,,"US-24-G1, 7.1.26.15869, Linux 3.6.5"
10.10.10.106,,UBNT,root@localhost,,Unknown,,,,,UAP 4.3.28.11361
10.10.10.120,00:11:22:33:44:61,,,,,,,,,
```


## Network Diagnostic (@todo)

Yet to be reimplemented


## Bundled dependencies

* [Python](https://www.python.org/)
* [python-dateutil](https://pypi.org/project/python-dateutil/)
* [six](https://pypi.org/project/six/)
* [ipcalc](https://pypi.org/project/ipcalc/)
* [icmplib](https://pypi.org/project/icmplib/)
* [dnspython](https://pypi.org/project/dnspython/)
* [pysnmplib](https://pypi.org/project/pysnmplib/)
* [argparse](https://pypi.org/project/argparse/)


## Dev setup

Get the code and setup the initial environment

```bash
git clone git@github.com:cdp1337/net-diag.git
cd net-diag
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
pip3 install -e .[dev]
```

Run the application from source

```bash
source venv/bin/activate
python src/net_diag/network_discover.py --ip 192.168.1.1 --community somestring --format json --debug
```