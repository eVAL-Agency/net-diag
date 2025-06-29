# Network Diagnostics

Collection of network diagnostic scripts, useful for technicians.


## Network Discover (SNMP)

Scan a network for hosts and host details.
Since this operates via SNMP, it can provide MAC details over a layer-3 network, (ie: a VPN).

### Options

* --net: Single network to scan, in CIDR notation
* --config: Configuration file to use for this scan
* --community: SNMP community string (default: public)
* --format: Output format, either "json", "csv", or "suitecrm" (default: json)
* --debug: Include to print debug information on stderr
* --crm-url: URL of the SuiteCRM instance
* --crm-client-id: Client ID for the SuiteCRM instance
* --crm-client-secret: Client secret for the SuiteCRM instance
* --address: Optional physical address to include in the report
* --city: Optional city to include in the report
* --state: Optional state to include in the report
* --exclude: Optional list of IP addresses to exclude from the report
* --exclude-self: Optional flag to exclude the host running the script from the report
* --fields: Comma-separated list of fields to include in the output

### Fields provided

* ip
* mac
* hostname
* contact
* floor
* location
* type
* manufacturer
* model
* os_version
* descr
* address
* city
* state
* ports

These fields can be modified with the `--fields` option to include or exclude specific fields from the output.


### Configuration File

For complex networks, a config file can be utilized to scan multiple networks at once.
This can be beneficial when switches with the ARP tables are on a separate network from hosts.

An example configuration file with 192.168.0.0/24 containing the network devices
and 192.168.1.0/24 containing workstations:

Default contains the parameters to apply to all targets, and each individual target can override these parameters.

192.168.0.0 network has devices which support SNMP and ICMP, whereas devices on 192.168.1.0
has devices which only support ICMP.

```yaml
default:
  community: snmp-public-pass
  address: 123 Here
  city: Columbus
  state: OH
  format: json
  exclude:
    - 192.168.1.1
targets:
  - net: 192.168.0.0/24
  - net: 192.168.1.0/24
    scanners:
      - icmp
```

Any command line parameter can be specified in both `default` and individual `targets` declarations.
(For parameters which contain a `-`, use `_` instead, ie: `--crm-client-id` becomes `crm_client_id`.)

### Scanners

At the moment, only `ICMP` and `SNMP` scanners are supported. 
By default, both are utilized but that behaviour can be modified via a config file.

### Examples

#### Save report to CSV

Simple usage, write scan results to a local file

```bash
network_discover --net 10.10.10.0/24 --community public --format csv > network.csv

# Generates output to stderr (some omitted for brevity)
Scanning host 10.10.10.1
Scanning host 10.10.10.2
Scanning host 10.10.10.3
Scanning host 10.10.10.4
Scanning host 10.10.10.5
Scanning host for neighbors 10.10.10.1
Scanning host for neighbors 10.10.10.2

# Generates CSV file with the following contents
ip,mac,hostname,contact,floor,location,type,manufacturer,model,os_version,descr,address,city,state
10.10.10.1,00:11:22:33:44:55,Unifi-Rack,Charlie Powell,02,Server Room,,,,,Linux eVAL-Rack 4.19.152-ui-alpine #4.19.152 SMP Mon Oct 14 10:40:15 CST 2024 aarch64,,,
1.2.3.4,00:11:22:33:44:56,,,,,,,,,,,,
1.2.3.5,00:11:22:33:44:57,,,,,,,,,,,,
10.10.10.13,00:11:22:33:44:58,,,,,,,,,,,,,
10.10.10.14,00:11:22:33:44:59,,,,,,,,,,,,,
10.10.10.21,00:11:22:33:44:60,,,,,,,,,,,,,
10.10.10.102,00:11:22:33:44:61,US24,,02,Server Room,,,,,"US-24-G1, 7.1.26.15869, Linux 3.6.5",,,
10.10.10.106,,UBNT,root@localhost,,Unknown,,,,,UAP 4.3.28.11361,,,
10.10.10.120,00:11:22:33:44:61,,,,,,,,,,,,
```

#### Publish discovery data to SuiteCRM

If using the MSP plugin for SuiteCRM or another compatible library, 
using `--format suitecrm` can sync data directly to the device database.

@todo Publish the SuiteCRM MSP plugin once it's more polished.  Contact me if you want an early alpha version.

This functionality requires oauth to be configured for your instance and a client ID/secret to be provided.

Required roles are:

* MSP_Devices read/list
* MSP_Devices edit
* MSP_Devices create

```bash
network_discover --net=192.168.0.0/24 --format=suitecrm --crm-url=crm.yourdomain.tld --crm-client-id=123456-1234-1234-123456789 --crm-client-secret=oauth_secret_key -c public

# Example output
Scanning host 192.168.0.100
Scanning host 192.168.0.143
Scanning host 192.168.0.150
Scanning host 192.168.0.151
Scanning host 192.168.0.152
...
Syncing 192.168.0.73 to SuiteCRM
Syncing 192.168.0.75 to SuiteCRM
Syncing 192.168.0.76 to SuiteCRM
Syncing 192.168.0.77 to SuiteCRM
```

#### Exclude specific IP addresses from report

Sometimes, (notably with gateways that have multiple IP addresses on different subnets), 
you may want to exclude specific hosts from the report.  (They will still be used to generate data for other hosts.)

```bash
network_discover --net=192.168.0.0/24 --exclude=192.168.0.1,192.168.0.2
```

The reason why this is beneficial: a gateway may have an IP on its main subnet and on a guest network.
For logging, you do not care about the interface on the guest, as it's only there for routing purposes for guests.

This will allow you to scan that network using the gateway as a pivot point, but will ignore it when publishing results.


## Network Diagnostic

Provides a command line interface to gather network diagnostics from a host device,
useful for diagnosing network and infrastructure issues.

### Basic Usage

Running with no options will prompt for which interface to monitor:

```
Please select a network interface to diagnose:

1: enp6s0 (up,broadcast,running,multicast)
2: docker0 (up,broadcast,multicast)
3: VPN_Wireguard (up,pointopoint,running,noarp)
4: wlx6c5ab06d580e (broadcast,multicast)

Enter the number of the interface you want to diagnose: 
```

Or specify `-i (iface)` to specify the interface directly when running the command.

### Example Output

```
Network Diagnostics

Interface           ️✅  enp6s0
Type                ️✅  ethernet
Status              ️✅  UP
Speed               ️✅  1.0 Gbps
Duplex              ️✅  Full Duplex
MTU                 ️✅  1500
LLDP Peer           ️✅  US-8-60W - Port 4 [12:34:56:78:90:ab:cd] (US-8-60W, 7.0.50.15613, Linux 3.6.5)
IP Address          ️✅  10.200.0.227/24
Routes              ️✅  Default gateway 10.200.0.1, Direct access to 10.200.0.0/24
Nameservers         ️✅  10.200.0.3
Domain Name         ️✅  house.local
Neighbors           ️✅  6 visible devices
WAN IP              ️✅  1.2.3.4
Internet Status     ️✅  Connected
Latency             ️✅  50.17 ms
DNS Resolution      ️✅  up.eval.bz -> 159.89.55.61
```

This UI is refreshed automatically every 2 seconds for near real-time updates.

Wifi interfaces will show additional information, such as signal strength, noise, and channel.

### JSON Support

Specify `--json` as an argument to perform a single iteration of diagnostics and output the results in JSON format.

### Threads

By default on Linux, the diagnostics will run as a background thread to provide real-time updates.

This can be disabled by specifying `--no-threads`.

**Windows**: Threading is not supported on Windows, so the diagnostics will always run in a single thread.

## Bundled dependencies

* [Python](https://www.python.org/)
* [python-dateutil](https://pypi.org/project/python-dateutil/)
* [six](https://pypi.org/project/six/)
* [ipcalc](https://pypi.org/project/ipcalc/)
* [icmplib](https://pypi.org/project/icmplib/)
* [dnspython](https://pypi.org/project/dnspython/)
* [pysnmplib](https://pypi.org/project/pysnmplib/)
* [argparse](https://pypi.org/project/argparse/)
* [mac-vendor-lookup](https://pypi.org/project/mac-vendor-lookup/)


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

Get the code running on Windows

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
git clone git@github.com:cdp1337/net-diag.git
cd net-diag
python -m venv venv
& venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip3 install -e .[dev]
python -m pip install windows-curses
```

Run the application from source

```bash
source venv/bin/activate
python src/net_diag/network_discover.py --ip 192.168.1.1 --community somestring --format json --debug
```


## Debugging

The use of the `--debug` flag will print all details from lookups.
Use this flag, (possibly along with `--single` to target the specific IP), when providing feedback
for data lookups.

Example:

```bash
python src/net_diag/network_discover.py --ip 192.168.253.100 --community somepass --format csv --single --debug

# Printed to stderr:
[1 of 1] - Scanning details for 192.168.253.100
[DEBUG] Scanning for DESCR - 1.3.6.1.2.1.1.1.0
[DEBUG] 1.3.6.1.2.1.1.1.0 = UAP-AC-Pro-Gen2 6.6.77.15402
[DEBUG] Scanning for MAC - 1.3.6.1.2.1.2.2.1.6
[DEBUG] 1.3.6.1.2.1.2.2.1.6.1 = 
[DEBUG] 1.3.6.1.2.1.2.2.1.6.2 = 74:ac:b9:bc:41:fa
[DEBUG] 1.3.6.1.2.1.2.2.1.6.3 = 
[DEBUG] 1.3.6.1.2.1.2.2.1.6.4 = 74:ac:b9:bd:41:fa
[DEBUG] 1.3.6.1.2.1.2.2.1.6.5 = 74:ac:b9:be:41:fa
[DEBUG] No SNMP response received before timeout
[DEBUG] Scanning for hostname - 1.3.6.1.2.1.1.5.0
[DEBUG] 1.3.6.1.2.1.1.5.0 = FL01WifiLobby
[DEBUG] Scanning for contact - 1.3.6.1.2.1.1.4.0
[DEBUG] 1.3.6.1.2.1.1.4.0 = Charlie Powell
[DEBUG] Scanning for firmware version - 1.3.6.1.2.1.16.19.2.0
[DEBUG] 1.3.6.1.2.1.16.19.2.0 = No Such Object currently exists at this OID
[DEBUG] Scanning for model - 1.3.6.1.2.1.16.19.3.0
[DEBUG] 1.3.6.1.2.1.16.19.3.0 = No Such Object currently exists at this OID
[DEBUG] Scanning for location - 1.3.6.1.2.1.1.6.0
[DEBUG] 1.3.6.1.2.1.1.6.0 = FL01 Lobby

# Printed to stdout:
ip,mac,hostname,contact,floor,location,type,manufacturer,model,os_version,descr
192.168.253.100,74:ac:b9:bc:41:fa,FL01WifiLobby,Charlie Powell,01,Lobby,,Ubiquiti Networks Inc.,,,UAP-AC-Pro-Gen2 6.6.77.15402
```