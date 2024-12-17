Early project, not quite ready for production yet.

network_discover

Options:

* --ip (REQUIRED): Starting IP (usually gateway or a core switch)
* --community: SNMP community string (default: public)
* --format: Output format, either "json" or "csv" (default: json)
* --debug: Include to print debug information on stderr
* --single: Only scan a single host (useful for debugging)

Example usage:

```bash
network_discover --ip 192.168.0.1 --format csv > network.csv
```
