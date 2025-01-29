## v0.2.4 - 2025.01.28

* Add --exclude-self to list of options


## v0.2.3 - 2025.01.27

* Fix MAC to Manufacturer scanning
* Scale thread count to match host count (for /32 scanning)


## v0.2.2 - 2025.01.24

* Switch Queue library
* Increase number of threads by 1 (to match cpu threads)
* Raspberry pi support (manual build step for now)


## v0.2.0 - 2025.01.24

Multithreading support for SNMP scanning utility

* Add MAC to Manufacturer lookup via [Johann Bauer's mac-vendor-lookup](https://github.com/bauerj/mac_vendor_lookup)
* Add hostname lookup via socket check when not available from SNMP
* Add OS-level ping to check host connectivity and to seed remote ARP caches
* Reorganize libraries into individual files to clean up main application
* Implement [standardized logging library for debug](https://docs.python.org/3/library/logging.html)
* Add support to push records to SuiteCRM
* Add check to skip local-only/loopback IP addresses from devices
* Add address data, (manually provided only), to report output
* Add device scan logging to upload data for SuiteCRM
* Add better support for SNMP DESCR field parsing, (still need more raw data for wider device support)
* Add multithreading support for faster scanning


## v0.0.6 - 2024.12.18

* Disabled network diagnostic script (until it gets rewritten)
* Add SNMP Network Discovery script