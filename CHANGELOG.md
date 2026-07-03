## v1.1.2 - 2026-07-03

* Add support for saving discovery data to GLPI

## v1.1.1 - 2026-02-14

* Add support for --dry-run, useful for testing
* Fix bugs related to OpenProject syncing

## v1.1.0 - 2026-02-11

* Add support for publishing reports to OpenProject.

## v1.0.0 - 2025-09-07

* Fix for no DNS providers available
* Fix ping to be more accurate and correct render errors
* Fix spacing on fully-functional terminals
* Fix exiting throwing an exception after compilation
* Fix uncaught exceptions rendering to stderr
* Add a small icon to signify the scan is still active
* Add support in network_discover to use local ARP cache
* Implement Windows support for network_diag
* Add support for publishing scans to Grist

## v0.9.0 - 2025.06.27

* Port network_diag to this project
* Add support for config files for network scanning


## v0.2.6 - 2025.05.07

* Switch github runner to Ubuntu 22.04


## v0.2.5 - 2025.01.29

* Ensure hostname for devices to be synced to SuiteCRM
* Add jetstream DESCR
* Set status to 'active' for devices that are online


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