import os
import subprocess
import sys
import json
import csv
import threading
from argparse import ArgumentParser
import yaml
from typing import Union
import re
from mac_vendor_lookup import MacLookup
import socket
import ipaddress
import logging
from datetime import datetime
import multiprocessing
from queue import Queue
from queue import Empty

from net_diag.libs.net_utils import get_neighbors
from net_diag.libs.suitecrmsync import SuiteCRMSync, SuiteCRMSyncException
from net_diag.libs.scanners.icmp import ICMPScanner
from net_diag.libs.scanners.snmp import SNMPScanner


def is_local_ip(ip: str) -> bool:
	"""
	Check if the given IP is a local-only IP

	(currently only supports IPv4 addresses)
	:param ip:
	:return:
	"""
	n_val = int(ipaddress.IPv4Address(ip))
	ranges = (
		# 127.0.0.0 - 127.255.255.255
		(0x7F000000, 0x7FFFFFFF),
		# 169.254.0.0 - 169.254.255.255
		(0xA9FE0000, 0xA9FEFFFF),
		# 192.0.2.0 - 192.0.2.255
		(0xC0000200, 0xC00002FF),
		# 198.51.100.0 - 198.51.100.255
		(0xC6336400, 0xC63364FF),
		# 203.0.113.0 - 203.0.113.255
		(0xCB007100, 0xCB0071FF),
		# 224.0.0.0 - 239.255.255.255
		(0xE0000000, 0xEFFFFFFF),
		# 240.0.0.0 - 255.255.255.254
		(0xF0000000, 0xFFFFFFFF)
	)
	for ip_set in ranges:
		if ip_set[0] <= n_val <= ip_set[1]:
			return True
	return False


class Host:
	"""
	Represents a single host on the network.
	"""

	def __init__(self, ip: str, config: dict, sync=None):
		"""
		Initialize a new Host device to be scanned

		:param ip: IP Address of the device
		:param config: Configuration parameters
		:param sync: Sync object (or None) for syncing this device to a backend
		"""

		self.ip = ip
		"""
		IP address of the device
		:type ip: str
		"""

		self.mac = None
		"""
		MAC address of the device
		:type mac: str|None
		"""

		self.hostname = None
		"""
		Hostname of the device
		:type hostname: str|None
		"""

		self.contact = None
		"""
		Contact information for the device, (usually a person or department responsible for it)
		:type contact: str|None
		"""

		self.floor = None
		"""
		Floor where the device is located, (if applicable)
		:type floor: str|None
		"""

		self.location = None
		"""
		Location where the device is located, (if applicable)
		:type location: str|None
		"""

		self.type = None
		"""
		Device type, (eg: switch, router, server, etc)
		:type type: str|None
		"""

		self.manufacturer = None
		"""
		Device manufacturer, (eg: Cisco, Dell, etc)
		:type manufacturer: str|None
		"""

		self.model = None
		"""
		Device model, (eg: Cisco Catalyst 2960, Dell PowerEdge R740, etc)
		:type model: str|None
		"""

		self.os_version = None
		"""
		Version of operating system
		:type os_version: str|None
		"""

		self.serial = None
		"""
		Serial number of the device, (if available)
		:type serial: str|None
		"""

		self.descr = None
		"""
		SNMP description of the device, (if available)
		:type descr: str|None
		"""

		self.object_id = None
		"""
		SNMP object ID of the device, (if available)
		:type object_id: str|None
		"""

		self.address = None
		"""
		Physical address of the device, (if available)
		:type address: str|None
		"""

		self.city = None
		"""
		City where the device is located, (if available)
		:type city: str|None
		"""

		self.state = None
		"""
		State/Province where the device is located, (if available)
		:type state: str|None
		"""

		self.log_lines = ''
		"""
		Raw log for the discovery of this device, (for debugging purposes)
		"""

		self.reachable = False
		"""
		If this device is reachable on the network, (eg: pingable)
		:type reachable: bool
		"""

		self.ports = None
		"""
		List of network/data ports on the device
		:type ports: dict[str,dict]|None
		"""

		self.config = config
		"""
		Configuration to use for this device, (eg: SNMP community string, scanners to use, etc)
		:type config: dict
		"""

		self.sync = sync
		"""
		Sync handler to use for publishing records, if applicable.
		:type sync: SuiteCRMSync|None
		"""

		self.neighbors = []
		"""
		List of neighbors (IP, MAC) tuples for this device.
		:type neighbors: list[tuple[str, str]]
		"""

		# Set override defaults
		if 'address' in config:
			self.address = config['address']

		if 'city' in config:
			self.city = config['city']

		if 'state' in config:
			self.state = config['state']

	def log(self, msg: str):
		"""
		Log a debug message to the debugger logger and to this device's internal log

		:param msg:
		:return:
		"""
		self.log_lines += '[%s] %s\n' % (datetime.now().isoformat(), msg)
		logging.debug(msg)

	def is_available(self) -> bool:
		"""
		Check if this device is available on the network

		Checks both ping and SNMP, as either could be disabled.
		:return:
		"""
		return self.reachable or self.descr is not None

	def scan(self):
		"""
		Perform a full scan of the device to store all details.
		:return:
		"""

		if 'icmp' in self.config['scanners']:
			(ICMPScanner(self)).scan()

		if 'snmp' in self.config['scanners']:
			(SNMPScanner(self)).scan()

		if self.hostname is None or self.hostname == '':
			try:
				self.log('Hostname not set, trying a socket to resolve')
				self.hostname = socket.gethostbyaddr(self.ip)[0]
				self.log('%s = %s' % (self.ip, self.hostname))
			except socket.herror:
				self.log('socket lookup failed')
				pass

	def scan_neighbors(self):
		"""
		Scan this device for any neighbors it may have.

		This is separate from the initial scan to give hosts an opportunity to populate their ARP cache
		:return:
		"""
		if 'snmp' in self.config['scanners']:
			(SNMPScanner(self)).scan_neighbors()

	def resolve_manufacturer(self):
		"""
		Resolve the manufacturer from the MAC address
		:return:
		"""
		if (self.manufacturer is None or self.manufacturer == '') and self.mac is not None:
			try:
				self.log('Manufacturer not set, trying a MAC lookup to resolve')
				self.manufacturer = MacLookup().lookup(self.mac)
				self.log('%s = %s' % (self.mac, self.manufacturer))
			except Exception:
				self.log('MAC address lookup failed')
				pass

	def sync_to_suitecrm(self):
		"""
		:param sync:
		:raises SuiteCRMSyncException:
		:return:
		"""
		if self.mac is None:
			logging.warning('No MAC address found for SuiteCRM sync on %s' % self.ip)
			return

		# SuiteCRM requires a hostname for devices
		self.ensure_hostname()

		self.log('Searching for devices in SuiteCRM with MAC %s' % self.mac)
		ret = self.sync.find(
			'MSP_Devices',
			{'mac_pri': self.mac, 'mac_sec': self.mac, 'mac_oob': self.mac},
			operator='OR',
			fields=(
				'id',
				'ip_pri',
				'mac_pri',
				'ip_sec',
				'mac_sec',
				'ip_oob',
				'mac_oob',
				'name',
				'loc_room',
				'loc_floor',
				'loc_address',
				'loc_address_city',
				'loc_address_state',
				'manufacturer',
				'model',
				'os_version',
				'type',
				'description',
				'status'
			)
		)
		self.log('Found %s device(s)' % len(ret))

		if len(ret) == 0:
			# No records located, create
			data = self._generate_suitecrm_payload(None)
			self.log('Creating device record for %s: (%s)' % (self.ip, json.dumps(data)))
			self.sync.create('MSP_Devices', data | {'discover_log': self.log_lines})
		elif len(ret) == 1:
			# Update only, (do not overwrite existing data)
			data = self._generate_suitecrm_payload(ret[0])
			if len(data):
				self.log('Syncing device record for %s: %s' % (self.ip, json.dumps(data)))
			else:
				self.log('No data changed for %s' % self.ip)
			self.sync.update('MSP_Devices', ret[0]['id'], data | {'discover_log': self.log_lines})
		else:
			logging.warning('Multiple records found for %s' % self.mac)

	def ensure_hostname(self):
		"""
		Ensure this device has a hostname, (of at least something)

		This is useful because SuiteCRM requires a name for devices
		:return:
		"""
		if self.hostname is None or self.hostname == '':
			self.hostname = self.ip

	def _generate_suitecrm_payload_if_different(self, server_data: Union[dict, None], data: dict, key: str, value: str):
		if value and (server_data is None or server_data[key] != value):
			data[key] = value

	def _generate_suitecrm_payload_if_empty(self, server_data: Union[dict, None], data: dict, key: str, value: str):
		if value and (server_data is None or server_data[key] == ''):
			data[key] = value

	def _generate_suitecrm_payload(self, server_data: Union[dict, None]) -> dict:
		data = {}

		# Fields that are guaranteed to be present; MAC and IP Address
		# Mac determines where the IP gets stored, (primary/secondary/out-of-band)
		mac = self.mac.lower()
		if server_data is not None and server_data['mac_sec'].lower() == mac:
			if server_data['ip_sec'] != self.ip:
				data['ip_sec'] = self.ip
		elif server_data is not None and server_data['mac_oob'].lower() == mac:
			if server_data['ip_oob'] != self.ip:
				data['ip_oob'] = self.ip
		else:
			if server_data is None or server_data['ip_pri'] != self.ip:
				data['ip_pri'] = self.ip

		if server_data is None:
			# Mac gets set only for new records
			# (otherwise it is the primary key used to lookup this record)
			data['mac_pri'] = self.mac

		# Fields that should always override inventory data
		self._generate_suitecrm_payload_if_different(server_data, data, 'loc_address', self.address)
		self._generate_suitecrm_payload_if_different(server_data, data, 'loc_address_city', self.city)
		self._generate_suitecrm_payload_if_different(server_data, data, 'loc_address_state', self.state)
		self._generate_suitecrm_payload_if_different(
			server_data,
			data,
			'status',
			'active' if self.reachable else False
		)

		# Fields that should only be set if they are present in the scan
		# and not already set in the inventory data.
		self._generate_suitecrm_payload_if_empty(server_data, data, 'name', self.hostname)
		self._generate_suitecrm_payload_if_empty(server_data, data, 'loc_room', self.location)
		self._generate_suitecrm_payload_if_empty(server_data, data, 'loc_floor', self.floor)
		self._generate_suitecrm_payload_if_empty(server_data, data, 'manufacturer', self.manufacturer)
		self._generate_suitecrm_payload_if_empty(server_data, data, 'model', self.model)
		self._generate_suitecrm_payload_if_empty(server_data, data, 'serial', self.serial)
		self._generate_suitecrm_payload_if_empty(server_data, data, 'os_version', self.os_version)
		self._generate_suitecrm_payload_if_empty(server_data, data, 'type', self.type)
		self._generate_suitecrm_payload_if_empty(server_data, data, 'description', self.descr)
		self._generate_suitecrm_payload_if_empty(server_data, data, 'name', self.hostname)

		return data

	def set_location(self, val: str):
		"""
		Check if there is a floor indication ("FL...") in the location and separate that as the floor attribute
		:param val:
		:return:
		"""
		if val is None:
			return

		floor_match = re.match(r'^FL([0-9A-Z]+) ', val)
		if floor_match:
			self.floor = floor_match.group(1)
			self.location = val[len(self.floor) + 2:].strip()
		else:
			self.location = val

	def __repr__(self) -> str:
		return f'<Host ip:{self.ip} mac:{self.mac} hostname:{self.hostname} descr:{self.descr}>'

	def to_dict(self) -> dict:
		data = {
			'ip': self.ip,
			'mac': self.mac,
			'hostname': self.hostname,
			'contact': self.contact,
			'floor': self.floor,
			'location': self.location,
			'type': self.type,
			'manufacturer': self.manufacturer,
			'model': self.model,
			'serial': self.serial,
			'ports': self.ports,
			'os_version': self.os_version,
			'descr': self.descr,
			'address': self.address,
			'city': self.city,
			'state': self.state
		}

		if 'fields' in self.config and self.config['fields'] is not None:
			# Only include the fields specified in the list
			data = {k: v for k, v in data.items() if k in self.config['fields']}

		return data


class Application:
	def __init__(self):
		self.queue = Queue()
		"""
		Queue of worker threads to perform the actual scan
		"""

		self.host_queue = Queue()
		"""
		Queue of results based on the threaded scan
		"""

		self.hosts = []
		"""
		List of devices located and scanned
		:param hosts: Host[]
		"""

		self.host_map = {}
		"""
		Map of IP address to the Host index in the `hosts` list.
		"""

		self.host_config = {}
		"""
		Configuration for individual hosts set from the config file.
		Useful to define credentials or scanners on a per-device basis.
		"""

		self.config = {}
		"""
		Options for this scan as stored from the configuration file or command line.
		:param config: dict
		"""

		self.defaults = {
			'community': 'public',
			'scanners': ['icmp', 'snmp'],
			'exclude': [],
			'format': 'json',
			'fields': None,
			'sync': None,
		}
		"""
		Default configuration options, extendable with the `default` parameter in config files.
		"""

		self.globals = {}
		"""
		Global-level configuration options which override all scans, generally set from command line arguments
		"""

		self.targets = []
		"""
		List of targets to scan along with their configuration data, usually set from the config file.
		"""

	def run(self):
		self.setup()

		try:
			# Initialize the process threads
			thread_count = min(self.queue.qsize(), multiprocessing.cpu_count() * 2)
			print('Starting scan with %s threads' % thread_count, file=sys.stderr)
			threads = []
			for n in range(thread_count):
				t = threading.Thread(target=self.worker)
				threads.append(t)
				t.start()

			# Wait for all threads to finish
			for thread in threads:
				thread.join()
		except KeyboardInterrupt:
			print('CTRL+C caught, clearing queue, please wait a moment', file=sys.stderr)
			# Manually clear the queue by retrieving all items and just dropping them
			while not self.queue.empty():
				try:
					self.queue.get(False)
				except Empty:
					pass
			exit(1)

		# Move all hosts discovered from the host queue into a standard list
		hosts = list(self.host_queue.queue)
		for host in hosts:
			if host.is_available() and host.ip not in self.config['exclude']:
				self.host_map[host.ip] = len(self.hosts)
				self.hosts.append(host)

		self.resolve_macs()

		# Perform any operations / lookups that require a MAC address
		for host in self.hosts:
			host.resolve_manufacturer()

		self.finalize_results()

	def setup(self):
		"""
		Setup the application and prep everything needed to run the scan
		:return:
		"""
		self._setup_load_arguments()
		self._setup_load_targets()

	def _setup_parser(self) -> ArgumentParser:
		parser = ArgumentParser(
			prog='network_discover.py',
			description='''Discover network devices using SNMP.
Refer to https://github.com/cdp1337/net-diag for sourcecode and full documentation.'''
		)

		parser.add_argument('--net', help='Network to scan eg: 192.168.0.0/24')
		parser.add_argument('--config', help='Configuration file to use for this scan, see (@todo) for more information')
		parser.add_argument('-c', '--community', help='SNMP community string to use')
		parser.add_argument('--format', choices=('json', 'csv', 'suitecrm'), help='Output format')
		parser.add_argument('--debug', action='store_true', help='Enable debug output')
		parser.add_argument('--crm-url', help='URL of the SuiteCRM instance')
		parser.add_argument('--crm-client-id', help='Client ID for the SuiteCRM instance')
		parser.add_argument('--crm-client-secret', help='Client secret for the SuiteCRM instance')
		parser.add_argument('--address', help='Optional address for this scan (for reporting)')
		parser.add_argument('--city', help='Optional city for this scan (for reporting)')
		parser.add_argument('--state', help='Optional state for this scan (for reporting)')
		parser.add_argument('--exclude', help='List of IPs to exclude from overall report, comma-separated')
		parser.add_argument('--exclude-self', action='store_true', help='Set to exclude the host running the scan')
		parser.add_argument(
			'--fields',
			help='''Comma-separated list of fields to include in the output, defaults to all fields if not defined.
			Available fields are: ip, mac, hostname, contact, floor, location, type, manufacturer, model,
			os_version, descr, address, city, state, ports'''
		)

		return parser

	def _setup_load_arguments(self):
		cli_args = self._setup_parser().parse_args()

		if cli_args.debug:
			logging.basicConfig(level=logging.DEBUG)

		if cli_args.config is None and cli_args.net is None:
			print('Required run parameters missing, please use --net or --config', file=sys.stderr)
			sys.exit(1)

		if cli_args.config:
			self._setup_load_config(cli_args)

		# Parameters that can be set from the command line get defined on the global list to take priority
		if cli_args.net:
			# If a network was specified on the command line, override the config file
			self.targets = [{
				'net': cli_args.net,
			}]

		if cli_args.community:
			self.globals['community'] = cli_args.community

		if cli_args.exclude:
			self.globals['exclude'] = cli_args.exclude.split(',')

		if cli_args.address:
			self.globals['address'] = cli_args.address

		if cli_args.city:
			self.globals['city'] = cli_args.city

		if cli_args.state:
			self.globals['state'] = cli_args.state

		if cli_args.format:
			self.globals['format'] = cli_args.format

		if cli_args.fields:
			self.globals['fields'] = cli_args.fields.split(',')

		if cli_args.exclude_self:
			# Include local IPs to be excluded
			# This is useful for dedicated scanning devices implanted in a client location
			# If the user defined --exclude=..., append to that list, otherwise
			# append to the default so as to not overwrite any configuration.
			local_ips = self.get_local_ips()
			if 'exclude' in self.globals:
				self.globals['exclude'] += local_ips
			else:
				if 'exclude' not in self.defaults:
					self.defaults['exclude'] = []
				self.defaults['exclude'] += local_ips
			logging.debug('Excluding local IPs: %s' % ', '.join(local_ips))

		# Store all options
		self.config = self.defaults | self.globals

	def _setup_load_config(self, cli_args):
		# Allow user to specify a config file to load, this provides the ability to scan multiple networks at once.
		if not os.path.exists(cli_args.config):
			print('Config file %s does not exist' % cli_args.config, file=sys.stderr)
			sys.exit(1)
		with open(cli_args.config, 'r') as f:
			data = yaml.safe_load(f)
			if 'default' in data:
				self.defaults |= data['default']
			if 'targets' in data:
				self.targets = data['targets']
			if 'hosts' in data:
				# Load host-specific configuration, (eg: credentials)
				for host in data['hosts']:
					if 'ip' not in host:
						print('Host configuration missing IP address, skipping', file=sys.stderr)
						continue
					self.host_config[host['ip']] = host

	def _setup_load_targets(self):
		# Build the queue of devices to scan
		for target in self.targets:
			if 'net' not in target:
				print('No network specified for scan, skipping', file=sys.stderr)
				continue

			# Compile the options for this network scan
			# 'default' options should be default, followed by any network-specific options.
			# 'global' options are usually set from the command line and should override everything.
			config = self.defaults | target | self.globals
			sync = None

			if config['format'] == 'suitecrm':
				sync = SuiteCRMSync(config['crm_url'], config['crm_client_id'], config['crm_client_secret'])
				try:
					# Perform a connection to check credentials prior to scanning for hosts
					sync.get_token()
				except SuiteCRMSyncException as e:
					print('Failed to connect to SuiteCRM: %s' % e, file=sys.stderr)
					sys.exit(1)

			# Add all hosts from this requested network
			for ip in ipaddress.ip_network(target['net']).hosts():
				host_ip = str(ip)
				if host_ip in self.host_config:
					# Use a host-specific config, as defined in the config file
					h = Host(host_ip, self.defaults | target | self.host_config[host_ip] | self.globals, sync)
				else:
					# Use target-shared configuration
					h = Host(host_ip, config, sync)
				self.queue.put(('scan', h))

	def worker(self):
		"""
		Worker thread to handle the scanning of a single device.

		:return:
		"""
		while True:
			try:
				action, host = self.queue.get(False, 0.5)
				if action == 'scan':
					# Initial scan of the device
					print('Scanning host %s' % (host.ip,), file=sys.stderr)
					host.scan()
					self.queue.put(('neighbors', host))
				elif action == 'neighbors':
					# Secondary scan, (now that the arp cache of the remote devices should be populated)
					if host.descr:
						print('Scanning host for neighbors %s' % (host.ip,), file=sys.stderr)
						host.scan_neighbors()
					self.host_queue.put(host)
				else:
					logging.error('Unsupported action %s' % action)
			except Empty:
				# No more tasks left in the queue
				print('Scanning thread finished', file=sys.stderr)
				return
			except ValueError:
				# Usually occurs because user hit CTRL+C
				print('Thread closing', file=sys.stderr)
				return

	def resolve_macs(self):
		# Grab the monitoring server's ARP cache to resolve any local devices.
		# This only works for devices on the same layer 2 network, (ie: same subnet)
		local_arp = get_neighbors()
		for data in local_arp:
			if data['ip'] in self.host_map:
				# This is a device we are scanning, update its MAC if required
				i = self.host_map[data['ip']]
				if self.hosts[i].mac is None:
					self.hosts[i].mac = data['mac']
					self.hosts[i].log('Resolved MAC from local ARP cache')

		# Resolve any located MAC from the remote arp table
		# This is important because hosts which do not have SNMP enabled should still have the MAC available.
		for host in self.hosts:
			if host.neighbors is not None:
				for ip, mac in host.neighbors:
					if ip in self.host_map:
						# This IP is one of the devices we are scanning, update its MAC if required
						i = self.host_map[ip]
						if self.hosts[i].mac is None:
							self.hosts[i].mac = mac
							self.hosts[i].log('Resolved MAC from ARP cache on %s' % host.ip)

	def finalize_results(self):
		if self.config['format'] == 'json':
			print(json.dumps([h.to_dict() for h in self.hosts], indent=2))
		elif self.config['format'] == 'csv':
			# Grab a new host just to retrieve the dictionary keys on the object
			generic = Host('test', self.config, None)
			# Set the header (and fields)
			writer = csv.DictWriter(sys.stdout, fieldnames=list(generic.to_dict().keys()))
			writer.writeheader()
			for h in self.hosts:
				writer.writerow(h.to_dict())
		elif self.config['format'] == 'suitecrm':
			for h in self.hosts:
				try:
					print('Syncing %s to SuiteCRM' % h.ip)
					h.sync_to_suitecrm()
				except SuiteCRMSyncException as e:
					print('Failed to sync %s to SuiteCRM: %s' % (h.ip, e), file=sys.stderr)
		else:
			print('Unknown format requested', file=sys.stderr)

	def get_local_ips(self) -> list:
		# Get IP and MAC address for this device
		process = subprocess.run(['ip', '-j', 'address'], stdout=subprocess.PIPE)
		ifaces = json.loads(process.stdout.decode().strip())
		ips = []
		for iface in ifaces:
			if iface['operstate'] == 'DOWN':
				continue

			if 'LOOPBACK' in iface['flags']:
				# Skip loopback interfaces
				continue

			if 'POINTOPOINT' in iface['flags']:
				# Skip VPNs
				continue

			if len(iface['addr_info']) == 0:
				# Skip interfaces with no IP set
				continue

			ips.append(iface['addr_info'][0]['local'])
		return ips


def run():

	app = Application()
	app.run()


if __name__ == '__main__':
	# Allow this script to be run standalone
	run()
