import os
import subprocess
import sys
import json
import csv
import threading
from argparse import ArgumentParser
import yaml
import ipaddress
import logging
import multiprocessing
from queue import Queue
from queue import Empty

from net_diag.libs.net_utils import get_neighbors
from net_diag.libs.suitecrmsync import SuiteCRMSync, SuiteCRMSyncException
from net_diag.libs.host import Host
from net_diag.libs.scanners.icmp import ICMPScanner
from net_diag.libs.scanners.snmp import SNMPScanner
from net_diag.libs.scanners.trane import TraneTracerSCScanner


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
					if 'icmp' in host.config['scanners']:
						(ICMPScanner(host)).scan()

					if 'snmp' in host.config['scanners']:
						(SNMPScanner(host)).scan()

					if 'trane-tracer-sc' in host.config['scanners']:
						(TraneTracerSCScanner(host)).scan()
					self.queue.put(('neighbors', host))
				elif action == 'neighbors':
					# Secondary scan, (now that the arp cache of the remote devices should be populated)
					if 'snmp' in host.config['scanners'] and host.descr:
						print('Scanning host for neighbors %s' % (host.ip,), file=sys.stderr)
						(SNMPScanner(host)).scan_neighbors()
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
