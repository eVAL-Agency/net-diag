import os
import socket
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
from mac_vendor_lookup import MacLookup
from urllib.error import HTTPError

from net_diag.libs.net_utils import get_neighbors
from net_diag.libs.host import Host
from net_diag.libs.scanners.icmp import ICMPScanner
from net_diag.libs.scanners.snmp import SNMPScanner
from net_diag.libs.scanners.http import HTTPScanner


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
		List of devices located and scanned (indexed by their IP address).
		:param hosts: dict[str, Host]
		"""

		self.hosts_by_ip = {}
		"""
		List of devices located and scanned (indexed by their IP address).
		:param hosts: dict[str, Host]
		"""

		self.hosts_by_mac = {}
		"""
		List of devices located and scanned (indexed by their MAC address).
		:param hosts: dict[str, Host]
		"""

		self.host_config = {}
		"""
		Configuration for individual hosts set from the config file.
		Useful to define credentials or scanners on a per-device basis.
		"""

		self.net_config = {}
		"""
		Configuration for a group of hosts set from the config file.
		Useful to define scanning policies for an entire network
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
			thread_count = multiprocessing.cpu_count() * 12
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

		# Perform all the local work for hosts, in the primary thread.
		print('All discovery and scanning completed', file=sys.stderr)

		print('Merging hosts...', file=sys.stderr)
		self._merge_hosts()

		print('Resolving MAC addresses...', file=sys.stderr)
		self._resolve_macs()

		print('Resolving hostnames...', file=sys.stderr)
		self._resolve_hostnames()

		print('Resolving manufacturers...', file=sys.stderr)
		self._resolve_manufacturers()

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
		parser.add_argument('--config', help='Configuration file to use for this scan')
		parser.add_argument('-c', '--community', help='SNMP community string to use')
		parser.add_argument('--format', choices=('json', 'csv', 'grist', 'glpi'), help='Output format')
		parser.add_argument('--debug', action='store_true', help='Enable debug output')
		parser.add_argument(
			'--dry-run',
			action='store_true',
			help='Perform a scan without syncing to any external systems, useful for testing and debugging'
		)
		parser.add_argument('--grist-url', help='URL of the Grist instance')
		parser.add_argument('--grist-account', help='Account token for discovered devices')
		parser.add_argument('--glpi-url', help='URL of GLPI instance to push results to')
		parser.add_argument('--glpi-token', help='Token for the user in GLPI to authenticate with')
		parser.add_argument('--glpi-tag', help='Set a specific tag for scan results')
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
			logging.error('Required run parameters missing, please use --net or --config')
			sys.exit(1)

		if cli_args.config:
			self._setup_load_config(cli_args)

		# Parameters that can be set from the command line get defined on the global list to take priority
		if cli_args.net:
			# If a network was specified on the command line, override the config file
			self.targets = [cli_args.net]

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

		if cli_args.grist_url:
			self.globals['grist_url'] = cli_args.grist_url

		if cli_args.grist_account:
			self.globals['grist_account'] = cli_args.grist_account

		if cli_args.glpi_url:
			self.globals['glpi_url'] = cli_args.glpi_url

		if cli_args.glpi_token:
			self.globals['glpi_token'] = cli_args.glpi_token

		if cli_args.glpi_tag:
			self.globals['glpi_tag'] = cli_args.glpi_tag

		if cli_args.dry_run:
			logging.info('Dry run, no output will be written')
			self.globals['dry_run'] = True
		else:
			self.globals['dry_run'] = False

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

		# validate format before running the application
		if self.config['format'] not in ['json', 'csv', 'glpi', 'grist']:
			logging.error('Invalid format requested!')
			sys.exit(1)

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
			if 'override' in data:
				for override in data['override']:
					if 'format' in override:
						logging.error('format is not valid within override!')
						sys.exit(1)

					if 'ip' in override:
						# Single host override
						self.host_config[override['ip']] = override
					elif 'net' in override:
						# Entire network override
						self.net_config[override['net']] = override
					else:
						logging.warning('Override defined without ip or net!')

	def _setup_load_targets(self):
		# Build the queue of devices to scan
		# Pre-compile subnet strings into ipaddress objects ONCE before the loop starts
		compiled_net_configs = [
			(ipaddress.IPv4Network(net_ip), net_data)
			for net_ip, net_data in self.net_config.items()
		]

		for target in self.targets:
			# Extract each target to the list of actual hosts within that range.
			# For /32 networks, this will resolve to a single host and
			# other networks will resolve to the host IPs within that range.
			hosts = ipaddress.ip_network(target).hosts()
			for ip in hosts:
				# Compile the options for this network scan
				# 'default' options should be default, followed by any network-specific options.
				# 'global' options are usually set from the command line and should override everything.
				host_ip = str(ip)
				host_config = self.host_config[host_ip] if host_ip in self.host_config else {}
				net_config = {}
				for net, net_data in compiled_net_configs:
					if ip in net:
						net_config = net_data
				config = self.defaults | net_config | host_config | self.globals

				# Do some basic pre-run checks
				if config['format'] == 'grist':
					if 'grist_url' not in config or 'grist_account' not in config:
						logging.error('Grist format requires --grist-url and --grist-account to be defined')
						sys.exit(1)
				elif config['format'] == 'glpi':
					if 'glpi_url' not in config:
						logging.error('GLPI format requires --glpi-url to be defined')
						sys.exit(1)
				h = Host(host_ip, config)
				self.queue.put(('discover', h))

	def worker(self):
		"""
		Worker thread to handle the scanning of a single device.

		:return:
		"""

		SKIP = "\033[2m"
		GREEN = "\033[92m"
		RED = "\033[91m"
		RESET = "\033[0m"

		while True:
			try:
				action, host = self.queue.get(False, 0.5)
				if action == 'discover':
					# Initial discovery to generate a list of valid targets
					# This first scan uses the configuration to determine if a scanner should be used.
					# This discovery is meant to be very fast and just confirm if the target is accessible.
					results = []
					if 'icmp' in host.config['scanners']:
						if ICMPScanner.discover(host):
							results.append(f'[ {GREEN}✓ ICMP{RESET} ]')
						else:
							results.append(f'[ {RED}✗ ICMP{RESET} ]')
					else:
						results.append(f'[ {SKIP}- ICMP{RESET} ]')

					if 'snmp' in host.config['scanners']:
						if SNMPScanner.discover(host):
							results.append(f'[ {GREEN}✓ SNMP{RESET} ]')
						else:
							results.append(f'[ {RED}✗ SNMP{RESET} ]')
					else:
						results.append(f'[ {SKIP}- SNMP{RESET} ]')

					if 'http' in host.config['scanners']:
						if HTTPScanner.discover(host):
							results.append(f'[ {GREEN}✓ HTTP{RESET} ]')
						else:
							results.append(f'[ {RED}✗ HTTP{RESET} ]')
					else:
						results.append(f'[ {SKIP}- HTTP{RESET} ]')

					print('Discovery on host %s: %s' % (host.ip, ' '.join(results)), file=sys.stderr)

					if len(host.scanners.keys()) > 0:
						# Only perform a scan of a host if there is at least one valid scanner.
						self.queue.put(('scan', host))
				elif action == 'scan':
					# Initial data scan of the device

					if 'snmp' in host.scanners:
						print('Scanning host %s (SNMP)' % (host.ip,), file=sys.stderr)
						SNMPScanner.scan(host)

					if 'http' in host.scanners:
						print('Scanning host %s (HTTP)' % (host.ip,), file=sys.stderr)
						HTTPScanner.scan(host)

					self.host_queue.put(host)
				else:
					logging.error('Unsupported action %s' % action)
			except Empty:
				# No more tasks left in the queue
				return
			except ValueError:
				# Usually occurs because user hit CTRL+C
				print('Thread closing', file=sys.stderr)
				return

	def _resolve_macs(self):
		"""
		Resolve missing device MAC addresses from the local ARP cache.
		:return:
		"""
		# Grab the monitoring server's ARP cache to resolve any local devices.
		# This only works for devices on the same layer 2 network, (ie: same subnet)
		local_arp = get_neighbors()
		for data in local_arp:
			if data['ip'] in self.hosts_by_ip and self.hosts_by_ip[data['ip']].mac is None:
				self.hosts_by_ip[data['ip']].mac = data['mac']
				self.hosts_by_ip[data['ip']].log('Resolved MAC from local ARP cache')

	def _resolve_hostnames(self):
		"""
		Attempt to resolve hostnames based on local socket data
		:return:
		"""
		for host in self.hosts:
			if host.hostname is None or host.hostname == '':
				try:
					host.log('Hostname resolved via local socket lookup')
					host.hostname = socket.gethostbyaddr(host.ip)[0]
					host.log('%s = %s' % (host.ip, host.hostname))
				except socket.herror:
					host.log('socket lookup failed')
					pass

	def _resolve_manufacturers(self):
		"""
		Attempt to resolve the manufacturer from the MAC address for devices
		:return:
		"""
		for host in self.hosts:
			if (host.manufacturer is None or host.manufacturer == '') and host.mac is not None:
				try:
					host.log('Manufacturer not set, trying a MAC lookup to resolve')
					host.manufacturer = MacLookup().lookup(host.mac)
					host.log('%s = %s' % (host.mac, host.manufacturer))
				except Exception:
					host.log('MAC address lookup failed')
					pass

	def finalize_results(self):
		if self.config['format'] == 'json':
			print(json.dumps([h.to_dict() for h in self.hosts], indent=2))
		elif self.config['format'] == 'csv':
			# Grab a new host just to retrieve the dictionary keys on the object
			generic = Host('test', self.config)
			# Set the header (and fields)
			writer = csv.DictWriter(sys.stdout, fieldnames=list(generic.to_dict().keys()))
			writer.writeheader()
			for h in self.hosts:
				writer.writerow(h.to_dict())
		elif self.config['format'] == 'grist':
			self._sync_grist()
		elif self.config['format'] == 'glpi':
			self._sync_glpi()
		else:
			print('Unknown format requested', file=sys.stderr)

	def _sync_grist(self):
		if self.config['dry_run']:
			print('Dry run enabled, skipping sync to Grist')
			return

		for h in self.hosts:
			try:
				print('Syncing %s to Grist' % h.ip)
				h.sync_to_grist()
			except HTTPError as e:
				h.synced_id = False
				print('Failed to sync %s to Grist: %s' % (h.ip, e), file=sys.stderr)

	def _sync_glpi(self):
		for h in self.hosts:
			if h.ip:
				ident = h.ip
			elif h.mac:
				ident = h.mac
			else:
				ident = 'device'
			print('Syncing %s to GLPI' % ident)
			h.sync_to_glpi()

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

	def _merge_hosts(self):
		"""
		Merge all the hosts discovered (and their neighbors when applicable) into a single list.

		:return:
		"""
		# Move all hosts discovered from the host queue into a standard list
		hosts = list(self.host_queue.queue)
		for host in hosts:
			if not host.reachable:
				# Skip hosts that are not reachable
				continue

			if host.ip and host.ip in self.config['exclude']:
				# Skip hosts explictly set to be ignored.
				continue

			self.hosts.append(host)
			if host.ip:
				self.hosts_by_ip[host.ip] = host
			if host.mac:
				self.hosts_by_mac[host.mac] = host

		# Iterate through the discovered neighbors from scanned hosts
		# and add/merge them into the main host list.
		# (Make a clone of the hosts to avoid modifying the queue while iterating)
		hosts = list(self.hosts)
		for host in hosts:
			for neighbor in host.neighbors.values():
				if neighbor.ip and neighbor.ip in self.hosts_by_ip:
					# Already exists, perform a merge instead
					self.hosts_by_ip[neighbor.ip].merge_from_host(neighbor)
				elif neighbor.mac and neighbor.mac in self.hosts_by_mac:
					# Already exists (by MAC)
					self.hosts_by_mac[neighbor.mac].merge_from_host(neighbor)
				elif neighbor.include:
					# This is a new host, add it to the list
					self.hosts.append(neighbor)


def run():

	app = Application()
	app.run()


if __name__ == '__main__':
	# Allow this script to be run standalone
	run()
