import subprocess
import sys
import json
import csv
import threading
from time import sleep

import argparse
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

from net_diag.libs.snmputils import snmp_parse_descr, snmp_lookup_single, snmp_lookup_bulk
from net_diag.libs.suitecrmsync import SuiteCRMSync, SuiteCRMSyncException
from net_diag.libs.nativeping import ping


def _parse_value(var_bind):
	"""
	Parse a raw value from SNMP to a more human-readable format.
	:param var_bind:
	:return: str
	"""
	val = var_bind[1].prettyPrint()

	if val[0:2] == '0x':
		# Pretty-printed MAC addresses have a "0x" prefix and no punctuation.
		# Drop the "0x" and add ':' every 2 characters
		val = ':'.join([val[2:][i:i + 2] for i in range(0, len(val[2:]), 2)])

	return val


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

	def __init__(self, ip: str):
		self.ip = ip
		self.mac = None
		self.hostname = None
		self.contact = None
		self.floor = None
		self.location = None
		self.type = None
		self.manufacturer = None
		self.model = None
		self.os_version = None
		self.descr = None
		self.address = None
		self.city = None
		self.state = None
		self.log_lines = ''
		self.reachable = False
		self.neighbors = None

	def log(self, msg: str):
		"""
		Log a debug message to the debugger logger and to this device's internal log

		:param msg:
		:return:
		"""
		self.log_lines += '[%s] %s\n' % (datetime.now().isoformat(), msg)
		logging.debug(msg)

	def ping(self):
		"""
		Ping the host to see if it is reachable
		:return:
		"""
		self.log('Pinging %s' % (self.ip,))
		self.reachable = ping(self.ip)
		self.log('Reachable' if self.reachable else 'Not reachable')

	def is_available(self) -> bool:
		"""
		Check if this device is available on the network

		Checks both ping and SNMP, as either could be disabled.
		:return:
		"""
		return self.reachable or self.descr is not None

	def _snmp_single_lookup(self, community: str, name: str, oid: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get some value
		:param community:
		:return:
		"""
		self.log('Scanning for %s - OID:%s' % (name, oid))
		val = snmp_lookup_single(self.ip, community, oid)
		if val is None:
			self.log('OID does not exist or value was NULL')
		else:
			self.log('Raw response: [%s]' % val)
		return val

	def get_snmp_descr(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the description of the device.
		:param community:
		:return:
		"""
		return self._snmp_single_lookup(community, 'DESCR', '1.3.6.1.2.1.1.1.0')

	def get_snmp_mac(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:param community:
		:return:
		"""
		lookup = '1.3.6.1.2.1.2.2.1.6'
		self.log('Scanning for MAC - OID:%s' % lookup)
		# Each device may have multiple interfaces.
		addresses = snmp_lookup_bulk(self.ip, community, lookup)
		for key, val in addresses.items():
			self.log('Raw response: [%s]' % val)
			if val == '0x000000000000':
				# Some devices will return a MAC of all 0's for an interface that is not in use.
				continue
			if val == '':
				# Some devices will return just a blank string for their interfaces
				continue

			if val[0:2] == '0x':
				# SNMP-provided MAC addresses will have a 0x prefix
				# Drop that and add ':' every 2 characters to be more MAC-like
				val = ':'.join([val[2:][i:i + 2] for i in range(0, len(val[2:]), 2)])

			return val

	def get_snmp_hostname(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the hostname of the device.
		:param community:
		:return:
		"""
		return self._snmp_single_lookup(community, 'hostname', '1.3.6.1.2.1.1.5.0')

	def get_snmp_contact(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:param community:
		:return:
		"""
		return self._snmp_single_lookup(community, 'contact', '1.3.6.1.2.1.1.4.0')

	def get_snmp_location(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:param community:
		:return:
		"""
		return self._snmp_single_lookup(community, 'location', '1.3.6.1.2.1.1.6.0')

	def get_snmp_firmware(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the firmware version of the device.
		:param community:
		:return:
		"""
		return self._snmp_single_lookup(community, 'firmware version', '1.3.6.1.2.1.16.19.2.0')

	def get_snmp_model(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the model version of the device.
		:param community:
		:return:
		"""
		return self._snmp_single_lookup(community, 'model', '1.3.6.1.2.1.16.19.3.0')

	def scan_details(self, community: str):
		"""
		Perform a full scan of the device to store all details.
		:param community:
		:return:
		"""

		self._scan_snmp(community)

		if self.hostname is None or self.hostname == '':
			try:
				self.log('Hostname not set, trying a socket to resolve')
				self.hostname = socket.gethostbyaddr(self.ip)[0]
				self.log('%s = %s' % (self.ip, self.hostname))
			except socket.herror:
				self.log('socket lookup failed')
				pass

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

	def get_neighbors_from_snmp(self, community: str):
		"""
		Perform a scan of the ARP table of the device to find neighbors.
		:param community:
		:return:
		"""

		if self.neighbors is not None:
			return self.neighbors

		if self.descr is None:
			# If no snmp scan performed for the base device already, (or it failed),
			# do not attempt to perform a neighbor scan.
			self.neighbors = []
			return []

		ret = []
		lookup = '1.3.6.1.2.1.3.1.1.2'
		self.log('Scanning for neighbors - OID:%s' % lookup)
		neighbors = snmp_lookup_bulk(self.ip, community, lookup)
		for key, val in neighbors.items():
			ip = '.'.join(key[len(lookup) + 1:].split('.')[2:])
			if val[0:2] == '0x':
				# SNMP-provided MAC addresses will have a 0x prefix
				# Drop that and add ':' every 2 characters to be more MAC-like
				val = ':'.join([val[2:][i:i + 2] for i in range(0, len(val[2:]), 2)])

			self.log('%s is at %s' % (ip, val))
			ret.append((ip, val))

		self.log('Found %s devices' % len(ret))
		self.neighbors = ret
		return ret

	def sync_to_suitecrm(self, sync: SuiteCRMSync):
		"""
		:param sync:
		:raises SuiteCRMSyncException:
		:return:
		"""
		if self.mac is None:
			logging.warning('No MAC address found for SuiteCRM sync on %s' % self.ip)
			return

		self.log('Searching for devices in SuiteCRM with MAC %s' % self.mac)
		ret = sync.find(
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
				'description'
			)
		)
		self.log('Found %s device(s)' % len(ret))

		if len(ret) == 0:
			# No records located, create
			data = self._generate_suitecrm_payload(None)
			self.log('Creating device record for %s: (%s)' % (self.ip, json.dumps(data)))
			sync.create('MSP_Devices', data | {'discover_log': self.log_lines})
		elif len(ret) == 1:
			# Update only, (do not overwrite existing data)
			data = self._generate_suitecrm_payload(ret[0])
			if len(data):
				self.log('Syncing device record for %s: %s' % (self.ip, json.dumps(data)))
			else:
				self.log('No data changed for %s' % self.ip)
			sync.update('MSP_Devices', ret[0]['id'], data | {'discover_log': self.log_lines})
		else:
			logging.warning('Multiple records found for %s' % self.mac)

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
		if self.address and (server_data is None or server_data['loc_address'] != self.address):
			data['loc_address'] = self.address

		if self.city and (server_data is None or server_data['loc_address_city'] != self.city):
			data['loc_address_city'] = self.city

		if self.state and (server_data is None or server_data['loc_address_state'] != self.state):
			data['loc_address_state'] = self.state

		# Fields that should only be set if they are present in the scan
		# and not already set in the inventory data.
		if self.hostname and (server_data is None or server_data['name'] == ''):
			data['name'] = self.hostname

		if self.location and (server_data is None or server_data['loc_room'] == ''):
			data['loc_room'] = self.location

		if self.floor and (server_data is None or server_data['loc_floor'] == ''):
			data['loc_floor'] = self.floor

		if self.manufacturer and (server_data is None or server_data['manufacturer'] == ''):
			data['manufacturer'] = self.manufacturer

		if self.model and (server_data is None or server_data['model'] == ''):
			data['model'] = self.model

		if self.os_version and (server_data is None or server_data['os_version'] == ''):
			data['os_version'] = self.os_version

		if self.type and (server_data is None or server_data['type'] == ''):
			data['type'] = self.type

		if self.descr and (server_data is None or server_data['description'] == ''):
			data['description'] = self.descr

		return data

	def _scan_snmp(self, community: str):
		val = self.get_snmp_descr(community)
		if val is None:
			# Initial lookup of DESCR failed; do not try to continue.
			return
		self._store_descr(val)

		mac = self.get_snmp_mac(community)
		if mac is not None:
			self.mac = mac

		hostname = self.get_snmp_hostname(community)
		if hostname is not None:
			self.hostname = hostname

		contact = self.get_snmp_contact(community)
		if contact is not None:
			self.contact = contact

		firmware = self.get_snmp_firmware(community)
		if firmware is not None:
			self.os_version = firmware

		model = self.get_snmp_model(community)
		if model is not None:
			self.model = model

		location = self.get_snmp_location(community)
		if location is not None:
			self._store_location(location)

	def _store_location(self, val: str):
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

	def _store_descr(self, val: str):
		"""
		Parse and store the description of the device.
		:param val:
		:return:
		"""

		if val is None:
			return

		self.descr = val
		data = snmp_parse_descr(val)
		for key, value in data.items():
			self.log('Parsed %s as [%s]' % (key, value))
			setattr(self, key, value)

	def __repr__(self) -> str:
		return f'<Host ip:{self.ip} mac:{self.mac} hostname:{self.hostname} descr:{self.descr}>'

	def to_dict(self) -> dict:
		return {
			'ip': self.ip,
			'mac': self.mac,
			'hostname': self.hostname,
			'contact': self.contact,
			'floor': self.floor,
			'location': self.location,
			'type': self.type,
			'manufacturer': self.manufacturer,
			'model': self.model,
			'os_version': self.os_version,
			'descr': self.descr,
			'address': self.address,
			'city': self.city,
			'state': self.state
		}


class Application:
	def __init__(self):
		self.queue = Queue()
		self.host_queue = Queue()
		self.hosts = []
		self.threads = []
		self.community = None
		self.sync = None
		self.excludes = []
		self.format = None

	def run(self):
		self.setup()

		try:
			# Initialize the process threads
			thread_count = min(self.queue.qsize(), multiprocessing.cpu_count())
			print('Starting scan with %s threads' % thread_count, file=sys.stderr)
			for n in range(0, thread_count):
				t = threading.Thread(target=self.worker)
				self.threads.append(t)
				t.start()
				sleep(0.5)

			# Wait for all threads to finish
			for thread in self.threads:
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
		host_map = {}
		for host in list(self.host_queue.queue):
			if host.is_available() and host.ip not in self.excludes:
				host_map[host.ip] = len(self.hosts)
				self.hosts.append(host)

		# Resolve any located MAC from the remote arp table
		# This is important because hosts which do not have SNMP enabled should still have the MAC available.
		for host in self.hosts:
			if host.neighbors is not None:
				for ip, mac in host.neighbors:
					if ip in host_map:
						# This IP is one of the devices we are scanning, update its MAC if required
						i = host_map[ip]
						if self.hosts[i].mac is None:
							self.hosts[i].mac = mac

		# Perform any operations / lookups that require a MAC address
		for host in self.hosts:
			host.resolve_manufacturer()

		self.finalize_results()

	def setup(self):
		"""
		Setup the application and prep everything needed to run the scan
		:return:
		"""
		parser = argparse.ArgumentParser(
			prog='network_discover.py',
			description='''Discover network devices using SNMP.
Refer to https://github.com/cdp1337/net-diag for sourcecode and full documentation.'''
		)

		parser.add_argument('--net', required=True, help='Network to scan eg: 192.168.0.0/24')
		parser.add_argument('-c', '--community', default='public', help='SNMP community string to use')
		parser.add_argument('--format', default='json', choices=('json', 'csv', 'suitecrm'), help='Output format')
		parser.add_argument('--debug', action='store_true', help='Enable debug output')
		parser.add_argument('--crm-url', help='URL of the SuiteCRM instance')
		parser.add_argument('--crm-client-id', help='Client ID for the SuiteCRM instance')
		parser.add_argument('--crm-client-secret', help='Client secret for the SuiteCRM instance')
		parser.add_argument('--address', help='Optional address for this scan (for reporting)')
		parser.add_argument('--city', help='Optional city for this scan (for reporting)')
		parser.add_argument('--state', help='Optional state for this scan (for reporting)')
		parser.add_argument('--exclude', help='List of IPs to exclude from overall report, comma-separated')
		parser.add_argument('--exclude-self', action='store_true', help='Set to exclude the host running the scan')

		options = parser.parse_args()

		self.community = options.community
		self.excludes = options.exclude.split(',') if options.exclude else []
		self.format = options.format
		if options.debug:
			logging.basicConfig(level=logging.DEBUG)

		if options.exclude_self:
			# Include local IPs to be excluded too
			# This is useful for dedicated scanning devices implanted in a client location
			self.excludes += self.get_local_ips()

		logging.debug('Excluding IPs: %s' % ', '.join(self.excludes))

		if self.format == 'suitecrm':
			self.sync = SuiteCRMSync(options.crm_url, options.crm_client_id, options.crm_client_secret)
			try:
				# Perform a connection to check credentials prior to scanning for hosts
				self.sync.get_token()
			except SuiteCRMSyncException as e:
				print('Failed to connect to SuiteCRM: %s' % e, file=sys.stderr)
				sys.exit(1)

		override = {}
		if options.address:
			override['address'] = options.address
		if options.city:
			override['city'] = options.city
		if options.state:
			override['state'] = options.state

		# Build the queue of devices to scan
		for ip in ipaddress.ip_network(options.net).hosts():
			h = Host(str(ip))
			for k, v in override.items():
				setattr(h, k, v)
			self.queue.put(('scan', h))

	def worker(self):
		while True:
			try:
				action, host = self.queue.get(False, 0.5)
				if action == 'scan':
					# Initial scan of the device
					print('Scanning host %s' % (host.ip,), file=sys.stderr)
					host.ping()
					host.scan_details(self.community)
					self.queue.put(('neighbors', host))
				elif action == 'neighbors':
					# Secondary scan, (now that the arp cache of the remote devices should be populated)
					if host.descr:
						print('Scanning host for neighbors %s' % (host.ip,), file=sys.stderr)
						host.get_neighbors_from_snmp(self.community)
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

	def finalize_results(self):
		if self.format == 'json':
			print(json.dumps([h.to_dict() for h in self.hosts], indent=2))
		elif self.format == 'csv':
			# Grab a new host just to retrieve the dictionary keys on the object
			generic = Host('test')
			# Set the header (and fields)
			writer = csv.DictWriter(sys.stdout, fieldnames=list(generic.to_dict().keys()))
			writer.writeheader()
			for h in self.hosts:
				writer.writerow(h.to_dict())
		elif self.format == 'suitecrm':
			for h in self.hosts:
				try:
					print('Syncing %s to SuiteCRM' % h.ip)
					h.sync_to_suitecrm(self.sync)
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
