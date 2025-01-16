import sys
import json
import csv
from pysnmp import hlapi
import argparse
from typing import Union
import re
from mac_vendor_lookup import MacLookup
import socket
import ipaddress
from net_diag.libs.suitecrmsync import SuiteCRMSync, SuiteCRMSyncException


class Debug:
	"""
	Simple debug logging class, prints to stderr
	"""
	_debug = False

	@classmethod
	def log(cls, msg: str):
		if cls._debug:
			print('[DEBUG] %s' % msg, file=sys.stderr)


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


def scan_snmp_single(host: str, community: str, lookup: str) -> Union[str, None]:
	"""
	Scan a given host (with a community string) for a given OID.

	:param host:
	:param community:
	:param lookup:
	:return:
	"""

	error_responses = (
		'No Such Object currently exists at this OID',
	)

	# snmpEngine, authData, transportTarget, contextData, nonRepeaters, maxRepetitions, *varBinds
	iterator = hlapi.getCmd(
		hlapi.SnmpEngine(),
		hlapi.CommunityData(community, mpModel=1),
		hlapi.UdpTransportTarget((host, 161), timeout=2, retries=0),
		hlapi.ContextData(),
		hlapi.ObjectType(hlapi.ObjectIdentity(lookup))
	)

	errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
	if errorIndication:
		# Usually indicates no SNMP on target device or credentials were incorrect.
		Debug.log(errorIndication.__str__())
		return None
	else:
		if errorStatus:  # SNMP agent errors
			Debug.log('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex) - 1] if errorIndex else '?'))
			return None
		else:
			for varBind in varBinds:  # SNMP response contents
				key = varBind[0].getOid().__str__()
				val = _parse_value(varBind)

				Debug.log('%s = %s' % (key, val))
				if val in error_responses:
					return None
				return val

	return None


def scan_snmp(host: str, community: str, lookup: str) -> dict:
	"""
	Scan a given host (with a community string) for a given OID.

	:param host:
	:param community:
	:param lookup:
	:return:
	"""
	ret = {}

	iterator = hlapi.bulkCmd(
		hlapi.SnmpEngine(),
		hlapi.CommunityData(community, mpModel=1),
		hlapi.UdpTransportTarget((host, 161), timeout=10, retries=0),
		hlapi.ContextData(),
		False,
		5,
		hlapi.ObjectType(hlapi.ObjectIdentity(lookup))
	)

	try:
		while True:
			errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
			if errorIndication:
				# Usually indicates no SNMP on target device or credentials were incorrect.
				Debug.log(errorIndication.__str__())
				return ret
			else:
				if errorStatus:  # SNMP agent errors
					Debug.log('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex) - 1] if errorIndex else '?'))
					return ret
				else:
					for varBind in varBinds:  # SNMP response contents
						key = varBind[0].getOid().__str__()
						val = _parse_value(varBind)

						Debug.log('%s = %s' % (key, val))

						if key[0:len(lookup)] != lookup:
							raise StopIteration

						ret[key] = val
	except StopIteration:
		pass

	return ret


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
	for set in ranges:
		if set[0] <= n_val <= set[1]:
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

	def get_snmp_descr(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the description of the device.
		:param community:
		:return:
		"""
		lookup = '1.3.6.1.2.1.1.1.0'
		Debug.log('Scanning for DESCR - %s' % lookup)
		return scan_snmp_single(self.ip, community, lookup)

	def get_snmp_mac(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:param community:
		:return:
		"""
		lookup = '1.3.6.1.2.1.2.2.1.6'
		Debug.log('Scanning for MAC - %s' % lookup)
		# Each device may have multiple interfaces.
		addresses = scan_snmp(self.ip, community, lookup)
		for key, val in addresses.items():
			if val == '00:00:00:00:00:00':
				# Some devices will return a MAC of all 0's for an interface that is not in use.
				continue
			if val == '':
				# Some devices will return just a blank string for their interfaces
				continue

			return val

	def get_snmp_hostname(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:param community:
		:return:
		"""
		lookup = '1.3.6.1.2.1.1.5.0'
		Debug.log('Scanning for hostname - %s' % lookup)
		return scan_snmp_single(self.ip, community, lookup)

	def get_snmp_contact(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:param community:
		:return:
		"""
		lookup = '1.3.6.1.2.1.1.4.0'
		Debug.log('Scanning for contact - %s' % lookup)
		return scan_snmp_single(self.ip, community, lookup)

	def get_snmp_location(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:param community:
		:return:
		"""
		lookup = '1.3.6.1.2.1.1.6.0'
		Debug.log('Scanning for location - %s' % lookup)
		return scan_snmp_single(self.ip, community, lookup)

	def get_snmp_firmware(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the firmware version of the device.
		:param community:
		:return:
		"""
		lookup = '1.3.6.1.2.1.16.19.2.0'
		Debug.log('Scanning for firmware version - %s' % lookup)
		return scan_snmp_single(self.ip, community, lookup)

	def get_snmp_model(self, community: str) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the model version of the device.
		:param community:
		:return:
		"""
		lookup = '1.3.6.1.2.1.16.19.3.0'
		Debug.log('Scanning for model - %s' % lookup)
		return scan_snmp_single(self.ip, community, lookup)

	def scan_details(self, community: str):
		"""
		Perform a full scan of the device to store all details.
		:param community:
		:return:
		"""

		self._scan_snmp(community)

		if self.hostname is None:
			try:
				Debug.log('Hostname not set, trying a socket to resolve')
				self.hostname = socket.gethostbyaddr(self.ip)[0]
				Debug.log('%s = %s' % (self.ip, self.hostname))
			except socket.herror:
				Debug.log('socket lookup failed')
				pass

		if self.manufacturer is None and self.mac is not None:
			try:
				Debug.log('Manufacturer not set, trying a MAC lookup to resolve')
				self.manufacturer = MacLookup().lookup(self.mac)
				Debug.log('%s = %s' % (self.mac, self.manufacturer))
			except Exception:
				Debug.log('MAC address lookup failed')
				pass

	def get_neighbors_from_snmp(self, community: str):
		"""
		Perform a scan of the ARP table of the device to find neighbors.
		:param community:
		:return:
		"""

		if self.descr is None:
			# If no snmp scan performed for the base device already, (or it failed),
			# do not attempt to perform a neighbor scan.
			return []

		ret = []
		lookup = '1.3.6.1.2.1.3.1.1.2'
		neighbors = scan_snmp(self.ip, community, lookup)
		for key, val in neighbors.items():
			ip = '.'.join(key[len(lookup) + 1:].split('.')[2:])
			ret.append((ip, val))

		return ret

	def sync_to_suitecrm(self, sync: SuiteCRMSync):
		"""
		:param sync:
		:raises SuiteCRMSyncException:
		:return:
		"""
		if self.mac is None:
			print('No MAC address found for SuiteCRM sync on %s' % self.ip, file=sys.stderr)
			return

		Debug.log('Searching for devices with MAC %s' % self.mac)
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
				'manufacturer',
				'model',
				'os_version',
				'type',
				'description'
			)
		)
		Debug.log('Found %s device(s)' % len(ret))

		if len(ret) == 0:
			# No records located, create
			data = {
				'ip_pri': self.ip,
				'mac_pri': self.mac,
				'name': self.hostname,
				'loc_room': self.location,
				'loc_floor': self.floor,
				'manufacturer': self.manufacturer,
				'model': self.model,
				'os_version': self.os_version,
				'type': self.type,
				'description': self.descr
			}
			Debug.log('Creating device record for %s: (%s)' % (self.ip, json.dumps(data)))
			sync.create('MSP_Devices', data)
		elif len(ret) == 1:
			# Update only, (do not overwrite existing data)
			if ret[0]['mac_sec'] == self.mac:
				ip_key = 'ip_sec'
			elif ret[0]['mac_oob'] == self.mac:
				ip_key = 'ip_oob'
			else:
				ip_key = 'ip_pri'

			data = {}
			if ret[0][ip_key] != self.ip:
				data[ip_key] = self.ip
			if not ret[0]['name'] and self.hostname:
				data['name'] = self.hostname
			if not ret[0]['loc_room'] and self.location:
				data['loc_room'] = self.location
			if not ret[0]['loc_floor'] and self.floor:
				data['loc_floor'] = self.floor
			if not ret[0]['manufacturer'] and self.manufacturer:
				data['manufacturer'] = self.manufacturer
			if not ret[0]['model'] and self.model:
				data['model'] = self.model
			if not ret[0]['os_version'] and self.os_version:
				data['os_version'] = self.os_version
			if not ret[0]['type'] and self.type:
				data['type'] = self.type
			if not ret[0]['description'] and self.descr:
				data['description'] = self.descr

			if len(data) > 0:
				Debug.log('Updating device record for %s: %s' % (self.ip, json.dumps(data)))
				sync.update('MSP_Devices', ret[0]['id'], data)
			else:
				Debug.log('No updates required for %s' % self.ip)
		else:
			print('Multiple records found for %s' % self.mac, file=sys.stderr)

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
		parts = val.split(';')
		if re.match(r'^ ; AXIS .* Network Camera', val):
			self.manufacturer = 'AXIS'
			self.model = parts[1][5:].strip()
			self.type = parts[2].strip()
			self.os_version = parts[3].strip()

	def __repr__(self):
		return f'<Host ip:{self.ip} mac:{self.mac} hostname:{self.hostname} descr:{self.descr}>'

	def to_dict(self):
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
			'descr': self.descr
		}


def run():
	parser = argparse.ArgumentParser(
		prog='network_discover.py',
		description='''Discover network devices using SNMP.
Refer to https://github.com/cdp1337/net-diag for sourcecode and full documentation.'''
	)

	parser.add_argument('--ip', required=True, help='IP address to start the scan from')
	parser.add_argument('-c', '--community', default='public', help='SNMP community string to use')
	parser.add_argument('--format', default='json', choices=('json', 'csv', 'suitecrm'), help='Output format')
	parser.add_argument('--debug', action='store_true', help='Enable debug output')
	parser.add_argument('--single', action='store_true', help='Scan a single host and do not discover neighbors')
	parser.add_argument('--crm-url', help='URL of the SuiteCRM instance')
	parser.add_argument('--crm-client-id', help='Client ID for the SuiteCRM instance')
	parser.add_argument('--crm-client-secret', help='Client secret for the SuiteCRM instance')

	options = parser.parse_args()

	hosts = ()
	sync = None

	if options.debug:
		Debug._debug = True

	if options.format == 'suitecrm':
		sync = SuiteCRMSync(options.crm_url, options.crm_client_id, options.crm_client_secret)
		try:
			# Perform a connection to check credentials prior to scanning for hosts
			sync.get_token()
		except SuiteCRMSyncException as e:
			print('Failed to connect to SuiteCRM: %s' % e, file=sys.stderr)
			sys.exit(1)

	try:
		hosts = scan(options.ip, options.community, single=options.single)
	except KeyboardInterrupt:
		print('Exiting scan', file=sys.stderr)
		# Either exit the scan if it requires additional work or continue to output the results
		if options.format == 'suitecrm':
			return
		else:
			pass

	finalize_results(options.format, hosts, sync=sync)


def scan(starting_ip: str, community: str, single: bool = False):
	hosts = []
	ips_found = []
	hosts_queue = []

	# Perform a scan starting with the host specified
	hosts_queue.append(Host(starting_ip))
	ips_found.append(starting_ip)

	while len(hosts_queue) > 0:
		h = hosts_queue.pop(0)
		print('[%s of %s] - Scanning details for %s' % (len(hosts) + 1, len(ips_found), h.ip), file=sys.stderr)
		h.scan_details(community)
		hosts.append(h)

		# Walk the ARP table of the device to discover more devices
		if single:
			neighbors = []
		else:
			if h.descr:
				print('[%s of %s] - Retrieving neighbors from ARP table on %s' % (len(hosts), len(ips_found), h.ip), file=sys.stderr)
			neighbors = h.get_neighbors_from_snmp(community)

		for ip, mac in neighbors:
			if ip not in ips_found and not is_local_ip(ip):
				child_host = Host(ip)
				child_host.mac = mac
				hosts_queue.append(child_host)
				ips_found.append(ip)

	return hosts


def finalize_results(format: str, hosts: list, sync: Union[SuiteCRMSync, None] = None):
	if format == 'json':
		print(json.dumps([h.to_dict() for h in hosts], indent=2))
	elif format == 'csv':
		# Grab a new host just to retrieve the dictionary keys on the object
		generic = Host('test')
		# Set the header (and fields)
		writer = csv.DictWriter(sys.stdout, fieldnames=list(generic.to_dict().keys()))
		writer.writeheader()
		for h in hosts:
			writer.writerow(h.to_dict())
	elif format == 'suitecrm':
		for h in hosts:
			try:
				print('Syncing %s to SuiteCRM' % h.ip)
				h.sync_to_suitecrm(sync)
			except SuiteCRMSyncException as e:
				print('Failed to sync %s to SuiteCRM: %s' % (h.ip, e), file=sys.stderr)
	else:
		print('Unknown format requested', file=sys.stderr)


if __name__ == '__main__':
	# Allow this script to be run standalone
	run()
