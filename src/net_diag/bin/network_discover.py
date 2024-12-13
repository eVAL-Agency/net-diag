import sys
import json
import csv
from pysnmp import hlapi
import argparse
from typing import Union
import re


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
		val = ':'.join([val[2:][i:i+2] for i in range(0, len(val[2:]), 2)])

	return val


def scan_snmp_single(host: str, community: str, lookup: str) -> Union[str,None]:
	"""
	Scan a given host (with a community string) for a given OID.

	:param host:
	:param community:
	:param lookup:
	:return:
	"""

	ret = {}

	# snmpEngine, authData, transportTarget, contextData, nonRepeaters, maxRepetitions, *varBinds
	iterator = hlapi.getCmd(
		hlapi.SnmpEngine(),
		hlapi.CommunityData(community, mpModel=0),
		hlapi.UdpTransportTarget((host, 161), timeout=2, retries=0),
		hlapi.ContextData(),
		hlapi.ObjectType(hlapi.ObjectIdentity(lookup))
	)

	errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
	if errorIndication:
		# Usually indicates no SNMP on target device or credentials were incorrect.
		return None
	else:
		if errorStatus:  # SNMP agent errors
			#print('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex)-1] if errorIndex else '?'))
			return None
		else:
			for varBind in varBinds:  # SNMP response contents
				return _parse_value(varBind)
			# pprint(' = '.join([key, val])) # DEBUG

	return ret


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
		hlapi.CommunityData(community, mpModel=0),
		hlapi.UdpTransportTarget((host, 161), timeout=2, retries=0),
		hlapi.ContextData(),
		False,
		5,
		hlapi.ObjectType(hlapi.ObjectIdentity(lookup))
	)

	try:
		while True:
			errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
			if errorIndication:
				return {}
			else:
				if errorStatus:  # SNMP agent errors
					return {}
					#print('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex)-1] if errorIndex else '?'), file=sys.stderr)
				else:
					for varBind in varBinds:  # SNMP response contents
						key = varBind[0].getOid().__str__()
						val = _parse_value(varBind)

						if key[0:len(lookup)] != lookup:
							raise StopIteration

						ret[key] = val
						# pprint(' = '.join([key, val])) # DEBUG
	except StopIteration:
		pass

	return ret


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
		self.descr = None

	def get_snmp_descr(self, community: str) -> Union[str,None]:
		"""
		Perform a basic SNMP scan to get the description of the device.
		:param community:
		:return:
		"""
		lookup = '1.3.6.1.2.1.1.1.0'
		return scan_snmp_single(self.ip, community, lookup)

	def get_snmp_mac(self, community: str) -> Union[str,None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:param community:
		:return:
		"""
		lookup = '1.3.6.1.2.1.2.2.1.6.1'
		return scan_snmp_single(self.ip, community, lookup)

	def get_snmp_hostname(self, community: str) -> Union[str,None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:param community:
		:return:
		"""
		lookup = '1.3.6.1.2.1.1.5.0'
		return scan_snmp_single(self.ip, community, lookup)

	def get_snmp_contact(self, community: str) -> Union[str,None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:param community:
		:return:
		"""
		lookup = '1.3.6.1.2.1.1.4.0'
		return scan_snmp_single(self.ip, community, lookup)

	def get_snmp_location(self, community: str) -> Union[str,None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:param community:
		:return:
		"""
		lookup = '1.3.6.1.2.1.1.6.0'
		return scan_snmp_single(self.ip, community, lookup)

	def scan_snmp_details(self, community: str):
		"""
		Perform a full scan of the device to store all details.
		:param community:
		:return:
		"""
		val = self.get_snmp_descr(community)
		if val is None:
			# Initial lookup of DESCR failed; do not try to continue.
			return

		self.descr = val

		mac = self.get_snmp_mac(community)
		if mac is not None:
			self.mac = mac

		hostname = self.get_snmp_hostname(community)
		if hostname is not None:
			self.hostname = hostname

		contact = self.get_snmp_contact(community)
		if contact is not None:
			self.contact = contact

		location = self.get_snmp_location(community)
		if location is not None:
			self._store_location(location)

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
			ip = '.'.join(key[len(lookup)+1:].split('.')[2:])
			ret.append((ip, val))

		return ret

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
			self.location = val[len(self.floor)+2:].strip()
		else:
			self.location = val

	def __repr__(self):
		return f'<Host ip:{self.ip} mac:{self.mac} hostname:{self.hostname} contact:{self.contact} location:{self.location} descr:{self.descr}>'

	def to_dict(self):
		return {
			'ip': self.ip,
			'mac': self.mac,
			'hostname': self.hostname,
			'contact': self.contact,
			'floor': self.floor,
			'location': self.location,
			'descr': self.descr
		}


def run():
	parser = argparse.ArgumentParser(
		prog='network_discover.py',
		description='Discover network devices using SNMP'
	)

	parser.add_argument('--ip', required=True)
	parser.add_argument('-c', '--community', default='public')
	parser.add_argument('--format', default='json', choices=('json', 'csv'))

	options = parser.parse_args()

	hosts = []
	ips_found = []
	hosts_queue = []

	# Perform a scan starting with the host specified
	hosts_queue.append(Host(options.ip))
	ips_found.append(options.ip)

	try:
		while len(hosts_queue) > 0:
			h = hosts_queue.pop(0)
			print('[%s of %s] - Scanning details for %s' % (len(hosts) + 1, len(ips_found), h.ip), file=sys.stderr)
			h.scan_snmp_details(options.community)
			hosts.append(h)

			# Walk the ARP table of the device to discover more devices
			if h.descr:
				print('[%s of %s] - Retrieving neighbors from ARP table on %s' % (len(hosts), len(ips_found), h.ip), file=sys.stderr)
			neighbors = h.get_neighbors_from_snmp(options.community)
			#neighbors = []
			for ip, mac in neighbors:
				if ip not in ips_found:
					child_host = Host(ip)
					child_host.mac = mac
					hosts_queue.append(child_host)
					ips_found.append(ip)
	except KeyboardInterrupt:
		print('Exiting scan', file=sys.stderr)
		pass

	if options.format == 'json':
		print(json.dumps([h.to_dict() for h in hosts], indent=2))
	elif options.format == 'csv':
		# Grab a new host just to retrieve the dictionary keys on the object
		generic = Host('test')
		# Set the header (and fields)
		writer = csv.DictWriter(sys.stdout, fieldnames=list(generic.to_dict().keys()))
		writer.writeheader()
		for h in hosts:
			writer.writerow(h.to_dict())
	else:
		print('Unknown format requested', file=sys.stderr)


if __name__ == '__main__':
	# Allow this script to be run standalone
	run()
