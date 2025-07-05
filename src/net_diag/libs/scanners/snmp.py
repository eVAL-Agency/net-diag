import re
from typing import Union
import asyncio

from net_diag.libs.net_utils import format_link_speed
from net_diag.libs.snmputils import snmp_lookup_single, snmp_lookup_bulk
from net_diag.libs.host import Host, HostInterface


class SNMPScanner:
	"""
	SNMP Scanner class for scanning devices using SNMP protocol.
	"""

	def __init__(self, host: Host):
		self.host = host

	def scan(self):
		"""
		Scan this device for all SNMP values

		This top-level scanner sets Descr and sysObjectID only.
		The rest of the values are up to the individual scanners to implement.

		:return:
		"""
		if 'community' not in self.host.config:
			# SNMP scans require a community string
			return

		val = self.get_descr()
		if val is None:
			# Initial lookup of DESCR failed; do not try to continue.
			return
		self.host.descr = val

		object_id = self.get_object_id()
		if object_id is not None:
			self.host.object_id = object_id

		# Use a device-specific scanner to perform the actual lookups
		# This allows specific devices to have their own scan functions.
		scanner = self._get_scanner()
		scanner.scan()

	def scan_neighbors(self):
		"""
		Perform a scan of the ARP table of the device to find neighbors.
		:return:
		"""

		if 'community' not in self.host.config:
			# SNMP scans require a community string
			return

		if not self.host.descr:
			# Scan requires SNMP to be available
			return

		scanner = self._get_scanner()
		scanner.scan_neighbors()

	def get_descr(self) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the description of the device.
		:return:
		"""
		return self._lookup_single('DESCR', '1.3.6.1.2.1.1.1.0')

	def get_object_id(self) -> Union[str, None]:
		"""
		Grab the sysObjectID of the device, which may be a unique identifier for the device type.
		:return:
		"""
		return self._lookup_single('sysObjectID', '1.3.6.1.2.1.1.2.0')

	def _lookup_single(self, name: str, oid: str) -> Union[str, None]:
		"""
		Perform a basic SNMP get to retrieve some value
		:param name: string Name of this scan for the logs
		:param oid: string SNMP OID to scan
		:return:
		"""
		self.host.log('Scanning for %s - OID:%s' % (name, oid))
		val = asyncio.run(snmp_lookup_single(self.host.ip, str(self.host.config['community']), oid))
		if val is None:
			self.host.log('OID does not exist or value was NULL')
		else:
			self.host.log('Raw response: [%s]' % val)
		return val

	def _lookup_bulk(self, name: str, oid: str) -> dict:
		"""
		Perform a bulk SNMP get to retrieve some values in a given parent
		:param name: string Name of this scan for the logs
		:param oid: string SNMP OID to scan
		:return:
		"""
		self.host.log('Scanning for %s - OID:%s' % (name, oid))
		val = asyncio.run(snmp_lookup_bulk(self.host.ip, str(self.host.config['community']), oid))
		if len(val) == 0:
			self.host.log('OID does not exist or value was NULL')
		else:
			self.host.log('Found %s items' % len(val))
		return val

	def _get_scanner(self):
		"""
		Get the device-specific scanner based on the sysObjectID.

		Will return the default scanner if none specified.
		:return:
		"""
		# Allow some sysObjectIDs to specify additional scan parameters.
		scanners = {
			'1.3.6.1.4.1.14988.1': MikrotikScan,
			'1.3.6.1.4.1.14988.2': MikrotikScan,
			'1.3.6.1.4.1.41112': UbiquitiScan,
			'DEFAULT': DefaultScan,
		}
		if self.host.object_id in scanners:
			return scanners[self.host.object_id](self.host)
		else:
			return scanners['DEFAULT'](self.host)

	def _format_snmp_mac(self, val: str) -> Union[str, None]:
		"""
		Format a MAC address from SNMP data to a more human-readable format

		:param val:
		:return:
		"""
		if val == '0x000000000000':
			# Some devices will return a MAC of all 0's for an interface that is not in use.
			return None

		if val == '':
			# Some devices will return just a blank string for their interfaces
			return None

		if val[0:2] == '0x':
			# SNMP-provided MAC addresses will have a 0x prefix
			# Drop that and add ':' every 2 characters to be more MAC-like
			return ':'.join([val[2:][i:i + 2] for i in range(0, len(val[2:]), 2)])

		# No modifications required
		return val


class DefaultScan(SNMPScanner):
	"""
	Default scan function for devices that do not have a specific scan function.
	"""

	def __init__(self, host):
		super().__init__(host)
		self.basic_lookups = {
			'contact': '1.3.6.1.2.1.1.4.0',
			'hostname': '1.3.6.1.2.1.1.5.0',
			'location': '1.3.6.1.2.1.1.6.0',
			'os_version': '1.3.6.1.2.1.16.19.2',
			'model': '1.3.6.1.2.1.16.19.3.0',
			'gateway': '1.3.6.1.2.1.4.21.1.7.0.0.0.0',
		}
		self.descr_parses = (
			(
				#  ; AXIS 212 PTZ; Network Camera; 4.49; Jun 18 2009 13:28; 14D; 1;
				r'^ ; AXIS (?P<model>[^;]*); Network Camera; (?P<os_version>[^;]*); [ADFJMNOS][aceopu][bcglnprtvy] [0-9]{1,2} [0-9]{4} [0-9]{1,2}:[0-9]{2};.*',  # noqa: E501
				{'manufacturer': 'Axis Communications AB.', 'type': 'Camera'}
			),
			(
				# 24-Port Gigabit Smart PoE Switch with 4 Combo SFP Slots
				r'^24-Port Gigabit Smart PoE Switch with 4 Combo SFP Slots$',
				{'manufacturer': 'TP-Link Technologies Co., LTD.', 'type': 'Switch'}
			),
			(
				# H.264 Mega-Pixel Network Camera
				r'^H.264 Mega-Pixel Network Camera$',
				{'type': 'Camera'}
			),
			(
				# HP ETHERNET MULTI-ENVIRONMENT,SN:VNB8JCKF0M,FN:1N807W6,SVCID:27057,PID:HP Color LaserJet MFP M477fnw
				r'^HP ETHERNET MULTI-ENVIRONMENT,SN:(?P<serial>[^,]+),FN:[^,]+,SVCID:[^,]+,PID:(?P<model>.*)$',
				{'manufacturer': 'Hewlett Packard', 'type': 'Printer'}
			),
			(
				# JetStream 24-Port Gigabit Smart PoE+ Switch with 4 SFP Slots
				r'^JetStream 24-Port Gigabit Smart PoE\+ Switch with 4 SFP Slots$',
				{'manufacturer': 'TP-Link Technologies Co., LTD.', 'type': 'Switch'}
			),
			(
				# Ubiquiti UniFi UDM-Pro 4.1.13 Linux 4.19.152 al324
				r'^Ubiquiti UniFi (?P<model>UDM-Pro) (?P<os_version>[^ ]+) Linux [^ ]+ [^ ]+$',
				{'manufacturer': 'Ubiquiti Networks Inc.', 'type': 'Router'}
			)
		)

	def scan(self):
		# Parse the Descr value for common data
		for check in self.descr_parses:
			match = re.match(check[0], self.host.descr)
			if match:
				for key, val in check[1].items():
					# Set hardcoded overrides from the definition
					setattr(self.host, key, val)
				for key, val in match.groupdict().items():
					setattr(self.host, key, val)

		# Set all the basic keys
		for key, val in self.get_basic_keys().items():
			if key == 'location':
				self.host.set_location(val)
			else:
				setattr(self.host, key, val)

		mac = self.get_mac()
		if mac is not None:
			self.host.mac = mac

		self.host.interfaces = self.get_ports()

	def scan_neighbors(self):
		"""
		Perform a scan of the ARP table of the device to find neighbors.
		:return:
		"""

		ret = []
		lookup = '1.3.6.1.2.1.3.1.1.2'
		neighbors = self._lookup_bulk('ARP Table', lookup)
		for key, val in neighbors.items():
			ip = '.'.join(key[len(lookup) + 1:].split('.')[2:])
			val = self._format_snmp_mac(val)

			self.host.log('%s is at %s' % (ip, val))
			ret.append((ip, val))

		self.host.log('Found %s devices' % len(ret))
		self.host.neighbors = ret

	def get_basic_keys(self) -> dict:
		"""
		Get the basic keys for this device.

		Basic keys are single SNMP values which do not require any additional processing.
		:return:
		"""
		ret = {}
		for key, oid in self.basic_lookups.items():
			if not oid:
				continue

			val = self._lookup_single(key, oid)
			if val is not None:
				ret[key] = val

		return ret

	def get_mac(self) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:return:
		"""
		addresses = self._lookup_bulk('MAC', '1.3.6.1.2.1.2.2.1.6')
		for key, val in addresses.items():
			val = self._format_snmp_mac(val)
			if val is None:
				# Skip invalid MAC addresses
				continue

			self.host.log('Found MAC address of %s' % val)
			return val

		return None

	def get_ports(self) -> Union[dict, None]:
		"""
		Get port details for this device, (usually just switches)
		:return:
		"""

		ret = {}
		name_lookup = '1.3.6.1.2.1.2.2.1.2'
		names = self._lookup_bulk('Port Names', name_lookup)
		if len(names) == 0:
			self.host.log('Device does not contain any port information, skipping')
			return None

		for key, val in names.items():
			port_id = key[len(name_lookup) + 1:]
			ret[port_id] = HostInterface()
			ret[port_id].name = val

		label_lookup = '1.3.6.1.2.1.31.1.1.1.18'
		labels = self._lookup_bulk('Port Labels', label_lookup)
		for key, val in labels.items():
			port_id = key[len(label_lookup) + 1:]
			ret[port_id].label = val

		mtu_lookup = '1.3.6.1.2.1.2.2.1.4'
		mtus = self._lookup_bulk('Port MTUs', mtu_lookup)
		for key, val in mtus.items():
			port_id = key[len(mtu_lookup) + 1:]
			ret[port_id].mtu = int(val)

		speed_lookup = '1.3.6.1.2.1.2.2.1.5'
		speeds = self._lookup_bulk('Port Speeds', speed_lookup)
		for key, val in speeds.items():
			port_id = key[len(speed_lookup) + 1:]
			ret[port_id].speed = format_link_speed(val)

		mac_lookup = '1.3.6.1.2.1.2.2.1.6.0'
		macs = self._lookup_bulk('Port MACs', mac_lookup)
		for key, val in macs.items():
			port_id = key[len(mac_lookup) + 1:]
			ret[port_id].mac = self._format_snmp_mac(val)

		admin_lookup = '1.3.6.1.2.1.2.2.1.7'
		admin_statuses = self._lookup_bulk('Admin Status', admin_lookup)
		for key, val in admin_statuses.items():
			port_id = key[len(admin_lookup) + 1:]
			ret[port_id].admin_status = 'UP' if val == '1' else 'DOWN'

		status_lookup = '1.3.6.1.2.1.2.2.1.8'
		user_statuses = self._lookup_bulk('User Status', status_lookup)
		for key, val in user_statuses.items():
			port_id = key[len(status_lookup) + 1:]
			ret[port_id].user_status = 'UP' if val == '1' else 'DOWN'

		vlan_pid_lookup = '1.3.6.1.2.1.17.7.1.4.5.1.1'
		vlan_pids = self._lookup_bulk('Native VLAN', vlan_pid_lookup)
		for key, val in vlan_pids.items():
			port_id = key[len(vlan_pid_lookup) + 1:]
			ret[port_id].vlan = val

		vlan_egress_lookup = '1.3.6.1.2.1.17.7.1.4.2.1.4'
		if 'Linux UBNT' in self.host.descr:
			# Ubiquiti devices have their port definitions reversed, (lowest port number at bit 0)
			reversed = True
		else:
			# Specification calls for lowest port number at bit 63
			reversed = False

		vlan_egresses = self._lookup_bulk('VLAN Egress', vlan_egress_lookup)
		for key, val in vlan_egresses.items():
			vlan_id = key[len(vlan_egress_lookup) + 3:]
			# Convert 0xf400040000000000 to an integer so we can check each bit
			# This translates to 0b11110100000000000000010000000000
			# where each port (left to right) is 1 or 0 if that VLAN is enabled on that port.
			vlan_set = int(val[2:], 16)

			for port, port_data in ret.items():
				if int(port) >= 64:
					# Only check the first 64 ports
					break
				if not reversed and vlan_set >> 64 - int(port) & 1 == 1:
					# This port is enabled for this VLAN
					port_data.vlan_allow.append(vlan_id)
					self.host.log('Port %s allows VLAN %s' % (port, vlan_id))
				elif reversed and vlan_set >> int(port) & 1 == 1:
					port_data.vlan_allow.append(vlan_id)
					self.host.log('Port %s allows VLAN %s' % (port, vlan_id))

		return ret


class MikrotikScan(DefaultScan):
	"""
	Mikrotik-specific scan function.
	"""

	def __init__(self, host):
		super().__init__(host)
		self.basic_lookups['serial'] = '1.3.6.1.4.1.14988.1.1.7.3.0'
		self.basic_lookups['os_version'] = None
		self.descr_parses = (
			(
				# RouterOS RB3011UiAS
				r'^(?P<os_name>RouterOS) (?P<model>.*)$',
				{'type': 'Router'}
			),
			(
				# CSS326-24G-2S+ SwOS v2.17
				r'^(?P<model>.*) SwOS v(?P<os_version>[^ ]+)$',
				{'type': 'Switch'}
			)
		)

	def scan(self):
		super().scan()

		self.host.manufacturer = 'Mikrotik'

		# Check firmware from one of two locations
		val = self._lookup_single('os_version', '1.3.6.1.4.1.14988.1.1.7.7.0')
		if val:
			self.host.os_version = val
		else:
			val = self._lookup_single('os_version', '1.3.6.1.4.1.14988.1.1.7.4')
			if val:
				self.host.os_version = val


class UbiquitiScan(DefaultScan):
	"""
	Ubiquiti-specific scan function.
	"""

	def __init__(self, host):
		super().__init__(host)
		self.descr_parses = (
			(
				# UAP-AC-Lite 6.6.77.15402
				r'^(?P<model>UAP-AC-Lite) (?P<os_version>[^ ]+)$',
				{'type': 'WIFI'}
			),
			(
				# UAP-AC-Pro-Gen2 6.6.77.15402
				r'^(?P<model>UAP-AC-Pro-Gen2) (?P<os_version>[^ ]+)$',
				{'type': 'WIFI'}
			),
		)
		self.basic_lookups['serial'] = ''

	def scan(self):
		super().scan()

		self.host.manufacturer = 'Ubiquiti Networks Inc.'
