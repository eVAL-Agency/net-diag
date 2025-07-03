from typing import Union
from net_diag.libs.snmputils import snmp_parse_descr, snmp_lookup_single, snmp_lookup_bulk
import asyncio


class SNMPScanner:
	"""
	SNMP Scanner class for scanning devices using SNMP protocol.
	"""

	def __init__(self, host):
		self.host = host

	def scan(self):
		"""
		Scan this device for all SNMP values
		:param community:
		:return:
		"""
		if 'community' not in self.host.config:
			# SNMP scans require a community string
			return

		val = self.get_descr()
		if val is None:
			# Initial lookup of DESCR failed; do not try to continue.
			return
		self._store_descr(val)

		mac = self.get_mac()
		if mac is not None:
			self.host.mac = mac

		hostname = self.get_hostname()
		if hostname is not None:
			self.host.hostname = hostname

		contact = self.get_contact()
		if contact is not None:
			self.host.contact = contact

		firmware = self.get_firmware()
		if firmware is not None:
			self.host.os_version = firmware

		model = self.get_model()
		if model is not None:
			self.host.model = model

		location = self.get_location()
		if location is not None:
			self.host.set_location(location)

		self.host.ports = self.get_ports()

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

	def get_descr(self) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the description of the device.
		:return:
		"""
		return self._lookup_single('DESCR', '1.3.6.1.2.1.1.1.0')

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

	def get_hostname(self) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the hostname of the device.
		:return:
		"""
		return self._lookup_single('hostname', '1.3.6.1.2.1.1.5.0')

	def get_contact(self) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:return:
		"""
		return self._lookup_single('contact', '1.3.6.1.2.1.1.4.0')

	def get_location(self) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the MAC Address of the device.
		:return:
		"""
		return self._lookup_single('location', '1.3.6.1.2.1.1.6.0')

	def get_firmware(self) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the firmware version of the device.
		:return:
		"""
		return self._lookup_single('firmware version', '1.3.6.1.2.1.16.19.2')

	def get_model(self) -> Union[str, None]:
		"""
		Perform a basic SNMP scan to get the model version of the device.
		:return:
		"""
		return self._lookup_single('model', '1.3.6.1.2.1.16.19.3.0')

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
			ret[port_id] = {
				'name': val,
				'vlan_allow': [],
			}

		label_lookup = '1.3.6.1.2.1.31.1.1.1.18'
		labels = self._lookup_bulk('Port Labels', label_lookup)
		for key, val in labels.items():
			port_id = key[len(label_lookup) + 1:]
			ret[port_id]['label'] = val

		mtu_lookup = '1.3.6.1.2.1.2.2.1.4'
		mtus = self._lookup_bulk('Port MTUs', mtu_lookup)
		for key, val in mtus.items():
			port_id = key[len(mtu_lookup) + 1:]
			ret[port_id]['mtu'] = int(val)

		speed_lookup = '1.3.6.1.2.1.2.2.1.5'
		speeds = self._lookup_bulk('Port Speeds', speed_lookup)
		for key, val in speeds.items():
			port_id = key[len(speed_lookup) + 1:]
			ret[port_id]['speed'] = self._format_snmp_speed(val)

		mac_lookup = '1.3.6.1.2.1.2.2.1.6.0'
		macs = self._lookup_bulk('Port MACs', mac_lookup)
		for key, val in macs.items():
			port_id = key[len(mac_lookup) + 1:]
			ret[port_id]['mac'] = self._format_snmp_mac(val)

		admin_lookup = '1.3.6.1.2.1.2.2.1.7'
		admin_statuses = self._lookup_bulk('Admin Status', admin_lookup)
		for key, val in admin_statuses.items():
			port_id = key[len(admin_lookup) + 1:]
			ret[port_id]['admin_status'] = 'UP' if val == '1' else 'DOWN'

		status_lookup = '1.3.6.1.2.1.2.2.1.8'
		user_statuses = self._lookup_bulk('User Status', status_lookup)
		for key, val in user_statuses.items():
			port_id = key[len(status_lookup) + 1:]
			ret[port_id]['user_status'] = 'UP' if val == '1' else 'DOWN'

		vlan_pid_lookup = '1.3.6.1.2.1.17.7.1.4.5.1.1'
		vlan_pids = self._lookup_bulk('Native VLAN', vlan_pid_lookup)
		for key, val in vlan_pids.items():
			port_id = key[len(vlan_pid_lookup) + 1:]
			ret[port_id]['native_vlan'] = val

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
					port_data['vlan_allow'].append(vlan_id)
					self.host.log('Port %s allows VLAN %s' % (port, vlan_id))
				elif reversed and vlan_set >> int(port) & 1 == 1:
					port_data['vlan_allow'].append(vlan_id)
					self.host.log('Port %s allows VLAN %s' % (port, vlan_id))

		return ret

	def _store_descr(self, val: str):
		"""
		Parse and store the description of the device.
		:param val:
		:return:
		"""

		if val is None:
			return

		self.host.descr = val
		data = snmp_parse_descr(val)
		for key, value in data.items():
			self.host.log('Parsed %s as [%s]' % (key, value))
			setattr(self.host, key, value)

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

	def _format_snmp_speed(self, val: str) -> Union[str, None]:
		"""
		Format a speed value from SNMP data to a more human-readable format

		:param val:
		:return:
		"""
		if val == '25000000000':
			return '25gbps'
		elif val == '10000000000':
			return '10gbps'
		elif val == '2500000000':
			return '2.5gbps'
		elif val == '1000000000':
			return '1gbps'
		elif val == '100000000':
			return '100mbps'
		elif val == '10000000':
			return '10mbps'
		else:
			return val
