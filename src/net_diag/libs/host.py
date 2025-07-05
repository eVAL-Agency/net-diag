import json
import logging
import re
from datetime import datetime
from typing import Union
from mac_vendor_lookup import MacLookup


class Host:
	"""
	Represents a single host on the network.
	"""

	TYPE_ACCESS = 'Access'
	TYPE_CAMERA = 'Camera'
	TYPE_ELEVATOR = 'Elevator'
	TYPE_ENVIRONMENTAL = 'Environmental'
	TYPE_FIREWALL = 'Firewall'
	TYPE_GATEWAY = 'Gateway'
	TYPE_PHONE = 'Phone'
	TYPE_PRINTER = 'Printer'
	TYPE_ROUTER = 'Router'
	TYPE_SENSOR = 'Sensor'
	TYPE_SERVER = 'Server'
	TYPE_SWITCH = 'Switch'
	TYPE_TV = 'TV'
	TYPE_WIFI = 'Wifi'
	TYPE_WORKSTATION = 'Workstation'

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

		self.gateway = None
		"""
		Default gateway IP of the device
		:type gateway: str|None
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

		self.os_name = None
		"""
		Name of operating system
		:type os_name: str|None
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

		self.interfaces = None
		"""
		List of network/data ports on the device
		:type interfaces: dict[str,HostInterface]|None
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

	'''
	(@todo, move the socket logic to somewhere else.)
	def scan(self):
		"""
		Perform a full scan of the device to store all details.
		:return:
		"""

		if 'icmp' in self.config['scanners']:
			(net_diag.libs.scanners.ICMPScanner(self)).scan()

		if 'snmp' in self.config['scanners']:
			(net_diag.libs.scanners.SNMPScanner(self)).scan()

		if 'trane-tracer-sc' in self.config['scanners']:
			(net_diag.libs.scanners.TraneTracerSCScanner(self)).scan()

		if self.hostname is None or self.hostname == '':
			try:
				self.log('Hostname not set, trying a socket to resolve')
				self.hostname = socket.gethostbyaddr(self.ip)[0]
				self.log('%s = %s' % (self.ip, self.hostname))
			except socket.herror:
				self.log('socket lookup failed')
				pass
	'''

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
		interfaces = {}
		if self.interfaces is not None:
			for name, interface in self.interfaces.items():
				interfaces[name] = interface.to_dict()

		data = {
			'ip': self.ip,
			'mac': self.mac,
			'hostname': self.hostname,
			'gateway': self.gateway,
			'contact': self.contact,
			'floor': self.floor,
			'location': self.location,
			'type': self.type,
			'manufacturer': self.manufacturer,
			'model': self.model,
			'serial': self.serial,
			'interfaces': interfaces,
			'os_name': self.os_name,
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


class HostInterface:
	"""
	Represents a single interface (port) on a host.
	"""

	def __init__(self):
		"""
		Initialize a new HostInterface
		"""
		self.name = None
		self.label = None
		self.ip = None
		self.mac = None
		self.admin_status = None
		self.user_status = None
		self.mtu = None
		self.speed = None
		self.vlan = None
		self.vlan_allow = []

	def to_dict(self) -> dict:
		"""
		Convert this interface to a dictionary representation
		:return: dict
		"""
		data = {}

		# Only include keys that are not None or empty lists
		# This is because many scanners will only populate a subset of these fields
		keys = ['name', 'label', 'ip', 'mac', 'admin_status', 'user_status', 'mtu', 'speed', 'vlan', 'vlan_allow']
		for key in keys:
			value = getattr(self, key)
			if value is None:
				continue
			if isinstance(value, list) and len(value) == 0:
				continue

			data[key] = value
		return data
