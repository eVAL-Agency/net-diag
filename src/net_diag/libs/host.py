import json
import logging
import re
from datetime import datetime
from typing import Union


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

	ip_to_synced_ids = {}
	"""
	Cache of IP addresses to SuiteCRM IDs
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
		Set to True if this device is reachable on the network,
		generally set from a scanner upon a successful connection or ping.
		"""

		self.ping = None
		"""
		Ping response time for this device, (if available)
		:type ping: str|None
		"""

		self.links = None
		"""
		List of network/data ports on the device
		:type links: dict[str,HostLink]|None
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

		self.synced_id = None
		"""
		The ID of this object in the remote system, (if applicable)
		"""

		self.neighbors = {}
		"""
		List of neighbors (IP, Host) of this device.
		:type neighbors: dict[str, Host]
		"""

		self.include = False
		"""
		Set to True to force include this device in the scan results,
		useful for child devices under a parent device which do not fall under the default scan criteria.
		"""

		self.uplink_device = None
		"""
		IP address of the device that this host is connected to, (if applicable)
		:type uplink_device: str|None
		"""

		self.uplink_port = None
		"""
		Port name on the uplink device that this host is connected to, (if applicable)
		:type uplink_port: str|None
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
		return self.ping is not None or self.descr is not None

	def create_neighbor(self, ip: str):
		"""
		Create a neighboring Host device based off this host's config.

		:param ip:
		:return Host:
		"""
		if ip in self.neighbors:
			# If the neighbor already exists, return it
			return self.neighbors[ip]
		new_host = Host(ip, self.config, self.sync)
		self.neighbors[ip] = new_host
		return new_host

	def merge_from_host(self, other: 'Host'):
		"""
		Merge data from another Host into this one.
		This is useful for merging data from child devices into a parent device.

		(currently just supports MAC address)

		:param other: Host to merge data from
		:return:
		"""
		if self.mac is None and other.mac is not None:
			self.mac = other.mac
			self.log('Resolved MAC from neighbor')

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
				'serial',
				'description',
				'status',
				'msp_devices_id_c',
				'uplink_port',
			)
		)
		self.log('Found %s device(s)' % len(ret))

		if len(ret) == 0:
			# No records located, create
			data = self._generate_suitecrm_payload(None)
			self.log('Creating device record for %s: (%s)' % (self.ip, json.dumps(data)))
			result = self.sync.create('MSP_Devices', data | {'discover_log': self.log_lines})

			self.synced_id = result['data']['id']

			if 'ip_pri' in data and data['ip_pri']:
				self.ip_to_synced_ids[data['ip_pri']] = self.synced_id
			if 'ip_sec' in data and data['ip_sec']:
				self.ip_to_synced_ids[data['ip_sec']] = self.synced_id

		elif len(ret) == 1:
			# Update only, (do not overwrite existing data)
			self.synced_id = ret[0]['id']

			# Store the IP for future reference
			if ret[0]['ip_pri']:
				self.ip_to_synced_ids[ret[0]['ip_pri']] = ret[0]['id']
			if ret[0]['ip_sec']:
				self.ip_to_synced_ids[ret[0]['ip_sec']] = ret[0]['id']

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

	def _generate_suitecrm_uplink_device(self, server_data: Union[dict, None], data: dict):
		value = self.uplink_device
		key = 'msp_devices_id_c'
		if value and (server_data is None or server_data[key] == ''):
			# Local value set and CRM is empty; populate!
			# This value is expected to be an IP address of a device,
			# so try to resolve to that device's ID prior to uploading.
			if value in self.ip_to_synced_ids:
				data[key] = self.ip_to_synced_ids[value]
			else:
				ret = self.sync.find(
					'MSP_Devices',
					{'ip_pri': value},
					fields=('id', 'ip_pri')
				)
				if len(ret) == 1:
					# A device was located!  Store it and use that device.
					self.ip_to_synced_ids[ret[0]['ip_pri']] = ret[0]['id']
					data[key] = ret[0]['id']

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
		self._generate_suitecrm_payload_if_empty(server_data, data, 'uplink_port', self.uplink_port)

		self._generate_suitecrm_uplink_device(server_data, data)

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
		links = {}
		if self.links is not None:
			for name, iface in self.links.items():
				links[name] = iface.to_dict()

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
			'links': links,
			'os_name': self.os_name,
			'os_version': self.os_version,
			'descr': self.descr,
			'address': self.address,
			'city': self.city,
			'state': self.state,
			'ping': self.ping,
			'uplink_device': self.uplink_device,
			'uplink_port': self.uplink_port,
		}

		if 'fields' in self.config and self.config['fields'] is not None:
			# Only include the fields specified in the list
			data = {k: v for k, v in data.items() if k in self.config['fields']}

		return data


class HostLink:
	"""
	Represents a single interface (port) on a host.
	"""

	def __init__(self):
		"""
		Initialize a new HostLink
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
