import json
import logging
import re
from datetime import datetime
from urllib import request
import uuid
from enum import IntEnum, StrEnum


class HostPortAdminStatus(IntEnum):
	UP = 1       # Ready to pass packets
	DOWN = 2     # Administratively disabled / shut down
	TESTING = 3  # In some test mode


class HostPortUserStatus(IntEnum):
	UP = 1                # Ready to pass packets (Link up)
	DOWN = 2              # Interface down (No link / No cable)
	TESTING = 3           # In test mode, no operational packets can pass
	UNKNOWN = 4           # Status cannot be determined
	DORMANT = 5           # Waiting for an external trigger (e.g., dial-up/serial line)
	NOT_PRESENT = 6       # Refers to missing components (e.g., an empty SFP module slot)
	LOWER_LAYER_DOWN = 7  # This interface depends on a lower sub-layer which is down


class HostPortType(IntEnum):
	OTHER = 1
	REGULAR_1822 = 2
	HDH_1822 = 3
	DDN_X25 = 4
	RFC877_X25 = 5
	ETHERNET_CSMACD = 6     # Standard Physical Ethernet Port (10/100/1G/10G+)
	ISO88023_CSMACD = 7
	ISO88024_TOKENBUS = 8
	ISO88025_TOKENRING = 9
	STAR_LAN = 11
	FDDI = 15
	LAP_B = 16
	SDLC = 17
	T1 = 18
	CEPT = 19
	BASIC_ISDN = 20
	PRIMARY_ISDN = 21
	PROP_POINT_TO_POINT_SERIAL = 22
	PPP = 23                # Point-to-Point Protocol
	SOFTWARE_LOOPBACK = 24  # Local Loopback Interface (127.0.0.1)
	EON = 25
	ETHERNET_3MBIT = 26
	NSIP = 27
	SLIP = 28
	ULTRA = 29
	DS3 = 30
	SIP = 31
	FRAME_RELAY = 32
	RS232 = 33
	PARA = 34
	ARCNET = 35
	ATM = 37
	SONET = 39
	X25_PLE = 40
	ISO88026_MAN = 41
	SMDS_DXI = 42
	FR_FORWARD = 43
	CENTRONICS = 44
	IEEE80211 = 71          # Wireless LAN / Wi-Fi
	TUNNEL = 131            # Encapsulated tunnel interfaces (GRE, IPsec, etc.)
	IEEE8023AD_LAG = 161    # Link Aggregation / Port Channel / LACP Bond
	VLAN = 135              # Layer 2 Virtual LAN Interface (SVI)


class HostType(StrEnum):
	ACCESS = 'Access'
	CAMERA = 'Camera'
	ELEVATOR = 'Elevator'
	ENVIRONMENTAL = 'Environmental'
	FIREWALL = 'Firewall'
	GATEWAY = 'Gateway'
	PHONE = 'Phone'
	PRINTER = 'Printer'
	ROUTER = 'Router'
	SENSOR = 'Sensor'
	SERVER = 'Server'
	SWITCH = 'Switch'
	TV = 'TV'
	WIFI = 'Wifi'
	WORKSTATION = 'Workstation'


class Host:
	"""
	Represents a single host on the network.
	"""

	ip_to_synced_ids = {}
	"""
	Cache of IP addresses to SuiteCRM IDs
	"""

	def __init__(self, ip: str, config: dict):
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

		self.type: HostType | None = None
		"""
		Device type, (eg: switch, router, server, etc)
		:type type: HostType|None
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

		self.os_date = None
		"""
		Date of the OS release, supported by a few platforms
		Should be in YYYY-MM-DD format
		:type os_date: str|None
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

		self.ports = {}
		"""
		List of network/data ports on the device
		:type ports: dict[str,HostPort]
		"""

		self.config = config
		"""
		Configuration to use for this device, (eg: SNMP community string, scanners to use, etc)
		:type config: dict
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

		self.uptime = None
		"""
		Uptime (number of seconds) since the last boot, or None if not available
		:type uptime: int|None
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

	def create_neighbor(self, mac: str):
		"""
		Create a neighboring Host device based off this host's config.

		:param mac:
		:return Host:
		"""
		if mac in self.neighbors:
			# If the neighbor already exists, return it
			return self.neighbors[mac]
		new_host = Host('', self.config)
		new_host.mac = mac
		self.neighbors[mac] = new_host
		return new_host

	def find_port_by_mac(self, mac: str):
		"""
		Find a host port by its MAC address, or None if not found
		:param mac:
		:return: HostPort or None
		"""
		for port in self.ports.values():
			if port.mac.lower() == mac.lower():
				return port
		return None

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

	def sync_to_grist(self):
		"""
		:return:
		"""
		if self.mac is None:
			logging.warning('No MAC address found for Grist sync on %s' % self.ip)
			return

		# Grist does not require a hostname for devices, but it helps
		self.ensure_hostname()

		self.log('Pushing device data to Grist')
		payload = {
			'hostname': self.hostname,
			'manufacturer': self.manufacturer,
			'model': self.model,
			'ip_primary': self.ip,
			'mac_primary': self.mac,
			'floor': self.floor,
			'room': self.location,
			'discover_log': self.log_lines,
			'type': self.type,
			'_weak': ['hostname', 'manufacturer', 'model', 'type']
		}
		headers = {
			'Content-Type': 'application/json',
			'X-Token': self.sync[2]
		}
		req = request.Request(
			self.sync[1] + '/scripts/device_inventory',
			method='POST',
			headers=headers,
			data=json.dumps(payload).encode('utf-8')
		)
		result = request.urlopen(req)
		response = json.loads(result.read())
		if 'id' in response:
			self.synced_id = response['id']
			self.ip_to_synced_ids[self.ip] = response['id']

	def sync_to_glpi(self):
		"""
		:return:
		"""
		if self.mac is None:
			logging.warning('No MAC address found for GLPI sync on %s' % self.ip)
			return

		if self.type is None:
			logging.warning('No type found for GLPI sync on %s' % self.ip)

		if self.type in [HostType.SERVER, HostType.WORKSTATION]:
			logging.info('Skipping GLPI sync for computers')
			return

		# Ensure this device has a hostname
		self.ensure_hostname()

		self.log('Pushing device data to GLPI')
		item_type = 'NetworkEquipment'
		dev_type = 'Networking'
		if self.type == HostType.PRINTER:
			# Special case for printers
			item_type = 'Printer'
			dev_type = 'Printer'

		payload = {
			'deviceid': self.get_identifier(),
			'itemtype': item_type,
			'action': 'inventory',
			'content': {
				'versionclient': 'NetworkDiagnostics-Discover',
				'hardware': {
					'name': self.hostname,
					'chassis_type': str(self.type),
				},
				'network_ports': [],
				'network_device': {
					'mac': self.mac,
					'name': self.hostname,
					'type': dev_type,
				}
			},
		}

		if self.descr is not None:
			payload['content']['hardware']['description'] = self.descr
			payload['content']['network_device']['description'] = self.descr

		if self.contact is not None:
			payload['content']['network_device']['contact'] = self.contact

		if self.object_id is not None and self.descr is not None and 'glpi_credentials' in self.config:
			# Add the SNMP credentials, mostly for reference.
			payload['content']['network_device']['credentials'] = self.config['glpi_credentials']

		if self.gateway is not None:
			payload['content']['hardware']['defaultgateway'] = self.gateway

		if self.os_version is not None:
			firmware = {
				'version': self.os_version,
				'type': 'Firmware'
			}

			if self.os_name is not None:
				firmware['name'] = self.os_name
			if self.manufacturer is not None:
				firmware['manufacturer'] = self.manufacturer
			if self.os_date is not None:
				firmware['date'] = self.os_date

			payload['content']['firmwares'] = [firmware]

		if self.serial is not None:
			payload['content']['network_device']['serial'] = self.serial
		else:
			# GLPI really wants a serial
			payload['content']['network_device']['serial'] = self.get_identifier()

		if self.model is not None:
			payload['content']['network_device']['model'] = self.model

		if self.manufacturer is not None:
			payload['content']['network_device']['manufacturer'] = self.manufacturer

		if self.uptime is not None:
			payload['content']['network_device']['uptime'] = self.format_timeticks(self.uptime)

		counter = 0
		for port in self.ports.values():
			port_data = port.to_glpi()
			if 'ifnumber' not in port_data:
				port_data['ifnumber'] = counter
			payload['content']['network_ports'].append(port_data)

			counter = max(port_data['ifnumber'], counter) + 1

		self.log(json.dumps(payload))

		headers = {
			'Content-Type': 'application/json',
			'User-Agent': 'NetworkDiagnostics-Discover',
			'Authorization': 'GLPI-Token ' + self.config['glpi_token']
		}
		req = request.Request(
			self.config['glpi_url'] + '/front/inventory.php',
			method='POST',
			headers=headers,
			data=json.dumps(payload).encode('utf-8')
		)
		try:
			result = request.urlopen(req)
			response = json.loads(result.read())
			self.log(response)
		except request.HTTPError as e:
			error_body = e.read().decode('utf-8')
			self.log(error_body)

	def format_timeticks(self, ticks: int) -> str:
		"""
		Format timeticks (number of seconds) to a formatted string SNMP string

		:param ticks:
		:return:
		"""

		# Extract elements using sequential division matching centisecond markers
		days, remainder = divmod(ticks, 8640000)      # 100 * 60 * 60 * 24
		hours, remainder = divmod(remainder, 360000)     # 100 * 60 * 60
		minutes, remainder = divmod(remainder, 6000)      # 100 * 60
		seconds, centiseconds = divmod(remainder, 100)

		return f"{days} days, {hours:02}:{minutes:02}:{seconds:02}"

	def get_identifier(self) -> str:
		"""
		Get a mostly unique identifier for this device based off its mac

		:return:
		"""

		if self.manufacturer is not None:
			dev_id = [self.manufacturer.replace(' ', '').replace('.', '').lower()[:8]]
		else:
			dev_id = ['device']

		dev_id.append(self.mac.replace(':', '').lower())

		# Include the network diagnostics to track where this device was seen
		dev_id.append('network-diagnostics')

		return '-'.join(dev_id)

	def generate_device_uuid(self) -> str:
		"""
		Generates a repeatable, deterministic UUID v5 from any device string.
		"""
		# 1. Establish a standard baseline Namespace.
		# We use the built-in OID namespace as an anchor for infrastructure assets.
		NAMESPACE = uuid.NAMESPACE_OID

		device_identifier = self.get_identifier()

		# 2. Clean the input string to ensure minor whitespace differences don't break the hash
		clean_identifier = device_identifier.strip().lower()

		# 3. Generate the deterministic UUID v5
		device_uuid = uuid.uuid5(NAMESPACE, clean_identifier)

		return str(device_uuid)

	def ensure_hostname(self):
		"""
		Ensure this device has a hostname, (of at least something)

		This is useful because SuiteCRM requires a name for devices
		:return:
		"""
		if self.hostname is None or self.hostname == '':
			self.hostname = self.ip

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
		ports = {}
		for name, iface in self.ports.items():
			ports[name] = iface.to_dict()

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
			'ports': ports,
			'os_name': self.os_name,
			'os_version': self.os_version,
			'descr': self.descr,
			'address': self.address,
			'city': self.city,
			'state': self.state,
			'ping': self.ping,
		}

		if 'fields' in self.config and self.config['fields'] is not None:
			# Only include the fields specified in the list
			data = {k: v for k, v in data.items() if k in self.config['fields']}

		return data


class HostPort:
	"""
	Represents a single interface (port) on a host.
	"""

	def __init__(self):
		"""
		Initialize a new HostPort
		"""
		self.number: int | None = None
		self.name: str | None = None
		self.label: str | None = None
		self.ips: list = []
		self.mac: str | None = None
		self.admin_status: HostPortAdminStatus | None = None
		self.user_status: HostPortUserStatus | None = None
		self.mtu: int | None = None
		self.speed: int | None = None
		self.vlan = None
		self.vlan_allow = []
		self.type: HostPortType | None = None
		self.bytes_rx: int | None = None
		self.bytes_tx: int | None = None
		self.errors_rx: int | None = None
		self.errors_tx: int | None = None
		self.connections: list[str] = []

	def to_dict(self) -> dict:
		"""
		Convert this interface to a dictionary representation
		:return: dict
		"""
		data = {}

		# Only include keys that are not None or empty lists
		# This is because many scanners will only populate a subset of these fields
		keys = [
			'name', 'label', 'ips', 'mac',
			'admin_status', 'user_status',
			'mtu', 'speed', 'vlan', 'vlan_allow', 'type',
			'bytes_rx', 'bytes_tx', 'errors_rx', 'errors_tx',
			'connections'
		]
		for key in keys:
			value = getattr(self, key)
			if value is None:
				continue
			if isinstance(value, list) and len(value) == 0:
				continue

			data[key] = value
		return data

	def to_glpi(self) -> dict:
		link_data = {}
		field_mapping = {
			'speed': 'ifspeed',
			'name': 'ifname',
			'label': 'ifalias',
			'number': 'ifnumber',
			'mac': 'mac',
			'ips': 'ips',
			'user_status': 'ifstatus',
			'admin_status': 'ifinternalstatus',
			'mtu': 'ifmtu',
			'type': 'iftype',
			'bytes_rx': 'ifinbytes',
			'bytes_tx': 'ifoutbytes',
			'errors_rx': 'ifinerrors',
			'errors_tx': 'ifouterrors',
		}

		for attr, key in field_mapping.items():
			if getattr(self, attr) is not None:
				link_data[key] = getattr(self, attr)

		if len(self.connections) > 0:
			link_data['connections'] = []
			for connection in self.connections:
				link_data['connections'].append({'mac': connection})

		return link_data
