import json
import logging
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
	ISO88022_LLC = 10
	STAR_LAN = 11
	G703_AT_64K = 12
	G703_AT_2MB = 13
	RESERVED_14 = 14
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
	ATM_SUB_INTERFACE = 36
	ATM = 37
	X25_HUNT_GROUP = 38
	SONET = 39
	X25_PLE = 40
	ISO88026_MAN = 41
	SMDS_DXI = 42
	FR_FORWARD = 43
	CENTRONICS = 44
	MAC_LAYER_FILTER_PSEUDO = 45
	REPEATER_PSEUDO_INTERFACE = 46
	HIPPI = 47
	MODEM = 48
	AAL5 = 49
	SONET_PATH = 50
	SONET_VT = 51
	SMDS_ICIP = 52
	PROPRIETARY_VIRTUAL = 53
	PROPRIETARY_MULTIPLEX = 54
	FAST_100_BASE_VG = 55
	FIBRE_CHANNEL = 56
	HIPPI_INTERFACE = 57
	FRAME_RELAY_INTERCONNECT = 58
	ATM_FUNI = 59
	ATM_IMA = 60
	PPP_MULTILINK_BUNDLE = 61
	IP_OVER_CDLM = 62
	ARAP = 63
	PROP_CN_S_S_LINK = 64
	IP_OVER_ATM = 65
	DIGITAL_SIGNAL_0 = 66
	DIGITAL_SIGNAL_1 = 67
	PROPRIETARY_P2P_STRUCTURE = 68
	SR_PDS = 69
	ASYNC = 70
	IEEE80211 = 71          # Wireless LAN / Wi-Fi
	INTERLEAVE = 72
	FAST = 73
	IP_IN_IP = 74
	DIGITAL_SIGNAL_3 = 75
	RADSL = 76
	SDSL = 77
	VDSL = 78
	ISO88025_CR_FP = 79
	MYRINET = 80
	VOICE_EM = 81
	VOICE_FXO = 82
	VOICE_FXS = 83
	VOICE_ENCAP = 84
	VOICE_OVER_IP = 85
	ATM_DXI = 86
	ATM_PASSTHROUGH = 87
	L3_IP_TUNNEL = 88
	COFFEE = 89                 # Yes, actual RFC 2325 hyper text coffee pot control
	CES = 90
	ATM_SUB_LOGICAL = 91
	V35 = 92
	HSSI = 93
	X25_ASYNCH = 94
	X25_OVER_TCP = 95
	X25_B_CHANNEL = 96
	MIL_STD_188_154 = 97
	SNA_B_CHANNEL = 98
	SNA_OVER_LLC = 99
	IP_OVER_FRAME_RELAY = 100
	TOKEN_RING_P2P = 101
	RAC = 102
	ATM_LOGICAL = 103
	MPEG = 104
	PROP_WIRELESS_P2P = 105
	FR_DLCI_SUB_INTERFACE = 106
	G703_AT_2MB_STRUCTURED = 107
	G703_AT_64K_STRUCTURED = 108
	DIGITAL_SIGNAL_1_DATA = 109
	ISDN_U_INTERFACE = 110
	LAP_D = 111
	IP_SWITCH = 112
	RSRB = 113
	DLSW = 114
	TI_IN_IN = 115
	DIGITAL_SIGNAL_2 = 116
	G703_AT_8MB = 117
	G703_AT_34MB = 118
	G703_AT_140MB = 119
	PROP_MULTIPLEX_SUB_INTERFACE = 120
	HL_SERIAL = 121
	MPLS = 122
	MULTI_PROTO_INTERNAL_SUPPORT = 123
	L2_VLAN_FAST_ETHERNET = 124
	L3_VLAN_FAST_ETHERNET = 125
	MPOA_CLIENT = 126
	MPOA_SERVER = 127
	STACK_TO_STACK = 128
	VIRTUAL_IP_ADDRESS = 129
	MPLS_TUNNEL = 130
	TUNNEL = 131            # Encapsulated tunnel interfaces (GRE, IPsec, etc.)
	RESERVED_132 = 132
	RESERVED_133 = 133
	IP_OVER_TR = 134
	L3_VLAN = 136
	L2_VLAN = 137
	WIRELESS_MAC = 138
	WIRELESS_PHY = 139
	VOICE_OVER_ATM = 140
	VOICE_OVER_FRAME_RELAY = 141
	IDSL = 142
	BOND_INTERFACE = 143
	FRAME_RELAY_UNI = 144
	MFR_UNI = 145
	CESOPSN = 146
	LAP_F = 147
	VIRTUAL_PPPOE = 148
	VIRTUAL_PPPOA = 149
	TE_LINK = 150
	ETHERNET_MAC_LAYER = 151
	PROP_ATM = 152
	G709_ODU = 153
	G709_OTU = 154
	IEEE8023AD_LAG = 161    # Link Aggregation / Port Channel / LACP Bond
	VLAN = 135              # Layer 2 Virtual LAN Interface (SVI)
	BRIDGE = 209                # Transparent bridge interface (e.g. MikroTik Bridge)
	WWAN = 243                  # Wireless WAN / LTE / 5G Cellular Interfaces
	XDSL = 251                  # Generic xDSL Interface

	@classmethod
	def from_int(cls, value: int) -> 'HostPortType':
		try:
			return cls(value)
		except ValueError:
			return cls.OTHER


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


class HostConsumableType(IntEnum):
	OTHER = 1
	UNKNOWN = 2
	TONER = 3
	WASTE_TONER = 4
	INK = 5
	INK_CARTRIDGE = 6
	INK_RIBBON = 7
	WASTE_INK = 8
	OPC = 9
	DEVELOPER = 10
	FUSER_OIL = 11
	SOLID_WAX = 12
	RIBBON_WAX = 13
	WASTE_WAX = 14
	FUSER = 15
	CORONA_WIRE = 16
	FUSER_OIL_WICK = 17
	CLEANER_UNIT = 18
	FUSER_CLEANING_PAD = 19
	TRANSFER_UNIT = 20
	TONER_CARTRIDGE = 21
	FUSER_OILER = 22
	WATER = 23
	WASTE_WATER = 24
	GLUE_WATER_ADDITIVE = 25
	WASTE_PAPER = 26
	BINDING_SUPPLY = 27
	BANDING_SUPPLY = 28
	STITCHING_WIRE = 29
	SHRINK_WRAP = 30
	PAPER_WRAP = 31
	STAPLES = 32
	INSERTS = 33
	COVERS = 34
	MATTE_TONNER = 35
	MATTE_INK = 36


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

		self.scanners = {}
		"""
		Dictionary of scanners and any parameters needed by each

		If a scanner is present, it is assumed to be valid,
		this is useful if HTTP and SNMP are both used, but only some devices actually support one or the other.
		:type scanners: dict<str, *>
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

		self.os_vendor = None
		"""
		Name of the OS vendor
		:type os_vendor: str|None
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

		self.children_count = 0
		"""
		Number of children directly under this device

		A child is generally a network device which is physically connected to this device
		such as an external serially-connected sensor

		:type children_count: int
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

		self.consumables = {}
		"""
		Consumables, usually for printers
		:type consumables: dict[str, HostConsumable]
		"""

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
			return

		if self.type in [HostType.SERVER, HostType.WORKSTATION]:
			logging.info('Skipping GLPI sync for computers')
			return

		# Ensure this device has a hostname
		self.ensure_hostname()

		self.log('Pushing device data to GLPI')
		item_type = 'NetworkEquipment'
		network_device = {
			'mac': self.mac,
			'name': self.hostname,
			'type': 'Networking',
		}
		if self.type == HostType.PRINTER:
			# Special case for printers
			item_type = 'Printer'
			network_device['type'] = 'Printer'

		payload = {
			'deviceid': self.get_identifier(),
			# Item type defines the type of incoming object, but the schema restricts this severely.
			'itemtype': item_type,
			'action': 'inventory',
			'content': {
				'versionclient': 'GLPI-Agent_v1.18-1_NetworkDiagnostics-Discover',
				'hardware': {
					'name': self.hostname,
					'chassis_type': str(self.type),
				},
			},
		}

		if 'glpi_tag' in self.config and self.config['glpi_tag']:
			payload['tag'] = self.config['glpi_tag']

		if self.descr is not None:
			payload['content']['hardware']['description'] = self.descr
			if network_device:
				network_device['description'] = self.descr

		if self.contact is not None and network_device:
			network_device['contact'] = self.contact

		if (
			self.object_id is not None
			and self.descr is not None
			and 'glpi_credentials' in self.config
			and network_device
		):
			# Add the SNMP credentials, mostly for reference.
			network_device['credentials'] = self.config['glpi_credentials']

		if self.gateway is not None:
			payload['content']['hardware']['defaultgateway'] = self.gateway

		if self.os_version is not None:
			firmware = {
				'version': self.os_version,
				'type': 'Firmware'
			}

			if self.os_name is not None:
				firmware['name'] = self.os_name

			if self.os_vendor is not None:
				firmware['manufacturer'] = self.os_vendor
			elif self.manufacturer is not None:
				firmware['manufacturer'] = self.manufacturer

			if self.os_date is not None:
				firmware['date'] = self.os_date

			payload['content']['firmwares'] = [firmware]

		if self.serial is not None:
			payload['content']['hardware']['serial'] = self.serial
			if network_device:
				network_device['serial'] = self.serial
		else:
			# GLPI really wants a serial
			payload['content']['hardware']['serial'] = self.get_identifier()
			if network_device:
				network_device['serial'] = self.get_identifier()

		if self.model is not None:
			payload['content']['hardware']['model'] = self.model
			if network_device:
				network_device['model'] = self.model

		if self.manufacturer is not None:
			payload['content']['hardware']['manufacturer'] = self.manufacturer
			if network_device:
				network_device['manufacturer'] = self.manufacturer

		if len(self.ports) > 0:
			payload['content']['network_ports'] = []
			counter = 0
			for port in self.ports.values():
				port_data = port.to_glpi()
				if 'ifnumber' not in port_data:
					port_data['ifnumber'] = counter
				payload['content']['network_ports'].append(port_data)

				counter = max(port_data['ifnumber'], counter) + 1

		if self.type == HostType.PRINTER and len(self.consumables) > 0:
			consumables = {}
			for consumable in self.consumables.values():
				consumables |= consumable.to_glpi_cartridge()
			payload['content']['cartridges'] = [consumables]

		if network_device:
			payload['content']['network_device'] = network_device

		self.log(json.dumps(payload))

		if 'dry_run' in self.config and self.config['dry_run']:
			print(json.dumps(payload))
			return

		headers = {
			'Content-Type': 'application/json',
			'User-Agent': 'GLPI-Agent/1.18 (NetworkDiagnostics-Discover)',
		}

		# As long as GLPI-Agent/... is set as the User Agent, a token isn't required by default.
		if 'glpi_token' in self.config:
			headers['Authorization'] = 'GLPI-Token ' + self.config['glpi_token']

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

	def __repr__(self) -> str:
		return f'<Host ip:{self.ip} mac:{self.mac} hostname:{self.hostname} descr:{self.descr}>'

	def to_dict(self) -> dict:
		data = {
			'ip': self.ip,
			'mac': self.mac,
			'hostname': self.hostname,
			'gateway': self.gateway,
			'contact': self.contact,
			'location': self.location,
			'type': self.type,
			'manufacturer': self.manufacturer,
			'model': self.model,
			'serial': self.serial,
			'os_name': self.os_name,
			'os_version': self.os_version,
			'descr': self.descr,
			'ping': self.ping,
		}

		if len(self.consumables) > 0:
			data['consumables'] = []
			for consumable in self.consumables:
				data['consumables'].append(consumable.to_dict())

		if len(self.ports) > 0:
			data['ports'] = []
			for port in self.ports.values():
				data['ports'].append(port.to_dict())

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


class HostConsumable:
	def __init__(self):
		self.description: str | None = None
		self.type: HostConsumableType | None = None
		self.color: str | None = None
		self.current: int | None = None
		self.unit: int | None = None
		self.max: int | None = None

	def to_dict(self) -> dict:
		"""
		Convert this interface to a dictionary representation
		:return: dict
		"""
		data = {}

		# Only include keys that are not None or empty lists
		# This is because many scanners will only populate a subset of these fields
		keys = [
			'description', 'type', 'color', 'current', 'unit', 'max'
		]
		for key in keys:
			value = getattr(self, key)
			if value is None:
				continue
			if isinstance(value, list) and len(value) == 0:
				continue

			data[key] = value
		return data

	def to_glpi_cartridge(self) -> dict:
		"""
		GLPI has a weird format for cartridges; all values are expected to be merged into a single object.

		:return:
		"""
		key_name = self.description

		if self.max <= 0 or self.current <= 0:
			return {key_name: "0"}
		else:
			return {key_name: str(self.current / self.max * 100)}
