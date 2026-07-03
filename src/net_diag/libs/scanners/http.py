import socket
import requests
from bs4 import BeautifulSoup, Tag
import re
import time

from requests import Response
from requests.auth import HTTPDigestAuth, AuthBase
from requests.exceptions import RequestException

from net_diag.libs.scanners import ScannerInterface
from net_diag.libs.net_utils import format_link_speed
from net_diag.libs.host import Host, HostPort, HostType


class HTTPScanner(ScannerInterface):
	"""
	HTTP Scanner class for performing HTTP scans and collection tasks.
	"""

	def __init__(self, host: Host, port: int):
		"""
		:param host:
		"""
		super().__init__(host)
		self.port: int = port
		self.auth: None | AuthBase = None

	@classmethod
	def scan(cls, host: Host):
		"""
		Perform an HTTP/S scan on the target.
		"""
		host.log('Checking HTTP and HTTPS on %s' % (host.ip,))
		try:
			# Attempts a TCP connection; raises an exception if it times out or is refused
			with socket.create_connection((host.ip, 443), timeout=1):
				host.log('Port 443 appears to be open!')
				scanner = cls._perform_discovery(host, 443)
				if scanner is not None:
					return scanner._scan()
		except (socket.timeout, ConnectionRefusedError, OSError):
			host.log('Port 443 appears to be closed!')

		try:
			# Attempts a TCP connection; raises an exception if it times out or is refused
			with socket.create_connection((host.ip, 80), timeout=1):
				host.log('Port 80 appears to be open!')
				scanner = cls._perform_discovery(host, 80)
				if scanner is not None:
					return scanner._scan()
		except (socket.timeout, ConnectionRefusedError, OSError):
			host.log('Port 80 appears to be closed!')

	@classmethod
	def scan_neighbors(cls, host: Host):
		pass

	@classmethod
	def matches(cls, response: Response) -> bool:
		return True

	@classmethod
	def _perform_discovery(cls, host: Host, port: int) -> ScannerInterface | None:
		"""
		Initial discovery to detect the type of scanning to perform, or retrieve a standard scanner instead

		:param host:
		:param port:
		:return:
		"""
		protocol = "https" if port == 443 else "http"
		url = f"{protocol}://{host.ip}:{port}"

		try:
			# verify=False ignores self-signed SSL cert errors typical on local subnets
			# timeout ensures the script doesn't hang on slow responses
			response = requests.get(url, timeout=2.0, verify=False)
			server_header = response.headers.get('Server', '').lower()
			host.log('HTTP Server: %s' % (server_header,))
			# Parse the HTML content
			soup = BeautifulSoup(response.text, 'html.parser')
			page_title = soup.title.string.lower() if soup.title else ""
			host.log('HTTP Page Title: %s' % (page_title,))

			# Try the different HTTP scanners
			if TraneTracerSCScanner.matches(response):
				# Matches a Trane Tracer SC
				return TraneTracerSCScanner(host, port)
			else:
				# No matches available, default to the baseline HTTP scanner
				return HTTPScanner(host, port)
		except requests.exceptions.RequestException as e:
			host.log('HTTP retrieval on port %s failed with %s' % (port, e))
			return None

	def _ready(self) -> bool:
		"""
		Check if this scanner has everything it needs to scan

		:return:
		"""
		return True

	def _scan(self):
		"""
		Perform a device scan

		:return:
		"""
		pass

	def _scan_neighbors(self):
		"""
		Perform a neighbor scan, usually of children under this device

		:return:
		"""
		pass

	def _post(self, url: str, data, headers: dict | None = None) -> Response | None:
		protocol = "https" if self.port == 443 else "http"
		url = f"{protocol}://{self.host.ip}:{self.port}{url}"

		try:
			return requests.post(
				url,
				auth=self.auth,
				data=data,
				headers=headers,
				timeout=10
			)
		except requests.exceptions.RequestException as e:
			self.host.log('Failed to perform POST to %s: %s' % (url, e))
			return None


class TraneTracerSCScanner(HTTPScanner):
	"""
	Tracer SC is a Trane product that provides advanced control and monitoring capabilities for HVAC systems.
	It is designed to optimize energy efficiency and enhance system performance.
	"""

	def __init__(self, host: Host, port: int):
		super().__init__(host, port)
		self._remote_networks = {}
		username = self.host.config.get('http_username', '')
		password = self.host.config.get('http_password', '')

		if username != '' and password != '':
			self.auth = HTTPDigestAuth(username, password)

	@classmethod
	def matches(cls, response: Response) -> bool:
		server_header = response.headers.get('Server', '')
		# Parse the HTML content
		soup = BeautifulSoup(response.text, 'html.parser')
		page_title = soup.title.string if soup.title else ""

		# Assumed to be a Tracer SC if matches
		return server_header == 'nginx' and page_title == 'Tracer Synchrony' and 'Trane U.S. Inc.' in response.text

	def _ready(self) -> bool:
		if self.auth is None:
			self.host.log('Cannot perform Tracer SC scan; http-username or http-password are not defined!')
			return False

		return True

	def _scan(self):
		if not self._ready():
			return

		try:
			self.host.log('Retrieving Tracer SC configuration data')
			xml = self._get_batch(['/evox/about', '/evox/config/bacnet_global'], 'general_info')
		except RequestException as e:
			self.host.log('Failed to retrieve Tracer SC configuration data.\n' + str(e))
			return

		about = xml.find('obj', {'href': '/evox/about'})
		bacnet_global = xml.find('obj', {'href': '/evox/config/bacnet_global'})

		self.host.type = HostType.ENVIRONMENTAL
		self.host.hostname = bacnet_global.find('str', {'name': 'name'}).get('val')
		self.host.set_location(bacnet_global.find('str', {'name': 'location'}).get('val'))
		self.host.manufacturer = about.find('str', {'name': 'vendorName'}).get('val')
		self.host.model = about.find('str', {'name': 'productName'}).get('val')
		self.host.serial = about.find('str', {'name': 'hardwareSerialNumber'}).get('val')
		self.host.os_version = about.find('str', {'name': 'productVersion'}).get('val')
		if self.host.os_version.startswith('v'):
			# Trim off the leading 'v' version indicator if present
			self.host.os_version = self.host.os_version[1:]

		self.host.ports = self.get_ports()

		# Find the mac address from the interfaces
		for iface in self.host.ports.values():
			if iface.ip == self.host.ip:
				self.host.mac = iface.mac
				break

	def _scan_neighbors(self):
		if not self._ready():
			return

		self._scan_bridges()
		self._scan_devices()

	def _scan_bridges(self):
		# Issue a request to have the controller scan for bridges
		self.host.log('Initiating bridge discovery scan')
		res = self._get_call(
			'/evox/bacnet/availableNetworks',
			'<bool val="true"/>',
			'discover_bridges'
		)

		counter = 0
		complete = False
		while counter < 5:
			counter += 1
			time.sleep(5)
			res = self._get_call(
				'/evox/bacnet/availableNetworks',
				'<obj is="obix:Nil"/>',
				'bridges'
			)

			if self._get_tag_val(res, 'enum', 'status', recursive=True) == 'complete':
				# Scan marked as complete, so we have all the data necessary
				self.host.log('Bridge discovery complete')
				complete = True
				break

		if complete and res:
			counter = 0
			networks = res.find('list', {'name': 'networks'})
			for dev in networks.find_all('obj', recursive=False):
				counter += 1
				# <str name="routerAddress" val="192.168.0.153:47810"/>
				ip = self._get_tag_val(dev, 'str', 'routerAddress')
				ip = ip.split(':')[0]
				# <str name="routerAddressBinhex" val="C0A844887744"/>
				mac = self._get_tag_val(dev, 'str', 'routerAddressBinhex')
				mac = ':'.join(mac[i:i + 2] for i in range(0, len(mac), 2))
				# <int name="networkNumber" val="31"/>
				network = self._get_tag_val(dev, 'int', 'networkNumber')

				host = self.host.create_neighbor(ip)
				host.log('Discovered bridge device from source host %s %s' % (self.host.hostname, self.host.ip))
				host.mac = mac
				host.hostname = dev.find('str', {'name': 'routerName'}).get('val')
				host.manufacturer = dev.find('str', {'name': 'routerVendorName'}).get('val')
				host.type = HostType.ENVIRONMENTAL

				self._remote_networks[network] = (
					ip,
					dev.find('str', {'name': 'remoteDatalinkName'}).get('val'),
				)

			self.host.log('Discovered %d bridged devices' % counter)

	def _scan_devices(self):
		equipment_uris = {}
		lookups = []
		self.host.log('Getting connected devices')
		counter = 0
		xml = self._get_batch(['/evox/equipment/installedSummary'], 'devices')
		container = xml.find('list', {'href': '/evox/equipment/installedSummary'})
		for dev in container.find_all('obj', recursive=False):
			mac = None
			ip = None
			uplink_port = None
			uplink_device = None
			equipment_uri = self._get_tag_val(dev, 'uri', 'equipmentUri')
			# <uri name="deviceUri" val="//bacnet!76124/"/>
			# <uri name="deviceUri" val="/lon/nid/02.3d.18.f5.0c.00/"/>
			# <uri name="deviceUri" val="/modbus/link1/1"/>
			device_uri = self._get_tag_val(dev, 'uri', 'deviceUri')
			# <str name="displayName" val="Penthouse Plant Controls"/>
			display_name = self._get_tag_val(dev, 'str', 'displayName')
			# <str name="addressOnLink" val="1.C0A8008FBAC2"/>
			address_on_link = self._get_tag_val(dev, 'str', 'addressOnLink')
			# <str name="netAddr" val="23.56|wshp-6"/>
			net_addr = self._get_tag_val(dev, 'str', 'netAddr')
			link = dev.find('list', {'name': 'linkSpecific'})
			if link:
				link = link.find('obj', recursive=False)
			if link:
				link_pretty = link.find('obj', {'name': 'pretty'}, recursive=False)
			else:
				link_pretty = None
			if link_pretty:
				# <int name="networkNumber" val="1"/>
				network_number = self._get_tag_val(link_pretty, 'int', 'networkNumber')
				# <bool name="remoteNetwork" val="false"/>
				remote_network = self._get_tag_val(link_pretty, 'bool', 'remoteNetwork')
				# <str name="datalinkName" val="BVLL"/>
				data_link_name = self._get_tag_val(link_pretty, 'str', 'datalinkName')
				# <str name="macAddress" val="192.168.0.154:47810"/>
				mac_address = self._get_tag_val(link_pretty, 'str', 'macAddress')
			else:
				network_number = None
				remote_network = False
				data_link_name = None
				mac_address = None

			if device_uri.startswith('/modbus/link'):
				# Modbus links do not contain much information
				continue

			if mac_address is not None and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$', mac_address):
				# If the mac address looks like an IP address, use it as the IP
				ip = mac_address.split(':')[0]
				# Pull the MAC from the addressOnLink
				mac = address_on_link.split('.')[1]
				mac = ':'.join(mac[i:i + 2] for i in range(0, len(mac), 2))
			elif device_uri.startswith('//bacnet!'):
				ip = address_on_link
				mac = net_addr
			elif device_uri.startswith('/lon/nid/'):
				mac = device_uri[9:-1]

			if remote_network and network_number in self._remote_networks:
				uplink_device = self._remote_networks[network_number][0]
				uplink_port = self._remote_networks[network_number][1]
			elif data_link_name != 'BVLL' and data_link_name is not None:
				uplink_device = self.host.ip
				uplink_port = data_link_name

			if equipment_uri:
				lookups.append('/evox' + equipment_uri + '/VendorName/value')
				lookups.append('/evox' + equipment_uri + '/ControllerType/value')
				lookups.append('/evox' + equipment_uri + '/ModelName/value')
				lookups.append('/evox' + equipment_uri + '/FirmwareRevision/value')

			host = self.host.create_neighbor(ip)
			counter += 1
			host.log('Discovered device from source host %s %s' % (self.host.hostname, self.host.ip))
			host.hostname = display_name
			host.mac = mac
			host.include = True
			host.uplink_port = uplink_port
			host.uplink_device = uplink_device
			host.type = HostType.ENVIRONMENTAL

			equipment_uris[equipment_uri] = host

		self.host.log('Discovered %d devices' % counter)
		# Load the device details, (manufacturer, model, etc)
		self._scan_device_details(lookups, equipment_uris)

	def _scan_device_details(self, lookups: list, equipment_uris: dict):

		chunks = [lookups[i:i + 100] for i in range(0, len(lookups), 100)]
		# Evox allows for batch queries, but only up to a certain size.
		# Chunk the lookups to avoid exceeding the limit.
		for chunk in chunks:
			details_xml = self._get_batch(chunk, 'device_details')
			for line in details_xml.find_all('str'):
				href = line.get('href')
				if href.startswith('/evox/'):
					href = href[5:]
				val = line.get('val')
				key = None

				if href.endswith('/VendorName/value'):
					key = 'manufacturer'
				elif href.endswith('/ModelName/value'):
					key = 'model'
				elif href.endswith('/FirmwareRevision/value'):
					key = 'os_version'
				elif href.endswith('/ControllerType/value'):
					key = 'descr'  # @todo determine a better location for this value

				if key is not None:
					# Extract the equipment URI from the href
					equipment_uri = href.rsplit('/', 2)[0]
					if equipment_uri in equipment_uris:
						setattr(equipment_uris[equipment_uri], key, val)

	def get_ports(self):
		data = ['/evox/ipNetworkConfig/']
		bacnets = []

		# Perform an initial lookup to get the MSTP (serial) links present
		xml = self._get_batch(['/evox/config/bacnet_mstp'], 'bacnets')
		for ref in xml.find_all('ref', {'is': 'trane:bacnetMstpConfig_v1'}):
			data.append('/evox/config/bacnet_mstp/' + ref.get('href'))
			bacnets.append('/evox/config/bacnet_mstp/' + ref.get('href'))

		# Get all the interface data
		xml = self._get_batch(data, 'interfaces')

		ports = {}

		ip_configs = xml.find('obj', {'href': '/evox/ipNetworkConfig/'})
		if ip_configs:
			ip_interfaces = ip_configs.find('list', {'name': 'interfaces'})
			for tag in ip_interfaces.find_all('obj', {'is': 'trane:SC/ipNetworkConfig/enetInterface_v1'}):
				port = tag.find('str', {'name': 'name'}).get('val')

				ports[port] = HostPort()
				ports[port].name = port
				ports[port].ip = tag.find('str', {'name': 'ipaddr'}).get('val')
				ports[port].mac = tag.find('str', {'name': 'macaddr'}).get('val')
				ports[port].admin_status = 'UP' if tag.find('bool', {'name': 'enabled'}).get('val') == 'true' else 'DOWN'

			for tag in ip_interfaces.find_all('obj', {'is': 'trane:SC/ipNetworkConfig/wifiInterface_v1'}):
				port = tag.find('str', {'name': 'name'}).get('val')

				ports[port] = HostPort()
				ports[port].name = port
				ports[port].ip = tag.find('str', {'name': 'ipaddr'}).get('val')
				ports[port].mac = tag.find('str', {'name': 'macaddr'}).get('val')
				ports[port].admin_status = 'UP' if tag.find('bool', {'name': 'enabled'}).get('val') == 'true' else 'DOWN'

		for link in bacnets:
			tag = xml.find('obj', {'href': link})
			# link0 should display as Link 1 / MSTP 1.
			pretty_id = str(int(link[-2:-1]) + 1)
			port = 'mstp' + pretty_id

			ports[port] = HostPort()
			ports[port].name = port
			ports[port].label = 'BACnet MS/TP ' + pretty_id
			ports[port].ip = tag.find('int', {'name': 'networkNumber'}).get('val')
			ports[port].admin_status = 'UP' if tag.find('bool', {'name': 'enabled'}).get('val') == 'true' else 'DOWN'
			ports[port].speed = format_link_speed(tag.find('int', {'name': 'baudRate'}).get('val'))

		return ports

	def _get_tag_val(self, parent: Tag, val_type: str, key: str, recursive=False):
		node = parent.find(val_type, {'name': key}, recursive=recursive)
		if node is None:
			# Not present
			return None
		val = node.get('val')
		if val_type == 'int':
			return int(val)
		elif val_type == 'bool':
			return val == 'true'
		else:
			return val

	def _get_batch(self, parameters: list, api_call: str) -> BeautifulSoup:
		"""
		Retrieves a batch of parameters from the Tracer SC device.

		:param parameters: List of parameters to retrieve.
		:raise RequestException: If the request fails.
		"""
		data = ['<list is="obix:BatchIn">']
		for p in parameters:
			data.append(f'<uri is="obix:Read" val="{p}" />')
		data.append('</list>')

		res = self._post(
			'/evox/batch',
			''.join(data),
			{'Content-Type': 'text/xml', 'X-API-Call': api_call}
		)
		if res is None:
			self.host.log('Failed to retrieve Tracer SC configuration data')
			return BeautifulSoup('', 'xml')
		else:
			return BeautifulSoup(res.text, 'xml')

	def _get_call(self, url: str, payload: str, api_call: str) -> BeautifulSoup:
		"""
		Retrieves a batch of parameters from the Tracer SC device.

		:param url: URL to retrieve, (excluding the hostname)
		:param payload: Data payload to send
		:raise RequestException: If the request fails.
		"""

		res = self._post(
			url,
			payload,
			{'Content-Type': 'text/xml', 'X-API-Call': api_call}
		)
		if res is None:
			self.host.log('Failed to retrieve Tracer SC call data')
			return BeautifulSoup('', 'xml')
		else:
			return BeautifulSoup(res.text, 'xml')
