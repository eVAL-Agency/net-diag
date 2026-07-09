import socket
import requests
from bs4 import BeautifulSoup, Tag
import re
import time

from requests import Response
from requests.auth import HTTPDigestAuth, AuthBase
from requests.exceptions import RequestException

from net_diag.libs.scanners import ScannerInterface
from net_diag.libs.host import Host, HostPort, HostType, HostPortAdminStatus, HostPortUserStatus, HostPortType


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
	def discover(cls, host: Host) -> bool:
		"""
		Initial discovery to detect if this host supports HTTP/HTTPS

		:param host:
		:return:
		"""
		ports = [80, 443]
		for port in ports:
			try:
				# Attempts a TCP connection; raises an exception if it times out or is refused
				with socket.create_connection((host.ip, port), timeout=1):
					host.log('Port %s appears to be open!' % port)
					host.scanners['http'] = port
					return True

			except (socket.timeout, ConnectionRefusedError, OSError):
				host.log('Port %s appears to be closed!' % port)

		return False

	@classmethod
	def scan(cls, host: Host):
		"""
		Perform an HTTP/S scan on the target.
		"""
		if 'http' not in host.scanners:
			return

		scanner = cls._get_scanner(host)
		scanner.run_scan()
		scanner.run_scan_neighbors()

	@classmethod
	def _get_scanner(cls, host: Host) -> ScannerInterface:
		"""
		Try to determine the correct scanner to use for this HTTP target.

		Will issue a full connection to the homepage to allow the various modules to check if it matches what they want
		:param host:
		:param port:
		:return:
		"""
		port = host.scanners['http']
		protocol = "https" if port == 443 else "http"
		url = f"{protocol}://{host.ip}:{port}"

		response = requests.get(url, timeout=2.0, verify=False)
		server_header = response.headers.get('Server', '')
		host.log('HTTP Server: %s' % (server_header,))
		# Parse the HTML content
		soup = BeautifulSoup(response.text, 'html.parser')
		page_title = soup.title.string if soup.title else ""
		host.log('HTTP Page Title: %s' % (page_title,))

		# Try the different HTTP scanners
		if TraneTracerSCScanner.matches(response):
			# Matches a Trane Tracer SC
			return TraneTracerSCScanner(host, port)
		elif GrandstreamPhoneScanner.matches(response):
			return GrandstreamPhoneScanner(host, port)
		else:
			# No matches available, default to the baseline HTTP scanner
			return HTTPScanner(host, port)

	@classmethod
	def matches(cls, response: Response) -> bool:
		return True

	def run_scan(self):
		"""
		Perform a device scan

		:return:
		"""
		# The base HTTP scanner doesn't do anything
		pass

	def run_scan_neighbors(self):
		"""
		Perform a neighbor scan, usually of children under this device

		:return:
		"""
		# The base HTTP scanner doesn't do anything
		pass

	def _resolve_url(self, url: str = '') -> str:
		protocol = "https" if self.port == 443 else "http"
		return f"{protocol}://{self.host.ip}:{self.port}{url}"

	def _post(self, url: str, data, headers: dict | None = None) -> Response | None:
		url = self._resolve_url(url)

		try:
			return requests.post(
				url,
				auth=self.auth,
				data=data,
				headers=headers,
				timeout=10,
				verify=False
			)
		except requests.exceptions.RequestException as e:
			self.host.log('Failed to perform POST to %s: %s' % (url, e))
			return None

	def _get(self, url: str, headers: dict | None = None) -> Response | None:
		url = self._resolve_url(url)

		try:
			return requests.get(
				url,
				auth=self.auth,
				headers=headers,
				timeout=10,
				verify=False
			)
		except requests.exceptions.RequestException as e:
			self.host.log('Failed to perform GET to %s: %s' % (url, e))
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
		# Parse the HTML content
		soup = BeautifulSoup(response.text, 'html.parser')
		page_title = soup.title.string if soup.title else ""

		# Assumed to be a Tracer SC if matches
		if page_title == 'Tracer Synchrony' and 'Trane U.S. Inc.' in response.text:
			# Version 6.10
			return True

		if page_title == 'Tracer SC' and 'Tracer SC+' in response.text:
			# Version 4.0
			return True

		return False

	def run_scan(self):
		if self.auth is None:
			self._run_scan_unauthenticated()
		else:
			self._run_scan_authenticated()

	def _run_scan_unauthenticated(self):
		"""
		Perform an unauthenticated scan
		:return:
		"""

		try:
			self.host.log('Retrieving Tracer SC configuration data')
			res = self._get('/evox/about')
			xml = BeautifulSoup(res.text, 'xml')
			about = xml.find('obj', {'href': '/evox/about'})

			self.host.type = HostType.ENVIRONMENTAL
			self.host.manufacturer = self._get_tag_val(about, 'str', 'vendorName')
			self.host.os_name = self._get_tag_val(about, 'str', 'productName')
			self.host.os_version = self._get_tag_val(about, 'str', 'productVersion')
			self.host.model = self._get_tag_val(about, 'str', 'hardwareType')
			self.host.serial = self._get_tag_val(about, 'str', 'hardwareSerialNumber')
			self.host.os_date = self._get_tag_val(about, 'date', 'softwareVersionDate')

			if self.host.os_version is not None and self.host.os_version.startswith('v'):
				# Trim off the leading 'v' version indicator if present
				self.host.os_version = self.host.os_version[1:]
		except RequestException as e:
			self.host.log('Failed to retrieve Tracer SC configuration data.\n' + str(e))
			return

	def _run_scan_authenticated(self):
		"""
		Perform an authenticated scan
		:return:
		"""
		try:
			self.host.log('Retrieving Tracer SC configuration data')
			xml = self._get_batch(['/evox/about', '/evox/config/bacnet_global'], 'general_info')
		except RequestException as e:
			self.host.log('Failed to retrieve Tracer SC configuration data.\n' + str(e))
			return

		about = xml.find('obj', {'href': '/evox/about'})
		bacnet_global = xml.find('obj', {'href': '/evox/config/bacnet_global'})

		self.host.type = HostType.ENVIRONMENTAL
		self.host.manufacturer = self._get_tag_val(about, 'str', 'vendorName')
		self.host.os_name = self._get_tag_val(about, 'str', 'productName')
		self.host.os_version = self._get_tag_val(about, 'str', 'productVersion')
		self.host.model = self._get_tag_val(about, 'str', 'hardwareType')
		self.host.serial = self._get_tag_val(about, 'str', 'hardwareSerialNumber')
		self.host.os_date = self._get_tag_val(about, 'date', 'softwareVersionDate')

		self.host.hostname = self._get_tag_val(bacnet_global, 'str', 'name')
		self.host.location = self._get_tag_val(bacnet_global, 'str', 'location')

		if self.host.os_version is not None and self.host.os_version.startswith('v'):
			# Trim off the leading 'v' version indicator if present
			self.host.os_version = self.host.os_version[1:]

		self.get_ports()

		# Find the mac address from the interfaces
		for iface in self.host.ports:
			if self.host.ip in iface.ips:
				self.host.mac = iface.mac
				break

	def run_scan_neighbors(self):
		if self.auth is None:
			# Neighbor scan is only available for authenticated scans
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
				# There can be up to about 250 devices on a single bus, so convert the network to hex to fit
				network_mac = f'00:00:00:00:{network:02}:00'
				network_name = self._get_tag_val(dev, 'str', 'remoteDatalinkName')
				if re.match(r'MSTP[0-9]', network_name):
					pretty_name = 'MS/TP ' + network_name[-1:]
				else:
					pretty_name = network_name

				bridge = self.host.create_neighbor(mac)
				bridge.ip = ip
				bridge.include = True
				bridge.hostname = dev.find('str', {'name': 'routerName'}).get('val')
				bridge.manufacturer = dev.find('str', {'name': 'routerVendorName'}).get('val')
				bridge.type = HostType.ENVIRONMENTAL

				# Create the actual network interface for this bridge device
				bridge_nic = bridge.create_port(mac)
				bridge_nic.ips = [ip]
				# Assume that it's connected.
				bridge_nic.admin_status = HostPortAdminStatus.UP
				bridge_nic.user_status = HostPortUserStatus.UP

				# Create the MSTP network for this bridge device; this is where the bridged sensors will be linked.
				bridge_sensor_port = bridge.create_port(network_mac)
				bridge_sensor_port.name = network_name
				bridge_sensor_port.label = f'BACnet {pretty_name} ({network})'
				bridge_sensor_port.admin_status = HostPortAdminStatus.UP
				bridge_sensor_port.user_status = HostPortUserStatus.UP
				bridge.log(
					f'Discovered bridge device from source host {self.host.hostname} {self.host.ip}: {bridge.hostname} ({bridge.ip})'
				)
				self._remote_networks[network] = (
					bridge,
					network_mac,
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
			network_number = None

			equipment_uri = self._get_tag_val(dev, 'uri', 'equipmentUri')
			# <uri name="deviceUri" val="//bacnet!76124/"/>
			# <uri name="deviceUri" val="/lon/nid/02.3d.18.f5.0c.00/"/>
			# <uri name="deviceUri" val="/modbus/link1/1"/>
			device_uri = self._get_tag_val(dev, 'uri', 'deviceUri')
			# <str name="displayName" val="Penthouse Plant Controls"/>
			display_name = self._get_tag_val(dev, 'str', 'displayName')
			# <str name="addressOnLink" val="1.C0A8008FBAC2"/>
			# <str name="addressOnLink" val="31.06"/>
			# <str name="addressOnLink" val="02.3d.18.f5.0c.00"/>
			address_on_link = self._get_tag_val(dev, 'str', 'addressOnLink')

			if device_uri.startswith('/modbus/link'):
				# Modbus links do not contain much information
				continue

			if re.match(r'^[a-fA-F0-9]{1,2}\.[a-fA-F0-9]{1,2}$', address_on_link):
				# This is actually a MAC (kind of); it's a Device identifier with the network included
				# Example: 31.3C
				mac = '00:00:00:00:' + address_on_link.replace('.', ':')
			elif re.match(r'[0-9]\.[a-fA-F0-9]{12}$', address_on_link):
				# This is a remote device visible across the network.
				# Here the address_on_link contains the ACTUAL MAC address of the remote device.
				mac = address_on_link.split('.')[1]
				mac = ':'.join(mac[i:i + 2] for i in range(0, len(mac), 2))
			elif re.match(
				r'^[a-fA-F0-9]{2}\.[a-fA-F0-9]{2}\.[a-fA-F0-9]{2}\.[a-fA-F0-9]{2}\.[a-fA-F0-9]{2}\.[a-fA-F0-9]{2}$',
				address_on_link
			):
				# Another actual MAC address!
				mac = address_on_link.replace('.', ':')

			# Devices must have some form of MAC address to continue
			if mac is None:
				continue

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
				# <str name="datalinkName" val="BVLL"/>
				# data_link_name = self._get_tag_val(link_pretty, 'str', 'datalinkName')
				# <str name="macAddress" val="192.168.0.154:47810"/>
				# For standard devices, this will be the base10 value of the device identifier
				# on the serial network.  This maps to the base16 value in the MAC.
				# Example, 124 in the "macAddress" field points to device 0x7C.
				mac_address = self._get_tag_val(link_pretty, 'str', 'macAddress')

				if mac_address is not None and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$', mac_address):
					# If the mac address looks like an IP address, use it as the IP
					ip = mac_address.split(':')[0]

			child = self.host.create_neighbor(mac)
			child.log('Discovered device from source host %s %s' % (self.host.hostname, self.host.ip))
			counter += 1

			if equipment_uri:
				lookups.append('/evox' + equipment_uri + '/VendorName/value')
				lookups.append('/evox' + equipment_uri + '/ControllerType/value')
				lookups.append('/evox' + equipment_uri + '/ModelName/value')
				lookups.append('/evox' + equipment_uri + '/FirmwareRevision/value')
				equipment_uris[equipment_uri] = child.mac

			child.hostname = display_name
			child.include = True
			child.type = HostType.ENVIRONMENTAL
			if ip is not None:
				child.ip = ip

				# This child has an actual IP address, so ensure it has a network port too.
				child_port = child.create_port(mac)
				child_port.ips = [ip]
				child_port.admin_status = HostPortAdminStatus.UP
				child_port.user_status = HostPortUserStatus.UP

			if network_number is not None:
				# Check if this device is physically attached to the host
				host_interface = self.host.find_port_by_mac(f'00:00:00:00:{network_number:02}:00')
				if host_interface:
					host_interface.connections.append(mac)
					self.host.children_count += 1

					# Register a network connection on the child device; this will clone many properties from the parent.
					child_interface = child.create_port(mac)
					child_interface.admin_status = HostPortAdminStatus.UP
					child_interface.user_status = HostPortUserStatus.UP
					if ip is not None:
						child_interface.ips = [ip]
					child_interface.speed = host_interface.speed
					child_interface.type = host_interface.type
				elif network_number in self._remote_networks:
					# This device is not on THIS controller, but a bridged controller.
					# These are still valid and should be tracked on that device as appropriate.
					bridge_host = self._remote_networks[network_number][0]
					bridge_mac = self._remote_networks[network_number][1]
					bridge_interface = bridge_host.find_port_by_mac(bridge_mac)
					if bridge_interface:
						bridge_host.children_count += 1
						bridge_interface.connections.append(mac)

						# Register a network connection on the child device; this will clone many properties from the parent.
						child_interface = child.create_port(mac)
						child_interface.admin_status = HostPortAdminStatus.UP
						child_interface.user_status = HostPortUserStatus.UP
						if ip is not None:
							child_interface.ips = [ip]
						child_interface.speed = bridge_interface.speed
						child_interface.type = bridge_interface.type

		# Load the device details, (manufacturer, model, etc)
		child_data = self._scan_device_details(lookups, equipment_uris)
		for uri, child_mac in equipment_uris.items():
			if uri in child_data:
				child = self.host.neighbors[child_mac]
				for k, v in child_data[uri].items():
					setattr(child, k, v)

		self.host.log('Discovered %d devices' % counter)

	def _scan_device_details(self, lookups: list, equipment_uris: dict):

		ret = {}
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
					if equipment_uri not in ret:
						ret[equipment_uri] = {}
					ret[equipment_uri][key] = val
		return ret

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

		ip_configs = xml.find('obj', {'href': '/evox/ipNetworkConfig/'})
		if ip_configs:
			ip_interfaces = ip_configs.find('list', {'name': 'interfaces'})
			for tag in ip_interfaces.find_all('obj', {'is': 'trane:SC/ipNetworkConfig/enetInterface_v1'}):
				port_name = self._get_tag_val(tag, 'str', 'name')
				ip = self._get_tag_val(tag, 'str', 'ipaddr')
				mac = self._get_tag_val(tag, 'str', 'macaddr')

				port = self.host.create_port(mac)
				port.name = port_name
				if ip:
					port.ips = [ip]
				port.admin_status = HostPortAdminStatus(1 if self._get_tag_val(tag, 'bool', 'enabled') else 2)
				port.user_status = HostPortUserStatus(1 if self._get_tag_val(tag, 'bool', 'enabled') else 2)

			for tag in ip_interfaces.find_all('obj', {'is': 'trane:SC/ipNetworkConfig/wifiInterface_v1'}):
				port_name = self._get_tag_val(tag, 'str', 'name')
				ip = self._get_tag_val(tag, 'str', 'ipaddr')
				mac = self._get_tag_val(tag, 'str', 'macaddr')

				port = self.host.create_port(mac)
				port.name = port_name
				if ip:
					port.ips = [ip]
				port.admin_status = HostPortAdminStatus(1 if self._get_tag_val(tag, 'bool', 'enabled') else 2)
				port.user_status = HostPortUserStatus(1 if self._get_tag_val(tag, 'bool', 'enabled') else 2)

		for link in bacnets:
			tag = xml.find('obj', {'href': link})
			# link0 should display as Link 1 / MSTP 1.
			pretty_id = str(int(link[-2:-1]) + 1)
			port_name = 'mstp' + pretty_id
			network_number = self._get_tag_val(tag, 'int', 'networkNumber')
			# Trane uses the base10 value as a literal in their MAC address schema.
			# (even though 22 _SHOULD_ be 16 in the mac....)
			# To preserve functionality with this fast-and-loose usage of bases,
			# keep with their logic here.
			mac = f'00:00:00:00:{network_number:02}:00'

			port = self.host.create_port(mac)
			port.name = port_name
			port.label = f'BACnet MS/TP {pretty_id} ({network_number})'
			port.type = HostPortType.PROP_POINT_TO_POINT_SERIAL
			port.speed = self._get_tag_val(tag, 'int', 'baudRate')
			port.admin_status = HostPortAdminStatus(1 if self._get_tag_val(tag, 'bool', 'enabled') else 2)
			port.user_status = HostPortUserStatus(1 if self._get_tag_val(tag, 'bool', 'enabled') else 2)

		return self.host.ports

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


class GrandstreamPhoneScanner(HTTPScanner):
	"""
	For Grandstream phones which do not support SNMP
	"""

	def __init__(self, host: Host, port: int):
		super().__init__(host, port)

	@classmethod
	def matches(cls, response: Response) -> bool:
		server_header = response.headers.get('Server', '')
		# Parse the HTML content
		soup = BeautifulSoup(response.text, 'html.parser')
		page_title = soup.title.string if soup.title else ""

		# Assumed to be a Grandstream device
		content = '<iframe src="javascript:\'\'" id="__gwt_historyFrame" tabIndex=\'-1\' style="position:absolute;width:0;height:0;border:0"></iframe>'  # NOQA E501
		if not (
			server_header.startswith('lighttpd')
			and page_title == 'Loading Web Application'
			and content in response.text
		):
			return False

		# Check for the presense of a specific URL
		page_response = requests.get(response.url + 'cgi-bin/api.values.get', timeout=2.0, verify=False)
		return page_response.status_code == 200

	def run_scan(self):
		fields = {
			'vendor_fullname': 'manufacturer',
			'phone_model': 'model',
			#  'PAccountRegistered1', 'PAccountRegistered2', 'PAccountRegistered3', 'PAccountRegistered4',
			'68': 'os_version',
			'P67': 'mac',
			'Pipv4': 'ip',
			#  'Psubnet_web',  # Subnet - 255.255.255.0
			'Pgateway_web': 'gateway',
			#  'Pdns1_web',  # DNS 1
			#  'Pdns2_web',  # DNS 2
		}

		'''
		other fields, but these require authentication
		'P3',  # Custom display name / label
		'P35',  # Line 1 extension
		'P47',  # SIP account server
		'''

		payload = {"request": ':'.join(fields.keys())}
		ret = self._post('/cgi-bin/api.values.get', payload)
		data = ret.json()

		self.host.type = HostType.PHONE
		for source_key, target_key in fields.items():
			val = data['body'].get(source_key, None)
			if val is not None:
				setattr(self.host, target_key, val)
				if target_key == 'mac':
					# This is also the serial number.
					self.host.serial = val.replace(':', '')

		# Create a basic port to track the IP
		if self.host.mac and self.host.ip:
			port = HostPort()
			port.label = 'network'
			port.mac = self.host.mac
			port.ips = [self.host.ip]
			self.host.ports['network'] = port
