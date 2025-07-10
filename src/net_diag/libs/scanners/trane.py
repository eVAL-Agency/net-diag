import re
import time

import requests
from requests.auth import HTTPDigestAuth
from bs4 import BeautifulSoup, Tag
from requests.exceptions import RequestException

from net_diag.libs.net_utils import format_link_speed
from net_diag.libs.host import Host, HostLink
from net_diag.libs.scanners import ScannerInterface


class TraneTracerSCScanner(ScannerInterface):
	"""
	Tracer SC is a Trane product that provides advanced control and monitoring capabilities for HVAC systems.
	It is designed to optimize energy efficiency and enhance system performance.
	"""

	def __init__(self, host: Host):
		super().__init__(host)
		self._remote_networks = {}

	@classmethod
	def scan(cls, host: Host):
		if 'trane_username' not in host.config:
			return

		if 'trane_password' not in host.config:
			return

		scanner = cls(host)
		scanner._scan()

	@classmethod
	def scan_neighbors(cls, host: Host):
		if 'trane_username' not in host.config:
			return

		if 'trane_password' not in host.config:
			return

		scanner = cls(host)
		scanner._scan_neighbors()

	def _scan(self):
		try:
			self.host.log('Retrieving Tracer SC configuration data')
			xml = self._get_batch(['/evox/about', '/evox/config/bacnet_global'], 'general_info')
		except RequestException as e:
			self.host.log('Failed to retrieve Tracer SC configuration data.\n' + str(e))
			return

		about = xml.find('obj', {'href': '/evox/about'})
		bacnet_global = xml.find('obj', {'href': '/evox/config/bacnet_global'})

		self.host.type = Host.TYPE_ENVIRONMENTAL
		self.host.hostname = bacnet_global.find('str', {'name': 'name'}).get('val')
		self.host.set_location(bacnet_global.find('str', {'name': 'location'}).get('val'))
		self.host.manufacturer = about.find('str', {'name': 'vendorName'}).get('val')
		self.host.model = about.find('str', {'name': 'productName'}).get('val')
		self.host.serial = about.find('str', {'name': 'hardwareSerialNumber'}).get('val')
		self.host.os_version = about.find('str', {'name': 'productVersion'}).get('val')
		if self.host.os_version.startswith('v'):
			# Trim off the leading 'v' version indicator if present
			self.host.os_version = self.host.os_version[1:]

		self.host.links = self.get_ports()

		# Find the mac address from the interfaces
		for iface in self.host.links.values():
			if iface.ip == self.host.ip:
				self.host.mac = iface.mac
				break

	def _scan_neighbors(self):
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
				host.type = Host.TYPE_ENVIRONMENTAL

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
			link = dev.find('list', {'name': 'linkSpecific'}).find('obj', recursive=False)
			link_pretty = link.find('obj', {'name': 'pretty'}, recursive=False)
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
				mac = device_uri[9:-1]
			elif device_uri.startswith('/lon/nid/'):
				mac = device_uri[9:-1]

			if remote_network and network_number in self._remote_networks:
				uplink_device = self._remote_networks[network_number][0]
				uplink_port = self._remote_networks[network_number][1]
			elif data_link_name != 'BVLL' and data_link_name is not None:
				uplink_device = self.host.ip
				uplink_port = data_link_name

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
			host.type = Host.TYPE_ENVIRONMENTAL

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

				ports[port] = HostLink()
				ports[port].name = port
				ports[port].ip = tag.find('str', {'name': 'ipaddr'}).get('val')
				ports[port].mac = tag.find('str', {'name': 'macaddr'}).get('val')
				ports[port].admin_status = 'UP' if tag.find('bool', {'name': 'enabled'}).get('val') == 'true' else 'DOWN'

			for tag in ip_interfaces.find_all('obj', {'is': 'trane:SC/ipNetworkConfig/wifiInterface_v1'}):
				port = tag.find('str', {'name': 'name'}).get('val')

				ports[port] = HostLink()
				ports[port].name = port
				ports[port].ip = tag.find('str', {'name': 'ipaddr'}).get('val')
				ports[port].mac = tag.find('str', {'name': 'macaddr'}).get('val')
				ports[port].admin_status = 'UP' if tag.find('bool', {'name': 'enabled'}).get('val') == 'true' else 'DOWN'

		for link in bacnets:
			tag = xml.find('obj', {'href': link})
			# link0 should display as Link 1 / MSTP 1.
			pretty_id = str(int(link[-2:-1]) + 1)
			port = 'mstp' + pretty_id

			ports[port] = HostLink()
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

		try:
			res = requests.post(
				f'http://{self.host.ip}/evox/batch',
				auth=HTTPDigestAuth(self.host.config['trane_username'], self.host.config['trane_password']),
				data=''.join(data),
				headers={'Content-Type': 'text/xml', 'X-API-Call': api_call},
				timeout=10
			).text
		except requests.exceptions.RequestException as e:
			self.host.log(f'Failed to retrieve Tracer SC configuration data: {e}')
			res = ''

		return BeautifulSoup(res, 'xml')

	def _get_call(self, url: str, payload: str, api_call: str) -> BeautifulSoup:
		"""
		Retrieves a batch of parameters from the Tracer SC device.

		:param url: URL to retrieve, (excluding the hostname)
		:param payload: Data payload to send
		:raise RequestException: If the request fails.
		"""

		res = requests.post(
			f'http://{self.host.ip}{url}',
			auth=HTTPDigestAuth(self.host.config['trane_username'], self.host.config['trane_password']),
			data=payload,
			headers={'Content-Type': 'text/xml', 'X-API-Call': api_call},
			timeout=10
		).text

		return BeautifulSoup(res, 'xml')
