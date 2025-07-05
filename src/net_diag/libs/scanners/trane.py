import requests
from requests.auth import HTTPDigestAuth
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

from net_diag.libs.net_utils import format_link_speed
from net_diag.libs.host import Host, HostInterface


class TraneTracerSCScanner:
	"""
	Tracer SC is a Trane product that provides advanced control and monitoring capabilities for HVAC systems.
	It is designed to optimize energy efficiency and enhance system performance.
	"""

	def __init__(self, host: Host):
		self.host = host
		"""
		Underlying host to populate
		: type host: Host
		"""

	def scan(self):
		if 'trane_username' not in self.host.config:
			return

		if 'trane_password' not in self.host.config:
			return

		try:
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

		self.host.interfaces = self.get_ports()

		# Find the mac address from the interfaces
		for iface in self.host.interfaces.values():
			if iface.ip == self.host.ip:
				self.host.mac = iface.mac
				break

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
		ip_interfaces = (
			xml
			.find('obj', {'href': '/evox/ipNetworkConfig/'})
			.find('list', {'name': 'interfaces'})
		)

		ports = {}

		for tag in ip_interfaces.find_all('obj', {'is': 'trane:SC/ipNetworkConfig/enetInterface_v1'}):
			port = tag.find('str', {'name': 'name'}).get('val')

			ports[port] = HostInterface()
			ports[port].name = port
			ports[port].ip = tag.find('str', {'name': 'ipaddr'}).get('val')
			ports[port].mac = tag.find('str', {'name': 'macaddr'}).get('val')
			ports[port].admin_status = 'UP' if tag.find('bool', {'name': 'enabled'}).get('val') == 'true' else 'DOWN'

		for tag in ip_interfaces.find_all('obj', {'is': 'trane:SC/ipNetworkConfig/wifiInterface_v1'}):
			port = tag.find('str', {'name': 'name'}).get('val')

			ports[port] = HostInterface()
			ports[port].name = port
			ports[port].ip = tag.find('str', {'name': 'ipaddr'}).get('val')
			ports[port].mac = tag.find('str', {'name': 'macaddr'}).get('val')
			ports[port].admin_status = 'UP' if tag.find('bool', {'name': 'enabled'}).get('val') == 'true' else 'DOWN'

		for link in bacnets:
			tag = xml.find('obj', {'href': link})
			# link0 should display as Link 1 / MSTP 1.
			pretty_id = str(int(link[-2:-1]) + 1)
			port = 'mstp' + pretty_id

			ports[port] = HostInterface()
			ports[port].name = port
			ports[port].label = 'BACnet MS/TP ' + pretty_id
			ports[port].ip = tag.find('int', {'name': 'networkNumber'}).get('val')
			ports[port].admin_status = 'UP' if tag.find('bool', {'name': 'enabled'}).get('val') == 'true' else 'DOWN'
			ports[port].speed = format_link_speed(tag.find('int', {'name': 'baudRate'}).get('val'))

		return ports

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

		res = requests.post(
			f'http://{self.host.ip}/evox/batch',
			auth=HTTPDigestAuth(self.host.config['trane_username'], self.host.config['trane_password']),
			data=''.join(data),
			headers={'Content-Type': 'text/xml', 'X-API-Call': api_call},
			timeout=5
		).text

		return BeautifulSoup(res, 'xml')
