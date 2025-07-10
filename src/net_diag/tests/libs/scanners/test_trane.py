from unittest import TestCase
import responses
from responses import matchers
from importlib import resources
from net_diag.tests import data
from net_diag.libs.host import Host
from net_diag.libs.scanners.trane import TraneTracerSCScanner


class TestTraneTracerSCScanner(TestCase):
	def _load_file(self, group: str, filename: str) -> str:
		input_file = resources.files(data) / group / filename
		if not input_file.exists():
			return ''
		with input_file.open('r') as file:
			return file.read()

	def _setup_responses(self, group: str):
		responses.post(
			url='http://172.0.0.1/evox/batch',
			body=self._load_file(group, 'general_info.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'general_info'})]
		)

		responses.post(
			url='http://172.0.0.1/evox/batch',
			body=self._load_file(group, 'bacnets.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'bacnets'})]
		)

		responses.post(
			url='http://172.0.0.1/evox/batch',
			body=self._load_file(group, 'interfaces.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'interfaces'})]
		)

		responses.post(
			url='http://172.0.0.1/evox/batch',
			body=self._load_file(group, 'devices.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'devices'})]
		)

		responses.post(
			url='http://172.0.0.1/evox/batch',
			body=self._load_file(group, 'device_details.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'device_details'})]
		)

		responses.post(
			url='http://172.0.0.1/evox/bacnet/availableNetworks',
			body=self._load_file(group, 'discover_bridges.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'discover_bridges'})]
		)

		responses.post(
			url='http://172.0.0.1/evox/bacnet/availableNetworks',
			body=self._load_file(group, 'bridges.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'bridges'})]
		)

	@responses.activate
	def test_tracer_6_10(self):
		self._setup_responses('tracer_6_10')

		host = Host('172.0.0.1', {'trane_username': 'user', 'trane_password': 'pass'})
		TraneTracerSCScanner.scan(host)
		TraneTracerSCScanner.scan_neighbors(host)

		self.assertEqual('Test SC 10-13', host.hostname)
		self.assertEqual('123 Here', host.location)
		self.assertEqual('Trane', host.manufacturer)
		self.assertEqual('Tracer SC+', host.model)
		self.assertEqual('6.10.2115 (release)', host.os_version)
		self.assertEqual('SERIAL', host.serial)
		self.assertEqual('Environmental', host.type)
		self.assertEqual('00:11:22:33:44:55', host.mac)

		self.assertEqual(6, len(host.links))

		self.assertEqual('172.0.0.1', host.links['eth0'].ip)
		self.assertEqual('00:11:22:33:44:55', host.links['eth0'].mac)
		self.assertEqual('eth0', host.links['eth0'].name)
		self.assertEqual('UP', host.links['eth0'].admin_status)

		self.assertEqual('21', host.links['mstp1'].ip)
		self.assertEqual('38.4kbps', host.links['mstp1'].speed)
		self.assertEqual('mstp1', host.links['mstp1'].name)
		self.assertEqual('BACnet MS/TP 1', host.links['mstp1'].label)
		self.assertEqual('UP', host.links['mstp1'].admin_status)

		self.assertEqual(4, len(host.neighbors))

		self.assertEqual('HP 10-124', host.neighbors['22.7C'].hostname)
		self.assertEqual('22.7C', host.neighbors['22.7C'].ip)
		self.assertEqual('76124', host.neighbors['22.7C'].mac)
		self.assertEqual('Teletrol Systems Inc', host.neighbors['22.7C'].manufacturer)
		self.assertEqual('TRC-7600A-5', host.neighbors['22.7C'].model)
		self.assertEqual('172.0.0.1', host.neighbors['22.7C'].uplink_device)
		self.assertEqual('MSTP2', host.neighbors['22.7C'].uplink_port)

	@responses.activate
	def test_tracer_4_40(self):
		self._setup_responses('tracer_4_40')

		host = Host('172.0.0.1', {'trane_username': 'user', 'trane_password': 'pass'})
		TraneTracerSCScanner.scan(host)
		TraneTracerSCScanner.scan_neighbors(host)

		self.assertEqual('Test SC 1-5', host.hostname)
		self.assertEqual('123 Here St', host.location)
		self.assertEqual('Trane', host.manufacturer)
		self.assertEqual('Tracer SC', host.model)
		self.assertEqual('4.40.1218 (release)', host.os_version)
		self.assertEqual('E17SER', host.serial)
		self.assertEqual('Environmental', host.type)

		self.assertEqual(2, len(host.links))

		self.assertEqual('41', host.links['mstp1'].ip)
		self.assertEqual('38.4kbps', host.links['mstp1'].speed)
		self.assertEqual('mstp1', host.links['mstp1'].name)
		self.assertEqual('BACnet MS/TP 1', host.links['mstp1'].label)
		self.assertEqual('DOWN', host.links['mstp1'].admin_status)

		self.assertEqual('42', host.links['mstp2'].ip)
		self.assertEqual('38.4kbps', host.links['mstp2'].speed)
		self.assertEqual('mstp2', host.links['mstp2'].name)
		self.assertEqual('BACnet MS/TP 2', host.links['mstp2'].label)
		self.assertEqual('UP', host.links['mstp2'].admin_status)

		self.assertEqual(4, len(host.neighbors))

		self.assertEqual('HP 01-13', host.neighbors['32.0D'].hostname)
		self.assertEqual('32.0D', host.neighbors['32.0D'].ip)
		self.assertEqual('76013', host.neighbors['32.0D'].mac)
		self.assertEqual('Teletrol Systems Inc', host.neighbors['32.0D'].manufacturer)
		self.assertEqual('TRC-7600A-5', host.neighbors['32.0D'].model)
		self.assertEqual('192.168.0.153', host.neighbors['32.0D'].uplink_device)
		self.assertEqual('MSTP2', host.neighbors['32.0D'].uplink_port)
		self.assertEqual('3.5.05', host.neighbors['32.0D'].os_version)

		self.assertEqual('PS3037 Building Electric Meter', host.neighbors['192.168.0.154'].hostname)
		self.assertEqual('192.168.0.154', host.neighbors['192.168.0.154'].ip)
		self.assertEqual('C0:A8:33:99:44:55', host.neighbors['192.168.0.154'].mac)
		self.assertEqual('PS3037-E  P371912028', host.neighbors['192.168.0.154'].model)
		self.assertEqual('DENT Instruments, Inc.', host.neighbors['192.168.0.154'].manufacturer)
		self.assertIsNone(host.neighbors['192.168.0.154'].uplink_device)
		self.assertIsNone(host.neighbors['192.168.0.154'].uplink_port)
		self.assertEqual('0.5.9', host.neighbors['192.168.0.154'].os_version)
