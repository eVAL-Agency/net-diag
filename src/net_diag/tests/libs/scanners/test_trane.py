from unittest import TestCase
import responses
from responses import matchers
from importlib import resources
from net_diag.tests import data
from net_diag.libs.host import Host, HostType
from net_diag.libs.scanners.http import HTTPScanner


class TestTraneTracerSCScanner(TestCase):
	def _load_file(self, group: str, filename: str) -> str:
		input_file = resources.files(data) / 'http_tracer' / group / filename
		if not input_file.exists():
			return ''
		with input_file.open('r') as file:
			return file.read()

	def _setup_responses(self, group: str):
		responses.get(
			url='http://172.0.0.1:80/',
			headers={'Server': 'nginx'},
			body=self._load_file(group, 'index.txt')
		)
		responses.post(
			url='http://172.0.0.1:80/evox/batch',
			body=self._load_file(group, 'general_info.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'general_info'})]
		)

		responses.post(
			url='http://172.0.0.1:80/evox/batch',
			body=self._load_file(group, 'bacnets.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'bacnets'})]
		)

		responses.post(
			url='http://172.0.0.1:80/evox/batch',
			body=self._load_file(group, 'interfaces.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'interfaces'})]
		)

		responses.post(
			url='http://172.0.0.1:80/evox/batch',
			body=self._load_file(group, 'devices.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'devices'})]
		)

		responses.post(
			url='http://172.0.0.1:80/evox/batch',
			body=self._load_file(group, 'device_details.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'device_details'})]
		)

		responses.post(
			url='http://172.0.0.1:80/evox/bacnet/availableNetworks',
			body=self._load_file(group, 'discover_bridges.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'discover_bridges'})]
		)

		responses.post(
			url='http://172.0.0.1:80/evox/bacnet/availableNetworks',
			body=self._load_file(group, 'bridges.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'bridges'})]
		)

	@responses.activate
	def test_tracer_6_10(self):
		self._setup_responses('tracer_6_10')

		host = Host(
			'172.0.0.1',
			{'http_username': 'user', 'http_password': 'pass'}
		)
		host.scanners = {'http': 80}
		HTTPScanner.scan(host)

		self.assertEqual('Test SC 10-13', host.hostname)
		self.assertEqual('123 Here', host.location)
		self.assertEqual('Trane', host.manufacturer)
		self.assertEqual('Tracer SC+', host.model)
		self.assertEqual('6.10.2115 (release)', host.os_version)
		self.assertEqual('SERIAL', host.serial)
		self.assertEqual('Environmental', host.type)
		self.assertEqual('00:11:22:33:44:55', host.mac)
		self.assertEqual(4, host.children_count)

		self.assertEqual(6, len(host.ports))

		self.assertEqual('172.0.0.1', host.ports['eth0'].ips[0])
		self.assertEqual('00:11:22:33:44:55', host.ports['eth0'].mac)
		self.assertEqual('eth0', host.ports['eth0'].name)
		self.assertEqual(1, host.ports['eth0'].admin_status)
		self.assertEqual(1, host.ports['eth0'].user_status)

		self.assertEqual('192.168.1.10', host.ports['eth1'].ips[0])
		self.assertEqual('11:11:22:33:44:55', host.ports['eth1'].mac)
		self.assertEqual('eth1', host.ports['eth1'].name)
		self.assertEqual(2, host.ports['eth1'].admin_status)
		self.assertEqual(2, host.ports['eth1'].user_status)

		self.assertEqual('00:00:00:00:21:00', host.ports['mstp1'].mac)
		self.assertEqual(38400, host.ports['mstp1'].speed)
		self.assertEqual('mstp1', host.ports['mstp1'].name)
		self.assertEqual('BACnet MS/TP 1 (21)', host.ports['mstp1'].label)
		self.assertEqual(1, host.ports['mstp1'].admin_status)
		self.assertEqual(1, host.ports['mstp1'].user_status)

		self.assertEqual(4, len(host.neighbors))

		neighbor = host.neighbors['00:00:00:00:22:7C']
		self.assertEqual('HP 10-124', neighbor.hostname)
		self.assertEqual('00:00:00:00:22:7C', neighbor.mac)
		self.assertEqual('Teletrol Systems Inc', neighbor.manufacturer)
		self.assertEqual('TRC-7600A-5', neighbor.model)

	@responses.activate
	def test_tracer_4_40(self):
		self._setup_responses('tracer_4_40')

		host = Host(
			'172.0.0.1',
			{'http_username': 'user', 'http_password': 'pass'}
		)
		host.scanners = {'http': 80}
		HTTPScanner.scan(host)

		self.assertEqual('Test SC 1-5', host.hostname)
		self.assertEqual('123 Here St', host.location)
		self.assertEqual('Trane', host.manufacturer)
		self.assertEqual('HwVer12AB', host.model)
		self.assertEqual('4.40.1218 (release)', host.os_version)
		self.assertEqual('E17SER', host.serial)
		self.assertEqual('Environmental', host.type)

		self.assertEqual(2, len(host.ports))

		self.assertEqual(38400, host.ports['mstp1'].speed)
		self.assertEqual('mstp1', host.ports['mstp1'].name)
		self.assertEqual('BACnet MS/TP 1 (41)', host.ports['mstp1'].label)
		self.assertEqual(2, host.ports['mstp1'].admin_status)

		self.assertEqual(38400, host.ports['mstp2'].speed)
		self.assertEqual('mstp2', host.ports['mstp2'].name)
		self.assertEqual('BACnet MS/TP 2 (42)', host.ports['mstp2'].label)
		self.assertEqual(1, host.ports['mstp2'].admin_status)
		self.assertEqual(1, host.ports['mstp2'].user_status)

		self.assertEqual(4, len(host.neighbors))

		neighbor = host.neighbors['00:00:00:00:32:0D']
		self.assertEqual('HP 01-13', neighbor.hostname)
		self.assertEqual('00:00:00:00:32:0D', neighbor.mac)
		self.assertEqual('Teletrol Systems Inc', neighbor.manufacturer)
		self.assertEqual('TRC-7600A-5', neighbor.model)
		self.assertEqual('3.5.05', neighbor.os_version)
		self.assertEqual(HostType.ENVIRONMENTAL, neighbor.type)
		self.assertTrue(neighbor.include)

		neighbor = host.neighbors['C0:A8:44:88:77:44']
		self.assertEqual('Client 1-5 Base', neighbor.hostname)
		self.assertEqual('C0:A8:44:88:77:44', neighbor.mac)
		self.assertEqual('Trane', neighbor.manufacturer)
		self.assertEqual(None, neighbor.os_version)
		self.assertEqual(HostType.ENVIRONMENTAL, neighbor.type)
		self.assertTrue(neighbor.include)
		self.assertEqual(1, neighbor.children_count)
		self.assertIn('00:00:00:00:32:0D', neighbor.ports['32'].connections)

		neighbor = host.neighbors['C0:A8:33:99:44:55']
		self.assertEqual('PS3037 Building Electric Meter', neighbor.hostname)
		self.assertEqual('C0:A8:33:99:44:55', neighbor.mac)
		self.assertEqual('192.168.0.154', neighbor.ip)
		self.assertEqual('DENT Instruments, Inc.', neighbor.manufacturer)
		self.assertEqual('0.5.9', neighbor.os_version)
		self.assertEqual(HostType.ENVIRONMENTAL, neighbor.type)
		self.assertEqual('PS3037-E  P371912028', neighbor.model)
		self.assertTrue(neighbor.include)
