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
		with input_file.open('r') as file:
			return file.read()

	@responses.activate
	def test_tracer_6_10(self):
		responses.post(
			url='http://172.0.0.1/evox/batch',
			body=self._load_file('tracer_6_10', 'general_info.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'general_info'})]
		)

		responses.post(
			url='http://172.0.0.1/evox/batch',
			body=self._load_file('tracer_6_10', 'bacnets.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'bacnets'})]
		)

		responses.post(
			url='http://172.0.0.1/evox/batch',
			body=self._load_file('tracer_6_10', 'interfaces.txt'),
			match=[matchers.header_matcher({'X-API-Call': 'interfaces'})]
		)

		host = Host('172.0.0.1', {'trane_username': 'user', 'trane_password': 'pass'})
		scanner = TraneTracerSCScanner(host)
		scanner.scan()

		self.assertEqual('Test SC 10-13', host.hostname)
		self.assertEqual('123 Here', host.location)
		self.assertEqual('Trane', host.manufacturer)
		self.assertEqual('Tracer SC+', host.model)
		self.assertEqual('6.10.2115 (release)', host.os_version)
		self.assertEqual('SERIAL', host.serial)
		self.assertEqual('Environmental', host.type)
		self.assertEqual('00:11:22:33:44:55', host.mac)

		self.assertEqual(6, len(host.interfaces))

		self.assertEqual('172.0.0.1', host.interfaces['eth0'].ip)
		self.assertEqual('00:11:22:33:44:55', host.interfaces['eth0'].mac)
		self.assertEqual('eth0', host.interfaces['eth0'].name)
		self.assertEqual('UP', host.interfaces['eth0'].admin_status)

		self.assertEqual('21', host.interfaces['mstp1'].ip)
		self.assertEqual('38.4kbps', host.interfaces['mstp1'].speed)
		self.assertEqual('mstp1', host.interfaces['mstp1'].name)
		self.assertEqual('BACnet MS/TP 1', host.interfaces['mstp1'].label)
		self.assertEqual('UP', host.interfaces['mstp1'].admin_status)
