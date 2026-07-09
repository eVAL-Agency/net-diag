from unittest import TestCase

from net_diag.libs.host import Host, HostType, HostPortType


class TestHost(TestCase):
	def test_host_merge(self):
		host1 = Host('1.2.3.4', {})
		host1.create_port('11:22:33:44:55:66')

		host2 = Host('1.2.3.4', {})
		p = host2.create_port('11:22:33:44:55:66')
		p.name = 'eth0'
		p.type = HostPortType.ETHERNET_CSMACD

		# Test a key which won't be overridden
		host1.serial = 'this should not be replaced'

		host2.hostname = 'hostname'
		host2.gateway = '9.8.9.8'
		host2.contact = 'contact'
		host2.location = 'location'
		host2.type = HostType.CAMERA
		host2.manufacturer = 'manufacturer'
		host2.model = 'model'
		host2.serial = 'serial'
		host2.os_name = 'os name'
		host2.os_version = 'os version'
		host2.descr = 'descr'

		# Verify host 1 doesn't have any data.
		self.assertIsNone(host1.hostname)
		self.assertIsNone(host1.gateway)
		self.assertIsNone(host1.contact)
		self.assertIsNone(host1.type)
		self.assertIsNone(host1.manufacturer)
		self.assertIsNone(host1.model)
		self.assertEqual('this should not be replaced', host1.serial)
		self.assertIsNone(host1.os_name)
		self.assertIsNone(host1.os_version)
		self.assertIsNone(host1.descr)

		# Merge keys from host2
		host1.merge_from_host(host2)

		# Verify host 1 now has data.
		self.assertEqual('hostname', host1.hostname)
		self.assertEqual('9.8.9.8', host1.gateway)
		self.assertEqual('contact', host1.contact)
		self.assertEqual(HostType.CAMERA, host1.type)
		self.assertEqual('manufacturer', host1.manufacturer)
		self.assertEqual('model', host1.model)
		self.assertEqual('this should not be replaced', host1.serial)
		self.assertEqual('os name', host1.os_name)
		self.assertEqual('os version', host1.os_version)
		self.assertEqual('descr', host1.descr)

		self.assertEqual(1, len(host1.ports))
		self.assertEqual('eth0', host1.ports[0].name)
