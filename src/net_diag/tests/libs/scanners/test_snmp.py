import re
from typing import Union
from unittest import TestCase
from unittest.mock import patch

from net_diag.libs.host import Host
from net_diag.tests import data
from importlib import resources
import net_diag.libs.scanners.snmp

MOCKED_SNMP_FILE = ''


def mocked_snmp_extract_value(line: str) -> str:
	# 0x000000000000
	if line.startswith('OID='):
		# Windows style
		val = line[line.index('Value=') + 6:].strip()
	else:
		# Linux style
		val = line[line.index(' = ') + 3:].strip()
		if val == '""':
			# Empty string
			return ''
		elif val.startswith('OID: iso'):
			val = '1' + val[8:]
		elif val.startswith('STRING: "'):
			# Remove the quotes from a string value
			val = val[9:-1]
		else:
			val = val[val.index(': ') + 2:]

	if 'Hex-STRING: ' in line and re.match('^[0-9a-fA-F ]+$', val):
		# Translate the formatted hex string to a raw value
		val = '0x' + val.replace(' ', '')

	if 'Type=OctetString, Value=  ' in line and re.match('^[0-9a-fA-F: ]+$', val):
		# Translate the formatted hex string to a raw value
		val = '0x' + val.replace(' ', '').replace(':', '')

	return val


def mocked_snmp_extract_key(line: str) -> str:
	if line.startswith('OID=.'):
		# Windows style
		return line[5:line.index(',')]
	else:
		# Linux style
		return '1' + line[3:line.index(' ')]


async def mocked_snmp_lookup_single(hostname: str, community: str, oid: str) -> Union[str, None]:
	"""
	Override for the SNMP lookup function to return mocked data from a file.

	:param hostname:
	:param community:
	:param oid:
	:return:
	"""
	input_file = resources.files(data) / 'snmp' / (MOCKED_SNMP_FILE + '.txt')
	with input_file.open('r') as file:
		for line in file.readlines():
			# OID=.1.0.8802.1.1.2.1.3.7.1.2.1, Type=Integer, Value=3
			# iso.3.6.1.2.1.2.1.0 = INTEGER: 27
			if line.startswith('OID=.' + oid + ', ') or line.startswith('iso' + oid[1:] + ' = '):
				# This is the line the lookup is targeting
				return mocked_snmp_extract_value(line)
	return None


async def mocked_snmp_lookup_bulk(hostname: str, community: str, oid: str) -> dict:
	"""
	Override for the SNMP lookup function to return mocked data from a file.

	:param hostname:
	:param community:
	:param oid:
	:return:
	"""
	input_file = resources.files(data) / 'snmp' / (MOCKED_SNMP_FILE + '.txt')
	ret = {}
	with input_file.open('r') as file:
		for line in file.readlines():
			# OID=.1.0.8802.1.1.2.1.3.7.1.2.1, Type=Integer, Value=3
			# iso.3.6.1.2.1.2.1.0 = INTEGER: 27
			if line.startswith('OID=.' + oid + '.') or line.startswith('iso' + oid[1:] + '.'):
				# This is the line the lookup is targeting
				ret[mocked_snmp_extract_key(line)] = mocked_snmp_extract_value(line)
	return ret


class TestSNMPScanner(TestCase):
	@patch('net_diag.libs.scanners.snmp.snmp_lookup_single', side_effect=mocked_snmp_lookup_single)
	@patch('net_diag.libs.scanners.snmp.snmp_lookup_bulk', side_effect=mocked_snmp_lookup_bulk)
	def test_mikrotik_rb3011(self, mock_fn1, mock_fn2):
		global MOCKED_SNMP_FILE
		MOCKED_SNMP_FILE = 'mikrotik-rb3011'

		host = Host('172.0.0.1', {'community': 'test'})
		net_diag.libs.scanners.snmp.SNMPScanner.scan(host)
		net_diag.libs.scanners.snmp.SNMPScanner.scan_neighbors(host)

		self.assertTrue(host.reachable)
		self.assertEqual('RouterOS RB3011UiAS', host.descr)
		self.assertEqual('WortTechs', host.hostname)
		self.assertEqual('70:3A:CB:26:41:02', host.mac)
		self.assertEqual('Mikrotik', host.manufacturer)
		self.assertEqual('RB3011UiAS', host.model)
		self.assertEqual('1.3.6.1.4.1.14988.1', host.object_id)
		self.assertEqual('RouterOS', host.os_name)
		self.assertEqual('6.49.8', host.os_version)
		self.assertEqual('E7EA0E923087', host.serial)
		self.assertEqual('Router', host.type)
		self.assertEqual('172.172.156.1', host.gateway)

		self.assertEqual(12, len(host.links))

		self.assertEqual('ether1', host.links['1'].name)
		self.assertEqual('UP', host.links['1'].admin_status)
		self.assertEqual('UP', host.links['1'].user_status)
		self.assertEqual(1500, host.links['1'].mtu)
		self.assertEqual('1gbps', host.links['1'].speed)

		self.assertEqual('sfp1', host.links['6'].name)
		self.assertEqual('UP', host.links['6'].admin_status)
		self.assertEqual('DOWN', host.links['6'].user_status)
		self.assertEqual('1', host.links['6'].vlan)

	@patch('net_diag.libs.scanners.snmp.snmp_lookup_single', side_effect=mocked_snmp_lookup_single)
	@patch('net_diag.libs.scanners.snmp.snmp_lookup_bulk', side_effect=mocked_snmp_lookup_bulk)
	def test_ubiquiti_us8(self, mock_fn1, mock_fn2):
		global MOCKED_SNMP_FILE
		MOCKED_SNMP_FILE = 'unifi-us8-60w'

		host = Host('172.0.0.1', {'community': 'test'})
		net_diag.libs.scanners.snmp.SNMPScanner.scan(host)
		net_diag.libs.scanners.snmp.SNMPScanner.scan_neighbors(host)

		self.assertTrue(host.reachable)
		self.assertEqual('US-8-60W, 7.0.50.15613, Linux 3.6.5', host.descr)
		self.assertEqual('US-8-60W', host.hostname)
		self.assertEqual('F0:9F:C2:18:4C:28', host.mac)
		self.assertEqual('Ubiquiti Networks Inc.', host.manufacturer)
		self.assertEqual('US-8-60W', host.model)
		self.assertEqual('1.3.6.1.4.1.4413', host.object_id)
		self.assertEqual('7.0.50.15613', host.os_version)
		self.assertEqual('f09fc2184c27', host.serial)
		self.assertEqual('Switch', host.type)
		self.assertEqual('10.200.0.1', host.gateway)

		self.assertEqual(35, len(host.links))

		self.assertEqual('Slot: 0 Port: 1 Gigabit - Level', host.links['1'].name)
		self.assertEqual('UP', host.links['1'].admin_status)
		self.assertEqual('UP', host.links['1'].user_status)
		self.assertEqual(1518, host.links['1'].mtu)
		self.assertEqual('1gbps', host.links['1'].speed)
		self.assertEqual('1', host.links['1'].vlan)

	@patch('net_diag.libs.scanners.snmp.snmp_lookup_single', side_effect=mocked_snmp_lookup_single)
	@patch('net_diag.libs.scanners.snmp.snmp_lookup_bulk', side_effect=mocked_snmp_lookup_bulk)
	def test_ubiquiti_uxg_lite(self, mock_fn1, mock_fn2):
		global MOCKED_SNMP_FILE
		MOCKED_SNMP_FILE = 'unifi-uxg-lite'

		host = Host('172.0.0.1', {'community': 'test'})
		net_diag.libs.scanners.snmp.SNMPScanner.scan(host)
		net_diag.libs.scanners.snmp.SNMPScanner.scan_neighbors(host)

		self.assertTrue(host.reachable)
		self.assertEqual('Ubiquiti UniFi UXG-Lite 4.1.13 Linux 5.4.213 ipq5018', host.descr)
		self.assertEqual('UXG-Lite', host.hostname)
		self.assertEqual('9E:05:D6:51:8B:5A', host.mac)
		self.assertEqual('Ubiquiti Networks Inc.', host.manufacturer)
		self.assertEqual('UXG-Lite', host.model)
		self.assertEqual('1.3.6.1.4.1.8072.3.2.10', host.object_id)
		self.assertEqual('UniFi OS', host.os_name)
		self.assertEqual('4.1.13', host.os_version)
		self.assertEqual('Gateway', host.type)
		self.assertEqual('location', host.location)

		self.assertEqual(15, len(host.links))

		self.assertEqual('lo', host.links['1'].name)
		self.assertEqual('UP', host.links['1'].admin_status)
		self.assertEqual('UP', host.links['1'].user_status)
		self.assertEqual(65536, host.links['1'].mtu)
		self.assertEqual('9E:05:D6:51:8B:5A', host.links['1'].mac)
		self.assertEqual('10mbps', host.links['1'].speed)

		self.assertEqual(12, len(host.neighbors))

		self.assertEqual('10.200.0.2', host.neighbors['10.200.0.2'].ip)
		self.assertEqual('BC:EE:7B:8C:4C:4F', host.neighbors['10.200.0.2'].mac)
