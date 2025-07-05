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
		val = line[line.index(' = ') + 3:]
		if val.startswith('OID: iso'):
			val = '1' + val[8:]
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
		scanner = net_diag.libs.scanners.snmp.SNMPScanner(host)
		scanner.scan()

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

		self.assertEqual(12, len(host.interfaces))

		self.assertEqual('ether1', host.interfaces['1'].name)
		self.assertEqual('UP', host.interfaces['1'].admin_status)
		self.assertEqual('UP', host.interfaces['1'].user_status)
		self.assertEqual(1500, host.interfaces['1'].mtu)
		self.assertEqual('1gbps', host.interfaces['1'].speed)

		self.assertEqual('sfp1', host.interfaces['6'].name)
		self.assertEqual('UP', host.interfaces['6'].admin_status)
		self.assertEqual('DOWN', host.interfaces['6'].user_status)
		self.assertEqual('1', host.interfaces['6'].vlan)
