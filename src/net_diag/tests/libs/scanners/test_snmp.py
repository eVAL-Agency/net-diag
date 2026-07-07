import re
from unittest import TestCase
from unittest.mock import patch

from net_diag.libs.host import Host
from net_diag.tests import data
from importlib import resources
import net_diag.libs.scanners.snmp

MOCKED_SNMP_FILE = ''

TEST_DEVICE_PROFILES = {
	'axis-212ptz': {
		'host_attrs': {
			'reachable': True,
			'descr': ' ; AXIS 212 PTZ; Network Camera; 4.49; Jun 18 2009 13:28; 14D; 1; ',
			'contact': None,
			'location': None,
			'hostname': None,
			'mac': '00:40:8C:C8:13:20',
			'manufacturer': 'Axis Communications AB.',
			'model': '212 PTZ',
			'object_id': '1.3.6.1.4.1.368',
			'os_name': None,
			'os_version': '4.49',
			'os_date': None,
			'serial': None,
			'type': 'Camera',
			'gateway': '192.168.14.1',
			'uptime': 20625900
		},
		'total_ports': 3,
		'ports': {
			'1': {
				'name': 'lo',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 16436,
				'speed': 10000000,
				'bytes_rx': 0,
				'bytes_tx': 0,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': ['127.0.0.1'],
			},
			'2': {
				'name': 'eth0',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 1500,
				'speed': 100000000,
				'bytes_rx': 1138866078,
				'bytes_tx': 961215729,
				'errors_rx': 207,
				'errors_tx': 6,
				'ips': ['169.254.238.74', '192.168.14.31'],
			},
			'3': {
				'name': 'sit0',
				'label': None,
				'admin_status': 2,
				'user_status': 2,
				'mtu': 1480,
				'speed': 0,
				'bytes_rx': 0,
				'bytes_tx': 0,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			}
		}
	},
	'axis-m3004': {
		'host_attrs': {
			'reachable': True,
			'descr': ' ; AXIS M3004; Network Camera; 5.50.5.1; Nov 11 2014 14:36; 1A0; 1; ',
			'contact': None,
			'location': None,
			'hostname': None,
			'mac': 'AC:CC:8E:16:0E:C1',
			'manufacturer': 'Axis Communications AB.',
			'model': 'M3004',
			'object_id': '1.3.6.1.4.1.368',
			'os_name': None,
			'os_version': '5.50.5.1',
			'os_date': None,
			'serial': None,
			'type': 'Camera',
			'gateway': '192.168.14.1',
			'uptime': 512816900
		},
		'total_ports': 3,
		'ports': {
			'1': {
				'name': 'lo',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 16436,
				'speed': 10000000,
				'bytes_rx': 0,
				'bytes_tx': 0,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': ['127.0.0.1'],
			},
			'2': {
				'name': 'eth0',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 1500,
				'speed': 100000000,
				'bytes_rx': 835345512,
				'bytes_tx': 1315456986,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': ['169.254.72.24', '192.168.14.41'],
			},
			'3': {
				'name': 'sit0',
				'label': None,
				'admin_status': 2,
				'user_status': 2,
				'mtu': 1480,
				'speed': 0,
				'bytes_rx': 0,
				'bytes_tx': 0,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			}
		}
	},
	'axis-m3005': {
		'host_attrs': {
			'reachable': True,
			'descr': ' ; AXIS M3005; Network Camera; 5.51.6; Aug 15 2019 12:52; 1A7; 1; ',
			'contact': None,
			'location': None,
			'hostname': None,
			'mac': '00:40:8C:F0:C7:83',
			'manufacturer': 'Axis Communications AB.',
			'model': 'M3005',
			'object_id': '1.3.6.1.4.1.368',
			'os_name': None,
			'os_version': '5.51.6',
			'os_date': None,
			'serial': None,
			'type': 'Camera',
			'gateway': '192.168.14.1',
			'uptime': 2370826200
		},
		'total_ports': 3,
		'ports': {
			'1': {
				'name': 'lo',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 16436,
				'speed': 10000000,
				'bytes_rx': 3842,
				'bytes_tx': 3842,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': ['127.0.0.1'],
			},
			'2': {
				'name': 'eth0',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 1500,
				'speed': 100000000,
				'bytes_rx': 568287131,
				'bytes_tx': 4123578312,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': ['169.254.73.133', '192.168.14.10'],
			},
			'3': {
				'name': 'sit0',
				'label': None,
				'admin_status': 2,
				'user_status': 2,
				'mtu': 1480,
				'speed': 0,
				'bytes_rx': 0,
				'bytes_tx': 0,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			}
		}
	},
	'brother-mfc9330': {
		'host_attrs': {
			'reachable': True,
			'descr': 'Brother NC-8500h, Firmware Ver.1.00  (12.12.07),MID 8CE-415,FID 2',
			'contact': None,
			'location': None,
			'hostname': 'BRN001BA9E63A51',
			'mac': '00:1B:A9:E6:3A:51',
			'manufacturer': 'Brother Industries, Ltd.',
			'model': 'MFC-9330CDW',
			'object_id': '1.3.6.1.4.1.2435.2.3.9.1',
			'os_name': None,
			'os_version': '1.01 (C1302050813:0A26)',
			'os_date': '2013-02-05',
			'serial': 'U63480C3J120117',
			'type': 'Printer',
			'gateway': None,
			'uptime': 1973621537
		},
		'total_ports': 4,
		'ports': {
			'1': {
				'name': 'NC-8500h',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 1500,
				'speed': 100000000,
				'bytes_rx': 886711717,
				'bytes_tx': 23335551,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': ['10.200.0.201'],
			},
			'2': {
				'name': 'NC-8100w',
				'label': None,
				'admin_status': 2,
				'user_status': 2,
				'mtu': 1500,
				'speed': 72000000,
				'bytes_rx': 0,
				'bytes_tx': 0,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			},
			'3': {
				'name': 'NC-8100w',
				'label': None,
				'admin_status': 2,
				'user_status': 2,
				'mtu': 1500,
				'speed': 72000000,
				'bytes_rx': 0,
				'bytes_tx': 0,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			},
			'4': {
				'name': 'SoftwareLoopBack',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 1500,
				'speed': 0,
				'bytes_rx': 4181,
				'bytes_tx': 4181,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			}
		},
		'total_consumables': 10,
		'consumables': {
			'1': {
				'description': 'Black Toner Cartridge',
				'type': 3,
				'color': 'black',
				'current': -3,
				'unit': 13,
				'max': -2
			},
			'2': {
				'description': 'Cyan Toner Cartridge',
				'type': 3,
				'color': 'cyan',
				'current': -3,
				'unit': 13,
				'max': -2
			},
			'5': {
				'description': 'Waste Toner Box',
				'type': 4,
				'color': None,
				'current': -3,
				'unit': 13,
				'max': -2
			},
			'6': {
				'description': 'Belt Unit',
				'type': 1,
				'color': None,
				'current': 43852,
				'unit': 7,
				'max': 50000
			},
			'9': {
				'description': 'Magenta Drum Unit',
				'type': 9,
				'color': None,
				'current': 10928,
				'unit': 7,
				'max': 15000
			},
			'10': {
				'description': 'Yellow Drum Unit',
				'type': 9,
				'color': None,
				'current': 10928,
				'unit': 7,
				'max': 15000
			},
		}
	},
	'mikrotik-rb3011': {
		'host_attrs': {
			'reachable': True,
			'descr': 'RouterOS RB3011UiAS',
			'contact': None,
			'location': None,
			'hostname': 'WortTechs',
			'mac': '70:3A:CB:26:41:02',
			'manufacturer': 'Mikrotik',
			'model': 'RB3011UiAS',
			'object_id': '1.3.6.1.4.1.14988.1',
			'os_name': 'RouterOS',
			'os_version': '6.49.8',
			'os_date': None,
			'serial': 'E7EA0E923087',
			'type': 'Router',
			'gateway': '172.172.156.1',
			'uptime': 1234851900,
		},
		'total_ports': 12,
		'ports': {
			'1': {
				'name': 'ether1',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 1500,
				'speed': 1000000000,
				'bytes_rx': 20797747659017,
				'bytes_tx': 6086170717999,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': ['172.172.156.202'],
			},
			'6': {
				'name': 'sfp1',
				'label': None,
				'admin_status': 1,
				'user_status': 6,
				'vlan': '1',
			}
		}
	},
	'mikrotik-sw': {
		'host_attrs': {
			'reachable': True,
			'descr': 'CSS326-24G-2S+ SwOS v2.17',
			'contact': 'drew@worttechnologies.tech',
			'location': 'Home',
			'hostname': 'switch1',
			'mac': '2C:C8:1B:A6:1D:39',
			'manufacturer': 'Mikrotik',
			'model': 'CSS326-24G-2S+',
			'object_id': '1.3.6.1.4.1.14988.2',
			'os_name': 'SwOS',
			'os_version': '2.17',
			'os_date': None,
			'serial': 'D2780EB1CF56',
			'type': 'Switch',
			'gateway': None,
			'uptime': 2393566157,
		},
		'total_ports': 26,
		'ports': {
			'1': {
				'name': 'Porch',
				'label': None,
				'admin_status': 1,
				'user_status': 2,
				'mtu': 1500,
				'speed': 0,
				'bytes_rx': 92996680,
				'bytes_tx': 586813473,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			},
			'5': {
				'name': 'Port5',
				'label': None,
				'admin_status': 1,
				'user_status': 2,
				'mtu': 1500,
				'speed': 0,
				'bytes_rx': 0,
				'bytes_tx': 0,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			},
			'24': {
				'name': 'router',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 1500,
				'speed': 1000000000,
				'bytes_rx': 41734370514804,
				'bytes_tx': 13453999521046,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			},
		}
	},
	'tplink-24poe': {
		'host_attrs': {
			'reachable': True,
			'descr': '24-Port Gigabit Smart PoE Switch with 4 Combo SFP Slots',
			'contact': 'Charlie Powell',
			'location': 'FL02 Maintenance Room',
			'hostname': '175switch02',
			'mac': 'C0:4A:00:F3:27:B6',
			'manufacturer': 'TP-Link Technologies Co., LTD.',
			'model': 'TL-SG2424P 1.0',
			'object_id': '1.3.6.1.4.1.11863.1.1.17',
			'os_name': None,
			'os_version': '1.0.4 Build 20131219 Rel.76195',
			'os_date': None,
			'serial': None,
			'type': 'Switch',
			'gateway': None,
			'uptime': 1164681323,
		},
		'total_ports': 27,
		'ports': {
			'1': {
				'name': 'port 1: Gigabit Copper',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 1500,
				'speed': 1000000000,
				'bytes_rx': 70590029831009,
				'bytes_tx': 212063267683422,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			},
			'5': {
				'name': 'port 5: Gigabit Copper',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 1500,
				'speed': 100000000,
				'bytes_rx': 7369622447442,
				'bytes_tx': 174004268185,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			},
			'24': {
				'name': 'port 24: Gigabit Copper',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 1500,
				'speed': 100000000,
				'bytes_rx': 3754667683029,
				'bytes_tx': 101736957325,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			},
		}
	},
	'tplink-jetstream-24poe': {
		'host_attrs': {
			'reachable': True,
			'descr': 'JetStream 24-Port Gigabit Smart PoE+ Switch with 4 SFP Slots',
			'contact': 'https://eval.agency',
			'location': 'FL 04 Maintenance',
			'hostname': '175switch-04',
			'mac': '50:D4:F7:56:C6:F6',
			'manufacturer': 'TP-Link Technologies Co., LTD.',
			'model': 'T1600G-28PS 3.0',
			'object_id': '1.3.6.1.4.1.11863.5.37',
			'os_name': None,
			'os_version': '3.0.3 Build 20190430 Rel.43300(s)',
			'os_date': None,
			'serial': None,
			'type': 'Switch',
			'gateway': None,
			'uptime': 1174859579,
		},
		'total_ports': 31,
		'ports': {
			'1': {
				'name': 'Vlan-interface1',
				'label': None,
				'admin_status': 1,
				'user_status': 1,
				'mtu': 1500,
				'speed': 1000000000,
				'bytes_rx': 3023943581,
				'bytes_tx': 253599136,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': ['192.168.253.14'],
			},
			'49154': {
				'name': 'gigabitEthernet 1/0/2 : copper',
				'label': None,
				'admin_status': 1,
				'user_status': 2,
				'mtu': 1518,
				'speed': 0,
				'bytes_rx': 0,
				'bytes_tx': 0,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			},
			'49178': {
				'name': 'gigabitEthernet 1/0/26 : fiber',
				'label': None,
				'admin_status': 2,
				'user_status': 2,
				'mtu': 1518,
				'speed': 0,
				'bytes_rx': 0,
				'bytes_tx': 0,
				'errors_rx': 0,
				'errors_tx': 0,
				'ips': [],
			},
		}
	},
}


def snmp_walk_time_to_ticks(time_str: str) -> int:
	"""
	Converts an snmpwalk formatted TimeTicks string back to raw centiseconds.
	"""

	# Match optional days and mandatory HH:MM:SS.th
	pattern = r'(?:(\d+)\s+days?,\s+)?(\d{1,2}):(\d{2}):(\d{2})\.(\d{2})'
	match = re.match(pattern, time_str.strip())

	if not match:
		raise ValueError(f"Invalid SNMP TimeTicks format: {time_str}")

	days = int(match.group(1)) if match.group(1) else 0
	hours = int(match.group(2))
	minutes = int(match.group(3))
	seconds = int(match.group(4))
	centiseconds = int(match.group(5))

	# Calculate total seconds and convert to centiseconds
	total_seconds = (days * 86400) + (hours * 3600) + (minutes * 60) + seconds
	return (total_seconds * 100) + centiseconds


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

	elif 'Type=OctetString, Value=  ' in line and re.match('^[0-9a-fA-F: ]+$', val):
		# Translate the formatted hex string to a raw value
		val = '0x' + val.replace(' ', '').replace(':', '')

	elif 'Timeticks: (' in line:
		# Export from Unix; this provides the raw value
		# Timeticks: (3490606900) 404 days, 0:07:49.00
		match = re.match(r'.*Timeticks: \((\d+)\).*', line)
		val = int(match.group(1))

	elif 'Type=TimeTicks, Value=' in line:
		# Translate timeticks "142 days, 22:04:43.00" to an int
		val = snmp_walk_time_to_ticks(val)

	elif 'Type=Counter64, Value=0x' in line:
		# Type=Counter64, Value=0x12EA5A5C8109
		cleaned = re.sub(r'[\s:xX]', '', val.strip())
		val = int(cleaned, 16)

	elif line.strip().endswith('IpAddress: 0.0.0.0'):
		val = None

	return val


def mocked_snmp_extract_key(line: str) -> str:
	if line.startswith('OID=.'):
		# Windows style
		return line[5:line.index(',')]
	else:
		# Linux style
		return '1' + line[3:line.index(' ')]


async def mocked_snmp_lookup_single(hostname: str, community: str, oids: str | list[str]) -> str | None | dict:
	"""
	Override for the SNMP lookup function to return mocked data from a file.

	:param hostname:
	:param community:
	:param oid:
	:return:
	"""
	if isinstance(oids, list):
		count = len(oids)
		lookups = oids
	else:
		lookups = [oids]
		count = None

	ret = {}
	input_file = resources.files(data) / 'snmp' / (MOCKED_SNMP_FILE + '.txt')
	with input_file.open('r') as file:
		for line in file.readlines():
			# OID=.1.0.8802.1.1.2.1.3.7.1.2.1, Type=Integer, Value=3
			# iso.3.6.1.2.1.2.1.0 = INTEGER: 27
			for oid in lookups:
				if line.startswith('OID=.' + oid + ', ') or line.startswith('iso' + oid[1:] + ' = '):
					# This is the line the lookup is targeting
					val = mocked_snmp_extract_value(line)
					if count is None:
						return val
					else:
						ret[oid] = val

	return None if count is None else ret


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
	def test_all_definitions(self, mock_fn1, mock_fn2):
		global MOCKED_SNMP_FILE
		for filename, profile in TEST_DEVICE_PROFILES.items():
			# Setup mock file for this specific loop iteration
			MOCKED_SNMP_FILE = filename

			host = Host('172.0.0.1', {'community': 'test'})
			net_diag.libs.scanners.snmp.SNMPScanner.scan(host)

			# Assert Host Top-Level Attributes dynamically
			for attr, expected_value in profile['host_attrs'].items():
				self.assertEqual(
					expected_value,
					getattr(host, attr),
					f'Failed on host attribute: {filename}/{attr}'
				)

			# Assert Global Port Count
			self.assertEqual(
				profile['total_ports'],
				len(host.ports),
				f'Failed on total ports: {filename}'
			)

			# Assert Individual Port Key/Values dynamically
			for port_idx, expected_port_data in profile['ports'].items():
				self.assertIn(
					port_idx,
					host.ports,
					f'Failed to find port: {filename}/port {port_idx}'
				)
				port = host.ports[port_idx]
				for port_attr, expected_port_value in expected_port_data.items():
					self.assertEqual(
						expected_port_value,
						getattr(port, port_attr),
						f'Failed on port attribute: {filename}/port {port_idx}/{port_attr}'
					)

			if 'total_consumables' in profile:
				self.assertEqual(
					profile['total_consumables'],
					len(host.consumables),
					f'Failed on total consumables: {filename}'
				)

			if 'consumables' in profile:
				for consumable_idx, expected_consumable_data in profile['consumables'].items():
					consumable = host.consumables[consumable_idx]
					for key, expected_value in expected_consumable_data.items():
						self.assertEqual(
							expected_value,
							getattr(consumable, key),
							f'Failed on port attribute: {filename}/consumable {consumable_idx}/{key}'
						)
