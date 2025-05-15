from pysnmp import hlapi
from typing import Union
import re
import logging


def snmp_lookup_single(hostname: str, community: str, oid: str) -> Union[str, None]:
	"""
	Lookup an OID value on a given host.

	:param hostname:
	:param community:
	:param oid:
	:return:
	"""

	error_responses = (
		'No Such Object currently exists at this OID',
	)

	# snmpEngine, authData, transportTarget, contextData, nonRepeaters, maxRepetitions, *varBinds
	iterator = hlapi.getCmd(
		hlapi.SnmpEngine(),
		hlapi.CommunityData(community, mpModel=1),
		hlapi.UdpTransportTarget((hostname, 161), timeout=2, retries=0),
		hlapi.ContextData(),
		hlapi.ObjectType(hlapi.ObjectIdentity(oid))
	)

	error_indication, error_status, error_index, var_binds = next(iterator)
	if error_indication:
		# Usually indicates no SNMP on target device or credentials were incorrect.
		logging.debug('[snmp_lookup_single] %s' % error_indication.__str__())
		return None
	else:
		if error_status:  # SNMP agent errors
			logging.debug(
				'[snmp_lookup_single] %s at %s' % (
					error_status.prettyPrint(),
					var_binds[int(error_index) - 1] if error_index else '?'
				)
			)
			return None
		else:
			for var_bind in var_binds:  # SNMP response contents
				key = var_bind[0].getOid().__str__()
				val = var_bind[1].prettyPrint()

				logging.debug('[snmp_lookup_single] %s = %s' % (key, val))
				if val in error_responses:
					return None
				return val

	return None


def snmp_lookup_bulk(hostname: str, community: str, oid: str) -> dict:
	"""
	Lookup a set of OID values on a given host.

	:param hostname:
	:param community:
	:param oid:
	:return:
	"""
	ret = {}

	iterator = hlapi.bulkCmd(
		hlapi.SnmpEngine(),
		hlapi.CommunityData(community, mpModel=1),
		hlapi.UdpTransportTarget((hostname, 161), timeout=10, retries=0),
		hlapi.ContextData(),
		False,
		5,
		hlapi.ObjectType(hlapi.ObjectIdentity(oid))
	)

	try:
		while True:
			error_indication, error_status, error_index, var_binds = next(iterator)
			if error_indication:
				# Usually indicates no SNMP on target device or credentials were incorrect.
				logging.debug('[snmp_lookup_bulk] %s' % error_indication.__str__())
				return ret
			else:
				if error_status:  # SNMP agent errors
					logging.debug(
						'[snmp_lookup_bulk] %s at %s' % (
							error_status.prettyPrint(),
							var_binds[int(error_index) - 1] if error_index else '?'
						)
					)
					return ret
				else:
					for var_bind in var_binds:  # SNMP response contents
						key = var_bind[0].getOid().__str__()
						val = var_bind[1].prettyPrint()

						if key[0:len(oid)] != oid:
							raise StopIteration

						logging.debug('[snmp_lookup_bulk] %s = %s' % (key, val))

						ret[key] = val
	except StopIteration:
		pass

	return ret


def snmp_parse_descr(descr: str) -> dict:
	"""
	Parse SNMP description string and return a dictionary with the parsed values

	Possible keys:

	* manufacturer
	* type
	* model
	* serial
	* os_version

	:param descr:
	:return:
	"""
	checks = (
		(
			#  ; AXIS 212 PTZ; Network Camera; 4.49; Jun 18 2009 13:28; 14D; 1;
			r'^ ; AXIS (?P<model>[^;]*); Network Camera; (?P<os_version>[^;]*); [ADFJMNOS][aceopu][bcglnprtvy] [0-9]{1,2} [0-9]{4} [0-9]{1,2}:[0-9]{2};.*',  # noqa: E501
			{'manufacturer': 'Axis Communications AB.', 'type': 'Camera'}
		),
		(
			# 24-Port Gigabit Smart PoE Switch with 4 Combo SFP Slots
			r'^24-Port Gigabit Smart PoE Switch with 4 Combo SFP Slots$',
			{'type': 'Switch'}
		),
		(
			# H.264 Mega-Pixel Network Camera
			r'^H.264 Mega-Pixel Network Camera$',
			{'type': 'Camera'}
		),
		(
			# HP ETHERNET MULTI-ENVIRONMENT,SN:VNB8JCKF0M,FN:1N807W6,SVCID:27057,PID:HP Color LaserJet MFP M477fnw
			r'^HP ETHERNET MULTI-ENVIRONMENT,SN:(?P<serial>[^,]+),FN:[^,]+,SVCID:[^,]+,PID:(?P<model>.*)$',
			{'manufacturer': 'Hewlett Packard', 'type': 'Printer'}
		),
		(
			# JetStream 24-Port Gigabit Smart PoE+ Switch with 4 SFP Slots
			r'^JetStream 24-Port Gigabit Smart PoE\+ Switch with 4 SFP Slots$',
			{'type': 'Switch'}
		),
		(
			# UAP-AC-Lite 6.6.77.15402
			r'^(?P<model>UAP-AC-Lite) (?P<os_version>[^ ]+)$',
			{'manufacturer': 'Ubiquiti Networks Inc.', 'type': 'WIFI'}
		),
		(
			# UAP-AC-Pro-Gen2 6.6.77.15402
			r'^(?P<model>UAP-AC-Pro-Gen2) (?P<os_version>[^ ]+)$',
			{'manufacturer': 'Ubiquiti Networks Inc.', 'type': 'WIFI'}
		),
		(
			# Ubiquiti UniFi UDM-Pro 4.1.13 Linux 4.19.152 al324
			r'^Ubiquiti UniFi (?P<model>UDM-Pro) (?P<os_version>[^ ]+) Linux [^ ]+ [^ ]+$',
			{'manufacturer': 'Ubiquiti Networks Inc.', 'type': 'Router'}
		)
	)

	for check in checks:
		match = re.match(check[0], descr)
		if match:
			ret = {}
			for key, value in check[1].items():
				# Set hardcoded overrides from the definition
				ret[key] = value
			for key, value in match.groupdict().items():
				ret[key] = value

			return ret

	# No match found
	return {}
