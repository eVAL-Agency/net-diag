from pysnmp.hlapi.v3arch.asyncio import ObjectType
from pysnmp.hlapi.v3arch.asyncio import ObjectIdentity
from pysnmp.hlapi.v3arch.asyncio import SnmpEngine
from pysnmp.hlapi.v3arch.asyncio import bulk_cmd
from pysnmp.hlapi.v3arch.asyncio import get_cmd
from pysnmp.hlapi.v3arch.asyncio import CommunityData
from pysnmp.hlapi.v3arch.asyncio import UdpTransportTarget
from pysnmp.hlapi.v3arch.asyncio import ContextData
from pysnmp.proto import rfc1905
from typing import Union
import re
import logging


async def snmp_lookup_single(hostname: str, community: str, oid: str) -> Union[str, None]:
	"""
	Lookup an OID value on a given host.

	:param hostname:
	:param community:
	:param oid:
	:return:
	"""

	lookups = ObjectType(ObjectIdentity(oid))
	snmpEngine = SnmpEngine()
	auth = CommunityData(community, mpModel=1)
	channel = await UdpTransportTarget.create((hostname, 161), timeout=2, retries=0)
	error_indication, error_status, error_index, var_binds = await get_cmd(
		snmpEngine,
		auth,
		channel,
		ContextData(),
		lookups
	)

	if error_indication:
		# Usually indicates no SNMP on target device or credentials were incorrect.
		logging.debug('[snmp_lookup] %s' % error_indication.__str__())
		return None
	elif error_status:  # SNMP agent errors
		logging.debug(
			'[snmp_lookup] %s at %s' % (
				error_status.prettyPrint(),
				var_binds[int(error_index) - 1][0] if error_index else '?'
			)
		)
		return None
	else:
		for var_bind in var_binds:  # SNMP response contents
			if var_bind[1].tagSet in (
				rfc1905.NoSuchObject.tagSet,
				rfc1905.NoSuchInstance.tagSet,
			):
				# Key doesn't exist
				return None
			key = var_bind[0].getOid().__str__()
			val = var_bind[1].prettyPrint()

			logging.debug('[snmp_lookup] %s = %s' % (key, val))
			return val

	return None


async def snmp_lookup_bulk(hostname: str, community: str, oid: str) -> dict:
	"""
	Lookup an OID value on a given host.

	:param hostname:
	:param community:
	:param oid:
	:return:
	"""
	ret = {}

	lookups = [ObjectType(ObjectIdentity(oid))]
	snmpEngine = SnmpEngine()
	run = True
	while run:
		error_indication, error_status, error_index, var_binds = await bulk_cmd(
			snmpEngine,
			CommunityData(community, mpModel=1),
			await UdpTransportTarget.create((hostname, 161), timeout=3, retries=0),
			ContextData(),
			0,
			20,
			*lookups
		)

		if error_indication:
			# Usually indicates no SNMP on target device or credentials were incorrect.
			logging.debug('[snmp_lookup] %s' % error_indication.__str__())
			run = False
		elif error_status:  # SNMP agent errors
			logging.debug(
				'[snmp_lookup] %s at %s' % (
					error_status.prettyPrint(),
					var_binds[int(error_index) - 1][0] if error_index else '?'
				)
			)
			run = False
		else:
			for var_bind in var_binds:  # SNMP response contents
				if var_bind[1].tagSet in (
					rfc1905.NoSuchObject.tagSet,
					rfc1905.NoSuchInstance.tagSet,
				):
					# Key doesn't exist
					run = False
					break
				key = var_bind[0].getOid().__str__()
				val = var_bind[1].prettyPrint()

				if key[0:len(oid)] != oid:
					# New OID entered, stop the lookup
					run = False
					break

				logging.debug('[snmp_lookup] %s = %s' % (key, val))

				ret[key] = val

		# Reset the lookup to the last OID returned, so we can continue
		lookups = [var_binds[len(var_binds) - 1]]

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
			{'manufacturer': 'TP-Link Technologies Co., LTD.', 'type': 'Switch'}
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
			{'manufacturer': 'TP-Link Technologies Co., LTD.', 'type': 'Switch'}
		),
		(
			# MikroTik RouterOS 6.49.8 (long-term) RB3011UiAS
			r'^(?P<manufacturer>MikroTik) (?P<os>RouterOS) (?P<os_version>[0-9\.]+) (long-term) RB3011UiAS$',
			{'type': 'Router', 'model': 'RB3011UiAS-RM'}
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
