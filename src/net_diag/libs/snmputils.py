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
