from pysnmp.hlapi.v3arch.asyncio import ObjectType
from pysnmp.hlapi.v3arch.asyncio import ObjectIdentity
from pysnmp.hlapi.v3arch.asyncio import SnmpEngine
from pysnmp.hlapi.v3arch.asyncio import bulk_cmd
from pysnmp.hlapi.v3arch.asyncio import get_cmd
from pysnmp.hlapi.v3arch.asyncio import CommunityData
from pysnmp.hlapi.v3arch.asyncio import UdpTransportTarget
from pysnmp.hlapi.v3arch.asyncio import ContextData
from pysnmp.proto import rfc1905
import logging
from pysnmp.proto.rfc1902 import OctetString


def _cleanup_value(var_bind):
	if var_bind[1].tagSet in (
		rfc1905.NoSuchObject.tagSet,
		rfc1905.NoSuchInstance.tagSet,
	):
		# Key doesn't exist
		return None
	if isinstance(var_bind[1], ObjectIdentity):
		val = '.'.join(map(str, var_bind[1].asTuple()))
	elif isinstance(var_bind[1], OctetString):
		# Ensure pysnmp doesn't trip up with NULL bytes at the end of strings.
		val_bytes = var_bind[1].asOctets()
		val_bytes = val_bytes.rstrip(b'\x00')
		try:
			val = val_bytes.decode('utf-8')
		except UnicodeDecodeError:
			val = var_bind[1].prettyPrint()
	else:
		val = var_bind[1].prettyPrint()

	return val


async def snmp_lookup_single(hostname: str, community: str, oids: str | list[str]) -> str | None | dict:
	"""
	Lookup an OID value on a given host.

	:param hostname:
	:param community:
	:param oids:
	:return:
	"""

	if isinstance(oids, list):
		lookups = []
		count = len(oids)
		for oid in oids:
			lookups.append(ObjectType(ObjectIdentity(oid)))
	else:
		count = 1
		lookups = [ObjectType(ObjectIdentity(oids))]
	snmpEngine = SnmpEngine()
	auth = CommunityData(community, mpModel=1)
	channel = await UdpTransportTarget.create((hostname, 161), timeout=2, retries=0)
	error_indication, error_status, error_index, var_binds = await get_cmd(
		snmpEngine,
		auth,
		channel,
		ContextData(),
		*lookups
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
		ret = {}

		for var_bind in var_binds:  # SNMP response contents
			val = _cleanup_value(var_bind)
			key = var_bind[0].getOid().__str__()
			logging.debug('[snmp_lookup] %s = %s' % (key, val))
			if count == 1:
				# Single OID was requested.
				return val
			else:
				if val is not None:
					ret[key] = val

		return ret


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
		var_bind = None
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
				val = _cleanup_value(var_bind)
				if val is None:
					# Key doesn't exist
					run = False
					break
				key = var_bind[0].getOid().__str__()

				if key[0:len(oid)] != oid:
					# New OID entered, stop the lookup
					run = False
					break

				logging.debug('[snmp_lookup] %s = %s' % (key, val))

				ret[key] = val

		# Reset the lookup to the last OID returned, so we can continue
		if len(var_binds) > 0 and var_bind:
			lookups = [var_bind]
		else:
			run = False

	return ret
