from net_diag.libs.host import Host
from net_diag.libs.nativeping import ping
from net_diag.libs.scanners import ScannerInterface


class ICMPScanner(ScannerInterface):
	"""
	ICMP Scanner class for performing ICMP ping scans.
	"""

	def __init__(self, host):
		"""
		:param host:
		"""
		super().__init__(host)

	@classmethod
	def scan(cls, host: Host):
		"""
		Perform an ICMP ping scan on the target.
		"""
		host.log('Pinging %s' % (host.ip,))
		host.ping = ping(host.ip, return_latency=True, formatted=True)
		if not host.ping:
			host.log('Not reachable via ICMP ping')
		else:
			host.reachable = True
			host.log('Reachable via ICMP ping')

	@classmethod
	def scan_neighbors(cls, host: Host):
		pass
