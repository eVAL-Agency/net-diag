from net_diag.libs.nativeping import ping


class ICMPScanner:
	"""
	ICMP Scanner class for performing ICMP ping scans.
	"""

	def __init__(self, host):
		"""
		:param host:
		"""
		self.host = host

	def scan(self):
		"""
		Perform an ICMP ping scan on the target.
		"""
		self.host.log('Pinging %s' % (self.host.ip,))
		self.host.reachable = ping(self.host.ip)
		self.host.log('Reachable' if self.host.reachable else 'Not reachable')
