from net_diag.libs.host import Host


class ScannerInterface:
	"""
	Base class for all scanners.
	"""

	def __init__(self, host: Host):
		self.host: Host = host
		"""
		Underlying host to populate
		: type host: Host
		"""

	@classmethod
	def discover(cls, host: Host) -> bool:
		"""
		Perform a fast discovery for the host to verify if it supports this scanner

		:param host:
		:return:
		"""
		raise NotImplementedError("Subclasses must implement this method.")

	@classmethod
	def scan(cls, host: Host):
		"""
		Perform a scan on the target.
		"""
		raise NotImplementedError("Subclasses must implement this method.")

	@classmethod
	def scan_neighbors(cls, host: Host):
		"""
		Perform a scan on the target.
		"""
		raise NotImplementedError("Subclasses must implement this method.")
