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

	def run_scan(self):
		"""
		Perform a full scan of the host associated with this scanner
		:return:
		"""
		raise NotImplementedError("Subclasses must implement this method.")

	def run_scan_neighbors(self):
		"""
		Perform a full neighbor / child scan of devices available within this host scanner
		:return:
		"""
		raise NotImplementedError("Subclasses must implement this method.")
