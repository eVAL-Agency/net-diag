import platform
import subprocess


def ping(host_or_ip: str, packets: int = 1, timeout: int = 1) -> bool:
	"""
	Calls system "ping" command, returns True if ping succeeds.

	:param host_or_ip: IP address or hostname to ping
	:param packets: Number of retries
	:param timeout: seconds to wait for response
	:return: True if ping succeeds, False otherwise.

	Does not show any output, either as popup window or in command line.
	Python 3.5+, Windows and Linux compatible

	@see https://stackoverflow.com/a/55656177
	original author: Jose Francisco Lopez Pimentel
	https://stackoverflow.com/users/6365912/jose-francisco-lopez-pimentel
	"""
	# The ping command is the same for Windows and Linux, except for the "number of packets" flag.
	if platform.system().lower() == 'windows':
		command = ['ping', '-n', str(packets), '-w', str(timeout), host_or_ip]
		# run parameters: capture output, discard error messages, do not show window
		result = subprocess.run(
			command,
			stdin=subprocess.DEVNULL,
			stdout=subprocess.PIPE,
			stderr=subprocess.DEVNULL,
			creationflags=0x08000000
		)
		# 0x0800000 is a windows-only Popen flag to specify that a new process will not create a window.
		# On Python 3.7+, you can use a subprocess constant:
		#   result = subprocess.run(command, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
		# On windows 7+, ping returns 0 (ok) when host is not reachable; to be sure host is responding,
		# we search the text "TTL=" on the command output. If it's there, the ping really had a response.
		return result.returncode == 0 and b'TTL=' in result.stdout
	else:
		command = ['ping', '-c', str(packets), '-w', str(timeout), host_or_ip]
		# run parameters: discard output and error messages
		result = subprocess.run(
			command,
			stdin=subprocess.DEVNULL,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL
		)
		return result.returncode == 0
