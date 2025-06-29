import os
import socket
import struct
import subprocess
import re
import psutil


def get_interface_type(iface: str) -> str:
	"""
	Get the interface type as a human-readable string.

	:param iface: Interface to lookup, e.g. 'eth0', 'wlan0', etc.
	:return: ethernet, wlan, ppp, tap, bridge, vlan, ib, ibchild, firewire, gre, ipip, ip6tnl, sit, irda, or Unknown.
	"""
	if not os.path.exists('/sys/class/net'):
		return 'Unknown'

	try:
		iface_type = None
		with open(os.path.join('/sys/class/net', iface, 'type'), 'r') as f:
			iface_type = f.read().strip()

		# Simple checks
		simple_checks = {
			'24': 'firewire',  # Firewire, IEEE 1394 IPv4 - RFC 2734
			'512': 'ppp',  # Point-to-Point Protocol
			'768': 'ipip',  # IPIP Tunnel
			'769': 'ip6tnl',  # IPv6 Tunnel
			'772': 'lo',  # Loopback
			'776': 'sit',  # IPv6 in IPv4
			'778': 'gre',  # GRE over IP
			'783': 'irda',  # Linux-IrDA
			'801': 'wlan_aux',  # Auxiliary WLAN interface
			'65534': 'tun'  # TUN/TAP interface
		}
		if iface_type in simple_checks:
			return simple_checks[iface_type]

		if iface_type == '1':
			# Ethernet, may have more specific type which is more meaningful
			if os.path.exists(os.path.join('/sys/class/net', iface, 'phy80211')):
				return 'wlan'

			if os.path.exists(os.path.join('/sys/class/net', iface, 'wireless')):
				return 'wlan'

			if os.path.exists(os.path.join('/sys/class/net', iface, 'bridge')):
				return 'bridge'

			if os.path.exists(os.path.join('/proc/net/vlan/', iface)):
				# Yeah, this is a check for /proc from within a /sys collector, whatever
				return 'vlan'

			if os.path.exists(os.path.join('/sys/class/net', iface, 'bonding')):
				return 'bond'

			if os.path.exists(os.path.join('/sys/class/net', iface, 'tun_flags')):
				return 'tap'

			if os.path.exists(os.path.join('/sys/devices/virtual/net', iface)):
				return 'virtual'

			return 'ethernet'
		elif iface_type == '32':
			# InfiniBand
			if os.path.exists(os.path.join('/sys/class/net', iface, 'bonding')):
				return 'bond'
			elif os.path.exists(os.path.join('/sys/class/net', iface, 'create_child')):
				return 'ib'
			else:
				return 'ibchild'
		else:
			return 'Unknown'

	except FileNotFoundError:
		# The type file does not exist, which means the interface is likely not valid
		return 'Unknown'


def get_routes(iface: str) -> list[dict]:
	"""
	Get the routing table for a specific interface.

	:param iface: Interface to get routes for, e.g. 'eth0', 'wlan0', etc.
	:return: List of dictionaries containing route information.
	"""
	routes = []
	try:
		if os.name == 'nt':
			if_addresses = psutil.net_if_addrs()[iface]
			address = None
			for ip in if_addresses:
				if ip.family == socket.AF_INET:
					address = ip.address
					break
			if address is not None:
				output = subprocess.check_output(['route', 'print'], text=True)
				for line in output.splitlines():
					if address not in line:
						continue
					fields = line.strip().split()
					if fields[3] != address:
						continue
					if fields[0] in (address, '255.255.255.255'):
						continue
					destination = fields[0]
					mask = fields[1]
					gateway = fields[2]

					if gateway == 'On-link':
						gateway = '0.0.0.0'

					routes.append({
						'destination': destination,
						'gateway': gateway,
						'mask': mask,
					})
		else:
			with open('/proc/net/route', 'r') as f:
				for line in f.readlines()[1:]:  # Skip header
					# Fields are:
					# Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
					fields = line.strip().split()
					if fields[0] == iface:
						destination = socket.inet_ntoa(struct.pack("<L", int(fields[1], 16)))
						gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
						mask = socket.inet_ntoa(struct.pack("<L", int(fields[7], 16)))

						routes.append({
							'destination': destination,
							'gateway': gateway,
							'mask': mask,
						})
	except FileNotFoundError:
		pass
	return routes


def get_nameservers() -> list[str]:
	"""
	Get the nameservers configured on the system.

	:return: List of nameserver IP addresses.
	"""
	nameservers = []
	try:
		with open('/etc/resolv.conf', 'r') as f:
			for line in f:
				if line.startswith('nameserver'):
					nameservers.append(line.split()[1].strip())
	except FileNotFoundError:
		pass
	return nameservers


def get_domain() -> str:
	"""
	Get the domain name of the system.

	:return: Domain name as a string.
	"""
	return socket.getfqdn().split('.', 1)[-1] if '.' in socket.getfqdn() else ''


def get_wireless_info(iface: str) -> dict:
	"""
	Get wireless information for a specific interface.

	:param iface: Interface to get wireless info for, e.g. 'wlan0'.
	:return: Dictionary with wireless information.
	"""
	info = {}
	try:
		output = subprocess.check_output(['/sbin/iwconfig', iface], text=True)
		checks = {
			'ssid': r'ESSID:"([^"]+)"',
			'mode': r'Mode:(\w+)',
			'frequency': r'Frequency:(\d+\.\d+ \w+)',
			'bitrate': r'Bit Rate=(\d+(\.\d+)? \w+)',
			'signal_level': r'Signal level=(-?\d+)',
			'quality': r'Quality=(\d+/\d+)'
		}
		for key, pattern in checks.items():
			match = re.search(pattern, output)
			info[key] = match.group(1) if match else None
	except FileNotFoundError:
		pass
	return info


def get_neighbors(iface: str) -> list[dict]:
	"""
	Get the neighbors (ARP table) for a specific interface.

	:param iface: Interface to get neighbors for, e.g. 'eth0', 'wlan0'.
	:return: List of dictionaries containing neighbor information.
	"""
	neighbors = []
	try:
		if os.name == 'nt':
			# Windows-specific command to get ARP table
			if_addresses = psutil.net_if_addrs()[iface]
			output = ''
			for ip in if_addresses:
				if ip.family == socket.AF_INET:
					output = subprocess.check_output(['arp', '-a', '-N', ip.address], text=True)
					break
			for line in output.strip().split('\n'):
				fields = line.split()
				if len(fields) >= 2:
					if fields[1] == 'ff-ff-ff-ff-ff-ff-ff':
						# Skip broadcast addresses
						continue
					neighbors.append({
						'ip': fields[0],
						'mac': fields[1],
						'state': 'reachable'  # Windows does not provide state
					})
		else:
			# Linux-specific command to get ARP table
			output = subprocess.check_output(['ip', 'neighbor', 'show', 'dev', iface], text=True)
			for line in output.strip().split('\n'):
				fields = line.split()
				if len(fields) >= 4:
					neighbors.append({
						'ip': fields[0],
						'mac': fields[2],
						'state': fields[1]
					})
	except subprocess.CalledProcessError:
		pass
	return neighbors


def enable_lldp(iface: str) -> bool:
	"""
	Enable LLDP on a specific interface.

	:param iface: Interface to enable LLDP on, e.g. 'eth0', 'wlan0'.
	:return: True if LLDP was successfully enabled, False otherwise.
	"""
	try:
		current_status = subprocess.check_output(['/sbin/lldptool', '-l', '-i', iface, 'adminStatus'], text=True).strip()
		if 'rx' in current_status:
			# Already enabled!
			return True

		new_status = 'rxtx' if 'tx' in current_status else 'rx'
		subprocess.run(['/sbin/lldptool', '-L', '-i', iface, f'adminStatus={new_status}'], check=True)
		return True
	except subprocess.CalledProcessError:
		return False


def get_lldp_peer(iface: str) -> dict:
	"""
	Get LLDP peer information for a specific interface.

	:param iface: Interface to get LLDP peer info for, e.g. 'eth0', 'wlan0'.
	:return: Dictionary with LLDP peer information.
	"""
	data = {
		'chassis_id': None,
		'mac': None,
		'port_id': None,
		'port_name': None,
		'system_name': None,
		'system_description': None,
	}
	try:
		output = subprocess.check_output(['/sbin/lldptool', '-t', '-n', '-i', iface], text=True)
		lines = output.strip().split('\n')
		last_key = None
		for line in lines:
			if not line.startswith('\t'):
				last_key = line
			else:
				line_value = line.strip()
				if last_key == 'Chassis ID TLV':
					# chassisID
					if line_value.startswith('MAC: '):
						data['chassis_id'] = line_value[5:]
					else:
						data['chassis_id'] = line_value

				elif last_key == 'Port ID TLV':
					# portID
					if line_value.startswith('Local: '):
						data['port_id'] = line_value[7:]
					elif line_value.startswith('Ifname: '):
						data['port_id'] = line_value[8:]
					else:
						data['port_id'] = line_value

				elif last_key == 'Port Description TLV':
					# portDesc
					data['port_name'] = line_value

				elif last_key == 'System Name TLV':
					# sysName
					data['system_name'] = line_value

				elif last_key == 'System Description TLV':
					# sysDesc
					data['system_description'] = line_value
	except subprocess.CalledProcessError:
		pass
	return data
