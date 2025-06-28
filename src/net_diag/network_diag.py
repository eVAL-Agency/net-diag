import curses
import sys
import json
import requests
from net_diag.libs.nativeping import ping
import ipcalc
from dns import resolver
from dns.exception import DNSException
import socket
import psutil
import os
from net_diag.libs import net_utils
import argparse

_VERSION = '0.9.0'


class _Diagnostics:
	def __init__(self, iface: str = None):
		self.iface = iface
		self.is_root = os.geteuid() == 0
		self.has_lldp = os.path.exists('/sbin/lldptool')
		self.lldp_enabled = False

		# Try to enable LLDP if available.
		if self.is_root and self.has_lldp:
			self.lldp_enabled = net_utils.enable_lldp(self.iface)

		self.if_stats = None
		self.if_addresses = None
		self.if_type = None
		self.wifi = None
		self.data = {}
		self.errors = []

	def run(self):

		# Use PSUtil to get most of the network stats
		self.if_stats = psutil.net_if_stats()[self.iface]
		self.if_addresses = psutil.net_if_addrs()[self.iface]
		self.if_type = net_utils.get_interface_type(self.iface)
		self.data = {}
		self.errors = []

		if self.if_type == 'wlan':
			# also include wireless information
			self.wifi = net_utils.get_wireless_info(self.iface)

		# Run all the diagnostics steps
		self._run_type()
		self._run_status()
		if self.if_type == 'wlan':
			self._run_wifi()
		self._run_speed()
		if self.if_type != 'wlan':
			self._run_duplex()
		self._run_mtu()
		self._run_lldp()
		self._run_address()
		self._run_routes()
		self._run_nameservers()
		self._run_domain()
		self._run_neighbors()
		self._run_wan()
		self._run_connectivity()
		self._run_latency()
		self._run_dns()

	def _run_type(self):
		# Interface name and type
		self.data['interface'] = self.iface
		self.data['type'] = self.if_type

	def _run_status(self):
		# Status
		if self.if_stats.isup:
			self.data['status'] = 'UP'
		else:
			self.data['status'] = 'DOWN'
			self.errors.append('status')

	def _run_wifi(self):
		# Wireless connection data
		if self.wifi['ssid'] is not None:
			self.data['ssid'] = self.wifi['ssid']
		else:
			self.data['ssid'] = 'Not Connected'
			self.errors.append('ssid')

		if self.wifi['frequency'] is not None:
			self.data['frequency'] = self.wifi['frequency']
		else:
			self.data['frequency'] = 'Unknown'
			self.errors.append('frequency')

		# ▁▂▃▄▅▆▇█
		if self.wifi['signal_level'] is not None:
			level = int(self.wifi['signal_level'])
			if level <= -90:
				self.data['signal'] = "▁       "
			elif level <= -80:
				self.data['signal'] = "▁▂      "
			elif level <= -70:
				self.data['signal'] = "▁▂▃     "
			elif level <= -67:
				self.data['signal'] = "▁▂▃▄    "
			elif level <= -60:
				self.data['signal'] = "▁▂▃▄▅   "
			elif level <= -50:
				self.data['signal'] = "▁▂▃▄▅▆  "
			elif level <= -30:
				self.data['signal'] = "▁▂▃▄▅▆▇ "
			else:
				self.data['signal'] = "▁▂▃▄▅▆▇█"

			self.data['signal'] = self.data['signal'] + f" ({self.wifi['signal_level']} dBm)"

			if level < -67:
				self.errors.append('signal')
		else:
			self.data['signal'] = 'Unknown'
			self.errors.append('signal')

		if self.wifi['quality'] is not None:
			self.data['quality'] = self.wifi['quality']
		else:
			self.data['quality'] = 'Unknown'
			self.errors.append('quality')

	def _run_speed(self):
		# Link speed
		if self.if_type == 'wlan':
			self.data['speed'] = self.wifi['bitrate']
			if self.data['speed'] is None:
				self.errors.append('speed')
		else:
			speed = self.if_stats.speed
			if speed >= 1000:
				self.data['speed'] = f"{speed / 1000:.1f} Gbps"
			elif speed > 0:
				self.data['speed'] = f"{speed} Mbps"
			else:
				self.data['speed'] = "Unknown"
				self.errors.append('speed')

	def _run_duplex(self):
		# Duplex mode
		duplex = self.if_stats.duplex
		if duplex == 0:
			self.data['duplex'] = "Unknown"
			self.errors.append('duplex')
		elif duplex == 1:
			self.data['duplex'] = "Half Duplex"
		elif duplex == 2:
			self.data['duplex'] = "Full Duplex"

	def _run_mtu(self):
		# MTU
		self.data['mtu'] = self.if_stats.mtu

	def _run_lldp(self):
		# LLDP Neighbor
		if not self.is_root:
			self.data['lldp'] = 'LLDP requires root privileges'
			self.errors.append('lldp')
		else:
			if not self.has_lldp:
				self.data['lldp'] = 'Install lldptool to use LLDP'
				self.errors.append('lldp')
			else:
				if not self.lldp_enabled:
					self.data['lldp'] = 'LLDP could not be enabled!'
					self.errors.append('lldp')
				else:
					peer = net_utils.get_lldp_peer(self.iface)
					self.data['lldp'] = f"{peer['system_name']} - {peer['port_name']} [{peer['chassis_id']}] ({peer['system_description']})"

	def _run_address(self):
		# IP Address
		self.data['address'] = None
		for ip in self.if_addresses:
			if ip.family == socket.AF_INET:
				self.data['address'] = f'{ip.address}/{ipcalc.IP(ip.address, mask=ip.netmask).subnet()}'
				break
		if self.data['address'] is None:
			self.data['address'] = 'No IPv4 Address'
			self.errors.append('address')

	def _run_routes(self):
		# Routes
		routes = net_utils.get_routes(self.iface)
		if len(routes) == 0:
			self.errors.append('routes')
			self.data['routes'] = 'No routes found'
		else:
			r = []
			for route in routes:
				if route['destination'] == '0.0.0.0':
					r.append('Default gateway ' + route['gateway'])
				elif route['gateway'] == '0.0.0.0':
					r.append(f"Direct access to {route['destination']}/{ipcalc.IP(route['destination'], mask=route['mask']).subnet()}")
				else:
					r.append(f"{route['destination']}/{ipcalc.IP(route['destination'], mask=route['mask']).subnet()} via {route['gateway']}")
			self.data['routes'] = ', '.join(r)

	def _run_nameservers(self):
		# Nameservers
		ns = net_utils.get_nameservers()
		if len(ns) == 0:
			self.errors.append('nameservers')
			self.data['nameservers'] = 'No nameservers found'
		else:
			self.data['nameservers'] = ', '.join(ns)

	def _run_domain(self):
		# Domain name
		self.data['domain'] = net_utils.get_domain() or 'Unknown'

	def _run_neighbors(self):
		# Number of visible neighbors (via ARP)
		self.data['neighbors'] = len(net_utils.get_neighbors(self.iface))
		if self.data['neighbors'] == 0:
			self.errors.append('neighbors')
			self.data['neighbors'] = 'No neighbors found'
		else:
			self.data['neighbors'] = f"{self.data['neighbors']} visible devices"

	def _run_wan(self):
		# WAN IP Address
		try:
			self.data['wan'] = requests.get('https://wan.eval.bz', headers={'user-agent': f'network-diag/{_VERSION}'}).text
		except Exception:
			self.data['wan'] = 'Lookup Failed'
			self.errors.append('wan')

	def _run_connectivity(self):
		# Check if the internet is _actually_ reachable or if it's being intercepted by a captive portal
		try:
			if requests.get('https://up.eval.bz', headers={'user-agent': f'network-diag/{_VERSION}'}).text == 'up':
				self.data['internet'] = 'Connected'
			else:
				self.data['internet'] = 'INTERCEPTED'
				self.errors.append('internet')
		except Exception:
			self.data['internet'] = 'Lookup Failed'
			self.errors.append('internet')

	def _run_latency(self):
		# Check latency to a known good host
		res = ping('up.eval.bz', 1, timeout=2, return_latency=True)
		if res is False:
			self.data['latency'] = 'Ping Failed'
			self.errors.append('latency')
		elif res > 100:
			# Successful, but high latency.
			self.data['latency'] = f"{res:.2f} ms"
			self.errors.append('latency')
		else:
			# Successful and low latency
			self.data['latency'] = f"{res:.2f} ms"

	def _run_dns(self):
		# Perform a DNS lookup to check if DNS is working
		q = []
		try:
			q = resolver.resolve('up.eval.bz', 'A', lifetime=0.5)
		except DNSException as e:
			self.data['dns'] = str(e)
			self.errors.append('dns')
		if len(q) >= 1:
			# If we got a response, DNS is working
			self.data['dns'] = 'up.eval.bz -> ' + str(q[0].address)

			# Also check if an _INVALID_ DNS response is returned, (hint, it should NOT)
			try:
				q = resolver.resolve('invalid.eval.bz', 'A', lifetime=0.5)
				if len(q) >= 1:
					self.data['dns'] = 'Non-existent domain resolved to: ' + str(q[0].address)
					self.errors.append('dns')
				else:
					self.data['dns'] = 'Non-existent domain resolved to nothing'
					self.errors.append('dns')
			except resolver.NXDOMAIN:
				pass
		else:
			self.data['dns'] = 'DNS Resolution Failed'
			self.errors.append('dns')


class Application:
	def __init__(self, iface: str = None):
		self.iface = iface
		self.window = None
		self.is_root = os.geteuid() == 0
		self.has_lldp = os.path.exists('/sbin/lldptool')
		self.lldp_enabled = False

		if self.iface is None:
			# No interface set, prompt the user for which one they'd like.
			ifaces = psutil.net_if_stats()
			counter = 0
			options = {}
			print('Please select a network interface to diagnose:')
			print('')
			for iface in ifaces:
				if iface == 'lo':
					# Skip loopback interface
					continue

				counter += 1
				print(f"{counter}: {iface} ({ifaces[iface].flags})")
				options[counter] = iface

			print('')
			choice = int(input('Enter the number of the interface you want to diagnose: '))
			if choice in options:
				self.iface = options[choice]
			else:
				print("Invalid choice, exiting.")
				sys.exit(1)

	def json(self):
		"""
		Run a single analysis and print results to JSON
		:return:
		"""
		diagnostics = _Diagnostics(self.iface)
		diagnostics.run()
		print(json.dumps(diagnostics.data, indent=4, sort_keys=False))

	def run(self):
		diagnostics = _Diagnostics(self.iface)
		self.window = curses.initscr()

		curses.noecho()
		curses.cbreak()
		self.window.keypad(True)

		labels = {
			'address': 'IP Address',
			'mtu': 'MTU',
			'domain': 'Domain Name',
			'wan': 'WAN IP',
			'internet': 'Internet Status',
			'dns': 'DNS Resolution',
			'lldp': 'LLDP Peer',
		}

		try:
			while True:
				diagnostics.run()
				self.window.clear()

				window_height = self.window.getmaxyx()[0] - 3
				unimportant_fields = [
					'type', 'status', 'duplex', 'mtu', 'domain', 'neighbors'
				]

				self.window.addstr(0, 0, "Network Diagnostics v" + _VERSION)

				line = 2
				for key, value in diagnostics.data.items():
					if window_height <= 17 and key in unimportant_fields:
						# For small windows, try to skip some unimportant fields
						continue

					if key in labels:
						self.window.addstr(line, 0, labels[key])
					else:
						self.window.addstr(line, 0, key.capitalize())

					if key in diagnostics.errors:
						self.window.addstr(line, 21, '❌')
						self.window.addstr(line, 25, str(value))
					else:
						self.window.addstr(line, 20, '️✅')
						self.window.addstr(line, 24, str(value))

					line += 1
					if line > window_height:
						# Too many items to render; skip the rest!
						break

				# Display some controls for the user
				self.window.timeout(2000)
				self.window.addstr(self.window.getmaxyx()[0] - 1, 0, "P to pause, Q or CTRL+C to exit")

				key = self.window.getch()
				if key == ord('q') or key == ord('Q') or key == 27:
					break
				elif key == ord('p') or key == ord('P'):
					self.pause()

				self.window.refresh()
		except KeyboardInterrupt:
			# Catch CTRL+C
			pass
		except Exception as e:
			# Catch any other exceptions
			self.window.addstr(0, 0, f"!!!ERROR!!! {str(e)}")
			# Print file where the error occurred
			self.window.addstr(1, 0, f"Error occurred at line {sys.exc_info()[-1].tb_lineno}")
			self.window.addstr(self.window.getmaxyx()[0] - 1, 0, "Paused, press any key to exit...")
			self.window.refresh()
			self.window.getch()
		finally:
			self.exit()

	def pause(self):
		"""
		Pause the application and wait for user input.
		This is useful for debugging or when you want to see the output before exiting.
		"""
		self.window.timeout(-1)
		self.window.addstr(self.window.getmaxyx()[0] - 1, 0, "Paused, press any key to continue...")
		self.window.refresh()
		self.window.getch()

	def exit(self, exit_code: int = 0):
		"""
		Shutdown the application and restore terminal settings.

		:param exit_code:
		:return:
		"""
		curses.nocbreak()
		curses.echo()
		self.window.keypad(False)
		curses.endwin()
		exit(exit_code)


def run():

	parser = argparse.ArgumentParser(description="Network Diagnostics Tool")
	parser.add_argument('-i', '--iface', type=str, help='Network interface to diagnose')
	parser.add_argument('--json', action='store_true', help='Output in JSON format')
	args = parser.parse_args()

	app = Application(args.iface)
	if args.json:
		app.json()
	else:
		# Run the curses application
		app.run()


if __name__ == '__main__':
	# Allow this script to be run standalone
	run()
