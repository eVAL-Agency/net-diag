import curses
import sys
import json
import time
from multiprocessing import Process
from multiprocessing import Manager
from multiprocessing import Event

import requests
from requests.exceptions import RequestException
from net_diag.libs.nativeping import ping
import ipcalc
from dns import resolver
from dns.exception import DNSException
import socket
import psutil
import os
from net_diag.libs import net_utils
import argparse
import traceback

_VERSION = '0.9.0'


class _Diagnostics:
	"""
	Handler for all NIC diagnostics.
	"""

	def __init__(self, iface: str = None):
		self.iface = iface
		self.if_type = net_utils.get_interface_type(self.iface)
		self.data = {}
		self.checks = []
		self.manager = Manager()
		self.stop_event = Event()
		self.threaded = True
		self.started = False

	def start(self):
		"""
		Start the background processes to monitor diagnostics.

		:return:
		"""

		# Pre-populate the data dictionary so the order of the keys is consistent.
		if self.threaded:
			self.data = self.manager.dict()

		self.data['interface'] = ('Not ran', True)
		self.data['type'] = ('Not ran', True)
		self.data['status'] = ('Not ran', True)

		if self.if_type == 'wlan':
			self.data['ssid'] = ('Not ran', True)
			self.data['frequency'] = ('Not ran', True)
			self.data['signal'] = ('Not ran', True)
			self.data['quality'] = ('Not ran', True)
		else:
			self.data['duplex'] = ('Not ran', True)

		self.data['speed'] = ('Not ran', True)
		self.data['mtu'] = ('Not ran', True)
		self.data['lldp'] = ('Not ran', True)
		self.data['address'] = ('Not ran', True)
		self.data['routes'] = ('Not ran', True)
		self.data['nameservers'] = ('Not ran', True)
		self.data['domain'] = ('Not ran', True)
		self.data['neighbors'] = ('Not ran', True)
		self.data['wan'] = ('Not ran', True)
		self.data['internet'] = ('Not ran', True)
		self.data['latency'] = ('Not ran', True)
		self.data['dns'] = ('Not ran', True)

		execs = [
			self._run_type,
			self._run_interface_details,
			self._run_lldp,
			self._run_connectivity,
			self._run_wan,
			self._run_latency,
			self._run_dns,
		]

		if self.threaded:
			if not self.started:
				for exe in execs:
					self.checks.append(Process(target=exe, args=(self.data, self.stop_event)))

				for check in self.checks:
					check.start()
		else:
			# Run all checks in the main thread
			for exe in execs:
				exe(self.data, self.stop_event)

	def stop(self):
		self.stop_event.set()
		# Wait for all checks to finish
		for checks in self.checks:
			checks.join()

	def run(self):
		"""
		Run diagnostics once and stop
		:return:
		"""
		self.start()
		if self.threaded:
			time.sleep(1)
			self.stop()

	def _run_type(self, data, stop_event):
		"""
		Set the interface name and type in the data dictionary.

		:param data:
		:return:
		"""
		# Interface name and type
		data['interface'] = (self.iface, False)
		data['type'] = (self.if_type, False)

	def _run_interface_details(self, data, stop_event):
		"""
		Perform basic local-data checks which can be performed relatively quickly.

		:param data:
		:param stop_event:
		:return:
		"""
		while True:
			if stop_event.is_set():
				return

			# Use PSUtil to get most of the network stats
			if_stats = psutil.net_if_stats()[self.iface]
			wifi = None
			if self.if_type == 'wlan':
				wifi = net_utils.get_wireless_info(self.iface)

			try:
				self._parse_status(data, if_stats)
				self._parse_mtu(data, if_stats)
				self._run_address(data)
				self._run_routes(data)
				self._run_nameservers(data)
				self._run_domain(data)
				self._run_neighbors(data)

				if wifi:
					self._parse_wifi(data, wifi)
					self._parse_speed_wifi(data, wifi)
				else:
					self._parse_speed_lan(data, if_stats)
					self._parse_duplex(data, if_stats)
			except BrokenPipeError:
				# Process stopped, just exit
				break

			if self.threaded:
				time.sleep(1)
			else:
				break

	def _parse_status(self, data, if_stats):
		# Status
		if if_stats.isup:
			data['status'] = ('UP', False)
		else:
			data['status'] = ('DOWN', True)

	def _parse_wifi(self, data, wifi):
		# Wireless connection data
		if wifi['ssid'] is not None:
			data['ssid'] = (wifi['ssid'], False)
		else:
			data['ssid'] = ('Not Connected', True)

		if wifi['frequency'] is not None:
			data['frequency'] = (wifi['frequency'], False)
		else:
			data['frequency'] = ('Unknown', True)

		# ▁▂▃▄▅▆▇█
		if wifi['signal_level'] is not None:
			level = int(wifi['signal_level'])
			if level <= -90:
				signal = "▁       "
			elif level <= -80:
				signal = "▁▂      "
			elif level <= -70:
				signal = "▁▂▃     "
			elif level <= -67:
				signal = "▁▂▃▄    "
			elif level <= -60:
				signal = "▁▂▃▄▅   "
			elif level <= -50:
				signal = "▁▂▃▄▅▆  "
			elif level <= -30:
				signal = "▁▂▃▄▅▆▇ "
			else:
				signal = "▁▂▃▄▅▆▇█"

			signal = signal + f" ({wifi['signal_level']} dBm)"

			data['signal'] = (signal, level < -67)
		else:
			data['signal'] = ('Unknown', True)

		if wifi['quality'] is not None:
			data['quality'] = (wifi['quality'], False)
		else:
			data['quality'] = ('Unknown', True)

	def _parse_speed_wifi(self, data, wifi):
		# Link speed
		if wifi['bitrate'] is None:
			data['speed'] = ('Unknown', True)
		else:
			data['speed'] = (wifi['bitrate'], False)

	def _parse_speed_lan(self, data, if_stats):
		# Link speed
		speed = if_stats.speed
		if speed >= 1000:
			data['speed'] = (f"{speed / 1000:.1f} Gbps", False)
		elif speed > 0:
			data['speed'] = (f"{speed} Mbps", False)
		else:
			data['speed'] = ("Unknown", True)

	def _parse_duplex(self, data, if_stats):
		# Duplex mode
		duplex = if_stats.duplex
		if duplex == 0:
			data['duplex'] = ("Unknown", True)
		elif duplex == 1:
			data['duplex'] = ("Half Duplex", False)
		elif duplex == 2:
			data['duplex'] = ("Full Duplex", False)

	def _parse_mtu(self, data, if_stats):
		# MTU
		data['mtu'] = (if_stats.mtu, False)

	def _run_lldp(self, data, stop_event):
		if os.name == 'nt':
			# LLDP is not supported on Windows
			data['lldp'] = ('LLDP is not supported on Windows', True)
			return

		is_root = os.geteuid() == 0
		has_lldp = os.path.exists('/sbin/lldptool')
		lldp_enabled = False

		# Try to enable LLDP if available.
		if is_root and has_lldp:
			lldp_enabled = net_utils.enable_lldp(self.iface)

		if not is_root:
			data['lldp'] = ('LLDP requires root privileges', True)
			return

		if not has_lldp:
			data['lldp'] = ('Install lldpad to use LLDP', True)
			return

		if not lldp_enabled:
			data['lldp'] = ('LLDP could not be enabled!', True)
			return

		while True:
			if stop_event.is_set():
				return

			try:
				peer = net_utils.get_lldp_peer(self.iface)
				data['lldp'] = (
					f"{peer['system_name']} - {peer['port_name']} [{peer['chassis_id']}] ({peer['system_description']})",
					False
				)
			except BrokenPipeError:
				# Process stopped, just exit
				break

			if self.threaded:
				time.sleep(1)
			else:
				break

	def _run_address(self, data):
		# IP Address
		if_addresses = psutil.net_if_addrs()[self.iface]

		address = None
		for ip in if_addresses:
			if ip.family == socket.AF_INET:
				address = f'{ip.address}/{ipcalc.IP(ip.address, mask=ip.netmask).subnet()}'
				break
		if address is None:
			data['address'] = ('No IPv4 Address', True)
		else:
			data['address'] = (address, False)

	def _run_routes(self, data):
		# Routes
		routes = net_utils.get_routes(self.iface)
		if len(routes) == 0:
			data['routes'] = ('No routes found', True)
		else:
			r = []
			for route in routes:
				if route['destination'] == '0.0.0.0':
					r.append('Default: ' + route['gateway'])
				elif route['gateway'] == '0.0.0.0':
					r.append(f"Direct: {route['destination']}/{ipcalc.IP(route['destination'], mask=route['mask']).subnet()}")
				else:
					r.append(f"{route['destination']}/{ipcalc.IP(route['destination'], mask=route['mask']).subnet()} via {route['gateway']}")
			data['routes'] = (', '.join(r), False)

	def _run_nameservers(self, data):
		# Nameservers
		ns = net_utils.get_nameservers()
		if len(ns) == 0:
			data['nameservers'] = ('No nameservers found', True)
		else:
			data['nameservers'] = (', '.join(ns), False)

	def _run_domain(self, data):
		# Domain name
		d = net_utils.get_domain()
		if d:
			data['domain'] = (d, False)
		else:
			data['domain'] = ('Unknown', True)

	def _run_neighbors(self, data):
		# Number of visible neighbors (via ARP)
		neighbors = len(net_utils.get_neighbors(self.iface))
		if neighbors == 0:
			data['neighbors'] = ('No neighbors found', True)
		else:
			data['neighbors'] = (f"{neighbors} visible devices", False)

	def _run_wan(self, data, stop_event):
		# WAN IP Address
		while True:
			if stop_event.is_set():
				return

			try:
				data['wan'] = (requests.get(
					'https://wan.eval.bz',
					headers={'user-agent': f'network-diag/{_VERSION}'},
					timeout=3
				).text, False)
			except RequestException:
				data['wan'] = ('Lookup Failed', True)
			except BrokenPipeError:
				# Process stopped, just exit
				break

			if self.threaded:
				time.sleep(10)
			else:
				break

	def _run_connectivity(self, data, stop_event):
		# Check if the internet is _actually_ reachable or if it's being intercepted by a captive portal
		while True:
			if stop_event.is_set():
				return

			try:
				if requests.get(
					'https://up.eval.bz',
					headers={'user-agent': f'network-diag/{_VERSION}'},
					timeout=3
				).text == 'up':
					data['internet'] = ('Connected', False)
				else:
					data['internet'] = ('INTERCEPTED', True)
			except RequestException:
				data['internet'] = ('Lookup Failed', True)
			except BrokenPipeError:
				# Process stopped, just exit
				break

			if self.threaded:
				time.sleep(10)
			else:
				break

	def _run_latency(self, data, stop_event):
		# Check latency to a known good host
		while True:
			if stop_event.is_set():
				return

			try:
				res = ping('up.eval.bz', 1, timeout=2, return_latency=True)
				if res is False:
					data['latency'] = ('Ping Failed', True)
				elif res > 100:
					# Successful, but high latency.
					data['latency'] = (f"{res:.2f} ms", True)
				else:
					# Successful and low latency
					data['latency'] = (f"{res:.2f} ms", False)
			except BrokenPipeError:
				# Process stopped, just exit
				break

			if self.threaded:
				time.sleep(1)
			else:
				break

	def _run_dns(self, data, stop_event):
		# Perform a DNS lookup to check if DNS is working
		while True:
			if stop_event.is_set():
				return

			try:
				q = []
				try:
					q = resolver.resolve('up.eval.bz', 'A', lifetime=0.5)
				except DNSException:
					data['dns'] = ('DNS Lookup Failed', True)

				if len(q) >= 1:
					# If we got a response, DNS is working
					res = 'up.eval.bz -> ' + str(q[0].address)

					# Also check if an _INVALID_ DNS response is returned, (hint, it should NOT)
					try:
						q = resolver.resolve('invalid.eval.bz', 'A', lifetime=0.5)
						if len(q) >= 1:
							data['dns'] = ('Non-existent domain resolved to: ' + str(q[0].address), True)
						else:
							data['dns'] = ('Non-existent domain resolved to nothing', True)
					except resolver.NXDOMAIN:
						# This is the expected behaviour which indicates everything is working.
						data['dns'] = (res, False)
			except BrokenPipeError:
				# Process stopped, just exit
				break

			if self.threaded:
				time.sleep(5)
			else:
				break


class Application:
	def __init__(self, iface: str = None):
		self.iface = iface
		self.window = None
		self.curses_started = False
		self.is_windows = os.name == 'nt'

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
				if ifaces[iface].flags:
					print(f"{counter}: {iface} ({ifaces[iface].flags})")
				else:
					print(f"{counter}: {iface}")
				options[counter] = iface

			print('')
			try:
				choice = int(input('Enter the number of the interface you want to diagnose: '))
			except KeyboardInterrupt:
				print("\nExiting...")
				sys.exit(0)
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
		diagnostics.threaded = False
		diagnostics.run()
		data = {}
		for key in diagnostics.data:
			data[key] = diagnostics.data[key][0]
		print(json.dumps(data, indent=4, sort_keys=False))

	def run(self):
		counter = -1
		diagnostics = _Diagnostics(self.iface)
		if self.is_windows:
			# Windows doesn't play nicely with threading
			diagnostics.threaded = False
		self.window = curses.initscr()

		curses.noecho()
		curses.cbreak()
		self.window.keypad(True)
		self.curses_started = True

		labels = {
			'address': 'IP Address',
			'mtu': 'MTU',
			'domain': 'Domain Name',
			'wan': 'WAN IP',
			'internet': 'Internet Status',
			'dns': 'DNS Resolution',
			'lldp': 'LLDP Peer',
			'ssid': 'SSID',
		}

		counter_icons = ['|....', '.|...', '..|..', '...|.', '....|', '...|.', '..|..', '.|...']

		try:
			diagnostics.start()

			while True:
				self.window.clear()

				window_height, window_width = self.window.getmaxyx()
				bottom_line = window_height - 1
				unimportant_fields = [
					'type', 'status', 'duplex', 'mtu', 'domain', 'neighbors'
				]

				self.window.addstr(0, 0, "Network Diagnostics v" + _VERSION)

				counter += 1
				if counter > 7:
					counter = 0
				# Display a rotating icon to indicate the application is working in the bottom right
				self.window.addstr(bottom_line, window_width - 8, counter_icons[counter])

				line = 2
				for key, value in diagnostics.data.items():
					if window_height <= 20 and key in unimportant_fields:
						# For small windows, try to skip some unimportant fields
						continue

					if key in labels:
						self.window.addstr(line, 0, labels[key])
					else:
						self.window.addstr(line, 0, key.capitalize())

					if value[1]:
						self.window.addstr(line, 20, '❌')
					else:
						self.window.addstr(line, 20, '️✅')
					self.window.addstr(line, 24, str(value[0]))

					line += 1
					if line + 3 > window_height:
						# Too many items to render; skip the rest!
						break

				# Display some controls for the user
				self.window.timeout(1000)
				self.window.addstr(bottom_line, 0, "P to pause, Q or CTRL+C to exit")

				key = self.window.getch()
				if key == ord('q') or key == ord('Q') or key == 27:
					break
				elif key == ord('p') or key == ord('P'):
					self.pause()

				self.window.refresh()
		except KeyboardInterrupt:
			# Catch CTRL+C
			diagnostics.stop()
			pass
		except Exception:
			# Catch any other exceptions
			# Before doing anything, shutdown curses so errors can be printed to the terminal
			diagnostics.stop()
			self.shutdown_curses()
			traceback.print_exc(file=sys.stderr)
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

	def shutdown_curses(self):
		"""
		Shutdown the curses application and restore terminal settings.
		:return:
		"""
		if self.curses_started:
			curses.nocbreak()
			curses.echo()
			self.window.keypad(False)
			curses.endwin()
			self.curses_started = False

	def exit(self, exit_code: int = 0):
		"""
		Shutdown the application and restore terminal settings.

		:param exit_code:
		:return:
		"""
		self.shutdown_curses()
		sys.exit(exit_code)


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
