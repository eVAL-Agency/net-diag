import base64
import json
from typing import Union
from urllib import request
from urllib.parse import urlencode
import logging


class OpenProjectSyncException(Exception):
	pass


class OpenProjectSync:
	types = None
	custom_fields = None
	statuses = None

	def __init__(self, api_url, api_key):
		self.api_url = api_url
		self.api_key = api_key
		self.workspace = ''
		self.type_name = 'Device'
		self.dry_run = False

	@classmethod
	def _send_get(cls, url, path, api_key):
		headers = {
			'Content-Type': 'application/json',
			'Accept': 'application/json',
		}
		# Create Basic auth header: base64-encode the bytes of "apikey:<key>", then decode to str
		token = base64.b64encode(f"apikey:{api_key}".encode('utf-8')).decode('ascii')
		headers['Authorization'] = f'Basic {token}'
		req = request.Request(
			'https://%s/%s' % (url, path),
			method='GET',
			headers=headers
		)
		dat = request.urlopen(req).read().decode('utf-8')
		return json.loads(dat)

	@classmethod
	def _send_post(cls, url, path, api_key, data):
		headers = {
			'Content-Type': 'application/json',
			'Accept': 'application/json',
		}
		# Create Basic auth header: base64-encode the bytes of "apikey:<key>", then decode to str
		token = base64.b64encode(f"apikey:{api_key}".encode('utf-8')).decode('ascii')
		headers['Authorization'] = f'Basic {token}'
		req = request.Request(
			'https://%s/%s' % (url, path),
			method='POST',
			headers=headers,
			data=json.dumps(data).encode('utf-8')
		)
		dat = request.urlopen(req).read().decode('utf-8')
		return json.loads(dat)

	@classmethod
	def _send_patch(cls, url, path, api_key, data):
		headers = {
			'Content-Type': 'application/json',
			'Accept': 'application/json',
		}
		# Create Basic auth header: base64-encode the bytes of "apikey:<key>", then decode to str
		token = base64.b64encode(f"apikey:{api_key}".encode('utf-8')).decode('ascii')
		headers['Authorization'] = f'Basic {token}'
		req = request.Request(
			'https://%s/%s' % (url, path),
			method='PATCH',
			headers=headers,
			data=json.dumps(data).encode('utf-8')
		)
		dat = request.urlopen(req).read().decode('utf-8')
		return json.loads(dat)

	def resolve_type(self) -> Union[int, None]:
		"""
		Resolve a type name to its ID, or None if it does not exist.

		:param type_name:
		:return:
		"""
		if self.types is None:
			t = self._send_get(
				self.api_url,
				'/api/v3/workspaces/%s/types' % self.workspace,
				self.api_key
			)
			self.types = {}
			for element in t['_embedded']['elements']:
				self.types[element['name']] = element['id']

		if self.type_name in self.types:
			return self.types[self.type_name]
		return None

	def resolve_project_id(self) -> Union[int, None]:
		"""
		Resolve the workspace name to its project ID, or None if it does not exist.

		:return:
		"""
		r = self._send_get(
			self.api_url,
			'/api/v3/workspaces/%s' % self.workspace,
			self.api_key
		)
		return r['id']

	def resolve_custom_field(self, custom_field) -> Union[str, None]:
		"""
		Resolve a custom field name to its identifier, or None if it does not exist.

		The returned name will be in the format of "customFieldN", where N is the ID of the custom field.
		This is required for referencing custom fields in work package creation and queries.

		:return:
		"""
		if self.custom_fields is None:
			project_id = self.resolve_project_id()
			type_id = self.resolve_type()
			self.custom_fields = {}
			res = self._send_get(self.api_url, '/api/v3/work_packages/schemas/%s-%s' % (str(project_id), str(type_id)), self.api_key)
			for key in res:
				if key.startswith('customField'):
					title = res[key]['name']
					self.custom_fields[title] = key

		if custom_field in self.custom_fields:
			return self.custom_fields[custom_field]
		return None

	def resolve_status(self, status_name) -> Union[str, None]:
		"""
		Resolve a status name to its URL fragment or None if it does not exist.

		This fragment will be in the format of "/api/v3/statuses/N", where N is the ID of the status.
		This is required for referencing statuses in work package creation and queries.

		:param status_name:
		:return:
		"""

		if self.statuses is None:
			self.statuses = {}
			res = self._send_get(self.api_url, '/api/v3/statuses', self.api_key)
			for element in res['_embedded']['elements']:
				self.statuses[element['name']] = element['_links']['self']['href']

		if status_name in self.statuses:
			return self.statuses[status_name]
		return None

	def find_device_by_mac(self, host):
		mac = host.mac
		type_id = self.resolve_type()
		if type_id is None:
			raise OpenProjectSyncException(f"Work package type '{self.type_name}' not found within OpenProject!")

		try:
			mac_field = self.resolve_custom_field('MAC Address')
		except Exception:
			raise OpenProjectSyncException(
				f"Unable to retrieve custom field ID for 'MAC Address' from OpenProject workspace '{self.workspace}'"
			)

		if mac_field is None:
			raise OpenProjectSyncException(
				f"Custom field 'MAC Address' not found within OpenProject workspace '{self.workspace}'"
			)

		filters = [
			{'type_id': {'operator': '=', 'values': [type_id]}},
			{mac_field: {'operator': '=', 'values': [mac]}}
		]

		# URL-encode the JSON filters so they are safe in a query string
		query = urlencode({
			'filters': json.dumps(filters),
			'pageSize': 1,
		})

		ret = self._send_get(self.api_url, '/api/v3/workspaces/%s/work_packages?%s' % (self.workspace, query), self.api_key)
		if len(ret['_embedded']['elements']) == 0:
			return None
		else:
			return ret['_embedded']['elements'][0]

	def _populate_host_data(self, existing_data, host):
		def empty_or_null(key):
			if existing_data is None:
				return True
			val = existing_data.get(key, '')
			return val is None or val == ''

		mac_field = self.resolve_custom_field('MAC Address')
		type_id = self.resolve_type()
		project_id = self.resolve_project_id()

		if mac_field is None:
			raise OpenProjectSyncException(
				f"Custom field 'MAC Address' not found within OpenProject workspace '{self.workspace}'"
			)

		if host.mac is None or host.mac == '':
			raise OpenProjectSyncException(
				f"Host {host.hostname} is missing a MAC address, cannot create or update in OpenProject workspace '{self.workspace}'"
			)

		if existing_data is None:
			# New host, baseline fields required
			data = {
				'_type': 'WorkPackage',
				'_links': {
					'schema': {'href': '/api/v3/work_packages/schemas/%s-%s' % (str(project_id), str(type_id))},
					'type': {'href': '/api/v3/types/%s' % str(type_id)},
					'project': {'href': '/api/v3/projects/%s' % str(project_id)},
				},
				'subject': host.hostname,
				mac_field: host.mac,
			}
			data_set = True
		else:
			data = {
				# LockVersion is required to prevent update conflicts, ie: multiple users changing a given resource at the same time.
				'lockVersion': existing_data['lockVersion'],
			}
			data_set = False

		# IP tends to be flexible, so keep this in sync.
		ip_field = self.resolve_custom_field('IP Address')
		if ip_field is not None and host.ip:
			if existing_data is None or host.ip != existing_data.get(ip_field, ''):
				data[ip_field] = host.ip
				data_set = True

		# All other fields should only update the database if they're not otherwise set.
		# This allows the operators to change incorrect data when necessary.
		manufacturer_field = self.resolve_custom_field('Manufacturer')
		if manufacturer_field is not None and host.manufacturer and empty_or_null(manufacturer_field):
			data[manufacturer_field] = host.manufacturer
			data_set = True

		model_field = self.resolve_custom_field('Model')
		if model_field is not None and host.model and empty_or_null(model_field):
			data[model_field] = host.model
			data_set = True

		type_field = self.resolve_custom_field('Device Type')
		if type_field is not None and host.type and empty_or_null(type_field):
			data[type_field] = host.type
			data_set = True

		serial_field = self.resolve_custom_field('Serial Number')
		if serial_field is not None and host.serial and empty_or_null(serial_field):
			data[serial_field] = host.serial
			data_set = True

		floor_field = self.resolve_custom_field('Floor')
		if floor_field is not None and host.floor and empty_or_null(floor_field):
			data[floor_field] = host.floor
			data_set = True

		room_field = self.resolve_custom_field('Room')
		if room_field is not None and host.location and empty_or_null(room_field):
			data[room_field] = host.location
			data_set = True

		status_value = self.resolve_status('Active')
		if status_value is not None:
			if '_links' not in data:
				data['_links'] = {}
			data['_links']['status'] = {'href': status_value}

		uplink_field = self.resolve_custom_field('Uplink Port')
		if uplink_field is not None and host.uplink_port and empty_or_null(uplink_field):
			data[uplink_field] = host.uplink_port
			data_set = True

		if host.uplink_device and host.uplink_device in host.ip_to_synced_ids:
			if '_links' not in data:
				data['_links'] = {}
			if 'parent' not in data['_links'] or data['_links']['parent']['href'] is None:
				data['_links']['parent'] = {'href': '/api/v3/work_packages/' + str(host.ip_to_synced_ids[host.uplink_device])}
				data_set = True

		if data_set:
			return data
		else:
			return None

	def create_host(self, host):
		type_id = self.resolve_type()
		project_id = self.resolve_project_id()
		if type_id is None:
			raise OpenProjectSyncException(f"Work package type '{self.type_name}' not found within OpenProject!")

		data = self._populate_host_data(None, host)

		if self.dry_run:
			logging.info(
				' '.join([
					f'[openprojectsync] Dry run enabled, skipping creation of host {host.hostname}',
					f'(MAC: {host.mac}) in OpenProject with new data:'
					f'\n{json.dumps(data)}'
				])
			)
			return

		ret = self._send_post(self.api_url, '/api/v3/workspaces/%s/work_packages' % str(project_id), self.api_key, data)

		# Save the new ID to the host for future reference.
		host.synced_id = ret['id']

	def update_host(self, existing_data, host):
		"""
		Update the host entry in OpenProject with the data from the given host object.

		:param existing_data:
		:param host:
		:return:
		"""

		if '_links' not in existing_data:
			raise OpenProjectSyncException("Existing work package data is missing '_links' section, cannot update!")

		if 'updateImmediately' not in existing_data['_links']:
			raise OpenProjectSyncException("Existing work package data is missing 'updateImmediately' link, cannot update!")

		target_url = existing_data['_links']['updateImmediately']['href']
		data = self._populate_host_data(existing_data, host)

		# Save the existing ID to the host for future reference.
		host.synced_id = existing_data['id']

		if data is not None:
			if self.dry_run:
				logging.info(
					' '.join([
						f'[openprojectsync] Dry run enabled, skipping update of host {host.hostname}',
						f'(MAC: {host.mac}) in OpenProject with new data:'
						f'\n{json.dumps(data)}'
					])
				)
				return
			logging.debug(f"Updating host {host.hostname} (MAC: {host.mac}) in OpenProject with new data: {data}")
			self._send_patch(self.api_url, target_url, self.api_key, data)
		else:
			logging.debug(
				f"No update needed for host {host.hostname} (MAC: {host.mac}), all relevant fields are already set in OpenProject"
			)
