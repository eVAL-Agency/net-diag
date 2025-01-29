"""
SuiteCRM Sync Library

Provides a simple API to interface with SuiteCRM via the REST API.
Built against SuiteCRM 7.14.5, probably does not work with v8
(mostly because SuiteCRM v8 is unfinished and at the time of writing, kinda sucks)

Features:

* OAuth2 authentication (only support auth mechanism)
* Create records (POST to /Api/V8/module)
* Update records (PATCH to /Api/V8/module)
* Find records (GET to /Api/V8/module/[MODULE_NAME])

License:
	AGPLv3

Version:
	2025.01.28

Changelog:
	2025.01.28
		* Added debug logging
		* Create and update return server data
"""
import json
from typing import Union
import time
import logging
from urllib import request
from urllib.error import HTTPError
from urllib import parse as urlparse


class SuiteCRMSyncException(Exception):
	pass


class SuiteCRMSyncAuthException(SuiteCRMSyncException):
	pass


class SuiteCRMSyncDataException(SuiteCRMSyncException):
	pass


class SuiteCRMSyncResponseException(SuiteCRMSyncException):
	pass


class SuiteCRMSync:
	"""
	Simple API to interface with SuiteCRM
	"""

	def __init__(self, url: str, client_id: str, client_secret: str):
		self.token = None
		self.expires = 0
		self.url = url
		self.client_id = client_id
		self.client_secret = client_secret

	def _send(
		self,
		url: str,
		method: str,
		data: Union[dict, None] = None,
		auth: bool = True,
		sensitive: tuple = ()
	):
		headers = {
			'Content-Type': 'application/json',
			'Accept': 'application/json',
		}
		if auth:
			headers['Authorization'] = 'Bearer %s' % self.get_token()

		log_url = self.url + url
		url = 'https://' + self.url + url
		log_data = dict(data) if data is not None else None

		if method.upper() == 'GET':
			post_data = None
			if data is not None:
				url += ('&' if '?' in url else '?') + urlparse.urlencode(data)
		else:
			post_data = data

		if post_data is not None:
			for key in sensitive:
				if key in log_data:
					log_data[key] = log_data[key][0:4] + '********'
			logging.debug('[suitecrmsync] Sending payload via %s to %s\n%s' % (method, log_url, json.dumps(log_data)))
			req = request.Request(
				url,
				method=method,
				headers=headers,
				data=json.dumps(post_data).encode('utf-8')
			)
		else:
			logging.debug('[suitecrmsync] Sending request via %s to %s' % (method, log_url))
			req = request.Request(
				url,
				method=method,
				headers=headers
			)

		response = ''
		try:
			ret = request.urlopen(req)
			response = ret.read()
			response_data = json.loads(response)
			logging.debug('[suitecrmsync] Request completed successfully\n%s' % response)
			return response_data
		except HTTPError as e:
			response = e.read()
			logging.error('[suitecrmsync] Request failed\n%s' % response)
			raise SuiteCRMSyncException()
		except json.decoder.JSONDecodeError:
			logging.error('[suitecrmsync] Failed to parse response\n%s' % response)
			raise SuiteCRMSyncException()

	def get_token(self) -> str:
		"""
		Get an access token from SuiteCRM based on OAuth2 client_id and client_secret

		Called automatically when required
		:return:
		"""
		if self.expires < int(time.time()):
			logging.debug('[suitecrmsync] Token expired or not set yet, obtaining new token')
			# Request an access token via OAuth2 from SuitCRM
			try:
				data = self._send(
					'/Api/access_token',
					'POST',
					{
						'grant_type': 'client_credentials',
						'client_id': self.client_id,
						'client_secret': self.client_secret,
					},
					False,
					('client_secret',)
				)
				self.token = data['access_token']
				self.expires = int(time.time()) + data['expires_in'] - 60
			except SuiteCRMSyncException:
				raise SuiteCRMSyncResponseException(
					'Failed to get access token, please check the credentials and server connectivity'
				)
		return self.token

	def update(self, object_type: str, object_id: str, data: dict):
		"""
		Patch/update a record in SuiteCRM

		:param object_type:
		:param object_id:
		:param data:
		:return
		"""

		# Send the UPDATE request to SuiteCRM
		try:
			return self._send(
				'/Api/V8/module',
				'PATCH',
				{
					'data': {
						'type': object_type,
						'id': object_id,
						'attributes': data,
					}
				}
			)
		except SuiteCRMSyncException:
			raise SuiteCRMSyncDataException('Failed to update %s %s\n%s' % (object_type, object_id, json.dumps(data)))

	def create(self, object_type: str, data: dict):
		"""
		create a record in SuiteCRM
		:param object_type:
		:param data:
		:return
		"""

		# Send the device data to SuiteCRM
		try:
			return self._send(
				'/Api/V8/module',
				'POST',
				{
					'data': {
						'type': object_type,
						'attributes': data,
					}
				}
			)
		except SuiteCRMSyncException:
			raise SuiteCRMSyncDataException('Failed to create %s\n%s' % (object_type, json.dumps(data)))

	def find(self, object_type: str, filters: dict, operator: str = 'AND', fields: [str] = ('id',)):
		"""

		:param object_type:
		:param filters:
		:param operator:
		:param fields:
		:return:
		"""
		params = {
			'fields[' + object_type + ']': ','.join(fields),
			'filter[operator]': operator,
		}
		op_map = {
			'=': 'EQ',
			'==': 'EQ',
			'!=': 'NEQ',
			'<>': 'NEQ',
			'>': 'GT',
			'>=': 'GTE',
			'<': 'LT',
			'<=': 'LTE',
		}
		for f_key in filters.keys():
			f_val = filters[f_key]
			if isinstance(f_val, list) or isinstance(f_val, tuple):
				f_op = f_val[0]
				f_val = f_val[1]
			else:
				f_op = 'EQ'

			if f_op.upper() in ('EQ', 'NEQ', 'GT', 'GTE', 'LT', 'LTE'):
				# Supported value; no modification required
				pass
			elif f_op in op_map:
				f_op = op_map[f_op]
			else:
				raise SuiteCRMSyncDataException(
					('Invalid filter format: %s %s %s' % (f_key, f_op, f_val))
				)

			params['filter[' + f_key + '][' + f_op + ']'] = f_val

		try:
			data = self._send(
				'/Api/V8/module/%s' % object_type,
				'GET',
				params
			)
			ret = []
			for record in data['data']:
				if len(record['attributes']) == 0:
					ret.append({'id': record['id']})
				else:
					ret.append(record['attributes'] | {'id': record['id']})
			return ret
		except SuiteCRMSyncException:
			raise SuiteCRMSyncDataException('Failed to find %s\n%s' % (object_type, json.dumps(params)))
