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
"""
import json
import time
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

	def get_token(self) -> str:
		"""
		Get an access token from SuiteCRM based on OAuth2 client_id and client_secret

		Called automatically when required
		:return:
		"""
		if self.expires < int(time.time()):
			# Request an access token via OAuth2 from SuitCRM
			req = request.Request(
				'https://%s/Api/access_token' % self.url,
				method='POST',
				headers={
					'Content-Type': 'application/json',
					'Accept': 'application/json',
				},
				data=json.dumps({
					'grant_type': 'client_credentials',
					'client_id': self.client_id,
					'client_secret': self.client_secret,
				}).encode('utf-8')
			)
			try:
				ret = request.urlopen(req)
			except HTTPError as e:
				raise SuiteCRMSyncAuthException(
					'Failed to get access token, please check the credentials and server connectivity\n' + e.read()
				)

			try:
				data = json.loads(ret.read())
				self.token = data['access_token']
				self.expires = int(time.time()) + data['expires_in'] - 60
			except json.decoder.JSONDecodeError:
				raise SuiteCRMSyncResponseException('Failed to parse access token response\n' + ret.read())
		return self.token

	def update(self, object_type: str, object_id: str, data: dict):
		"""
		Patch/update a record in SuiteCRM

		:param object_type:
		:param object_id:
		:param data:
		:return
		"""

		# Send the device data to SuiteCRM
		req = request.Request(
			'https://%s/Api/V8/module' % self.url,
			method='PATCH',
			headers={
				'Content-Type': 'application/json',
				'Accept': 'application/json',
				'Authorization': 'Bearer %s' % self.get_token(),
			},
			data=json.dumps({
				'data': {
					'type': object_type,
					'id': object_id,
					'attributes': data,
				}
			}).encode('utf-8')
		)

		try:
			request.urlopen(req)
		except HTTPError as e:
			raise SuiteCRMSyncDataException(
				('Failed to update %s %s\n%s' % (object_type, object_id, e.read()))
			)

	def create(self, object_type: str, data: dict):
		"""
		create a record in SuiteCRM
		:param object_type:
		:param data:
		:return
		"""

		# Send the device data to SuiteCRM
		req = request.Request(
			'https://%s/Api/V8/module' % self.url,
			method='POST',
			headers={
				'Content-Type': 'application/json',
				'Accept': 'application/json',
				'Authorization': 'Bearer %s' % self.get_token(),
			},
			data=json.dumps({
				'data': {
					'type': object_type,
					'attributes': data,
				}
			}).encode('utf-8')
		)

		try:
			request.urlopen(req)
		except HTTPError as e:
			raise SuiteCRMSyncDataException(
				('Failed to create %s\n%s' % (object_type, e.read()))
			)

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

		url = 'https://%s/Api/V8/module/%s?%s' % (self.url, object_type, urlparse.urlencode(params))
		req = request.Request(
			url,
			method='GET',
			headers={
				'Content-Type': 'application/json',
				'Accept': 'application/json',
				'Authorization': 'Bearer %s' % self.get_token(),
			}
		)

		try:
			ret = request.urlopen(req)
		except HTTPError as e:
			raise SuiteCRMSyncDataException(
				('Failed to complete find for %s\n%s' % (url, e.read()))
			)

		try:
			data = json.loads(ret.read())
		except json.decoder.JSONDecodeError:
			raise SuiteCRMSyncResponseException('Failed to parse find response\n%s' % ret.read())

		ret = []
		for record in data['data']:
			record['attributes']['id'] = record['id']
			ret.append(record['attributes'])
		return ret
