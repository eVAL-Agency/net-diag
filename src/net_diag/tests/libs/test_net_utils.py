from unittest import TestCase
from net_diag.libs.net_utils import format_link_speed


class TestNetUtils(TestCase):
	def test_format_link_speed(self):
		self.assertEqual('0bps', format_link_speed(0))
		self.assertEqual('100bps', format_link_speed(100))
		self.assertEqual('1kbps', format_link_speed(1000))
		self.assertEqual('1mbps', format_link_speed(1000000))
		self.assertEqual('10mbps', format_link_speed(10000000))
		self.assertEqual('1gbps', format_link_speed(1000000000))
		self.assertEqual('1tbps', format_link_speed(1000000000000))
		self.assertEqual('1.5kbps', format_link_speed(1500))
