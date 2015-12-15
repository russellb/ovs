# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import unittest

import ovs.json


class TestOVSJson(unittest.TestCase):
    _test_dict = {
        1: 1,
        2: {
            'a': ['a', 'b', 'c'],
            'b': True,
            'c': False,
            'd': None,
            'e': 3.14159,
            'f': '1',
            'g': u'u',
            'h': 'abc\\123',
        },
    }

    def test_from_string(self):
        # Make sure the parser doesn't blow up on a really simple json string
        ovs.json.from_string(json.dumps(self._test_dict))

    def test_to_string(self):
        # Make sure the serializer doesn't blow up on a really simple dict
        ovs.json.to_string(self._test_dict)
        ovs.json.to_string(self._test_dict, pretty=True)
        ovs.json.to_string(self._test_dict, sort_keys=False)

    def test_to_and_from_string(self):
        # Make sure it can parse what it spits out
        s = ovs.json.to_string(self._test_dict)
        ovs.json.from_string(s)

        s = ovs.json.to_string(self._test_dict, pretty=True)
        ovs.json.from_string(s)

    def test_serialize_python_class(self):
        try:
            ovs.json.to_string(object())
        except Exception:
            pass
        else:
            raise Exception('Serialization of object should fail')
