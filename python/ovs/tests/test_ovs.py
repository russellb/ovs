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

import unittest

# Import everything from the ovs lib to ensure all modules show up in the
# coverage report.  It also ensures that if we don't have test coverage yet,
# they can at least be successfully imported.
import ovs.jsonrpc  # noqa
import ovs.tests.test_ovs  # noqa
import ovs.version  # noqa
import ovs.timeval  # noqa
import ovs.daemon  # noqa
import ovs.reconnect  # noqa
import ovs.vlog  # noqa
import ovs.json  # noqa
import ovs.stream  # noqa
import ovs.fatal_signal  # noqa
import ovs.ovsuuid  # noqa
import ovs.dirs  # noqa
import ovs.util  # noqa
import ovs.socket_util  # noqa
import ovs.process  # noqa
import ovs.poller  # noqa
import ovs.unixctl.client  # noqa
import ovs.unixctl.server  # noqa
import ovs.db.data  # noqa
import ovs.db.idl  # noqa
import ovs.db.parser  # noqa
import ovs.db.types  # noqa
import ovs.db.schema  # noqa
import ovs.db.error  # noqa


class TestOVS(unittest.TestCase):
    def test_pass(self):
        pass
