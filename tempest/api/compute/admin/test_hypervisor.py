# Copyright 2013 IBM Corporation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from tempest.api.compute import base
from tempest import test


class HypervisorAdminTestJSON(base.BaseV2ComputeAdminTest):

    """
    Tests Hypervisors API that require admin privileges
    """

    @classmethod
    def resource_setup(cls):
        super(HypervisorAdminTestJSON, cls).resource_setup()
        cls.client = cls.os_adm.hypervisor_client

    def _list_hypervisors(self):
        # List of hypervisors
        resp, hypers = self.client.get_hypervisor_list()
        self.assertEqual(200, resp.status)
        return hypers

    def assertHypervisors(self, hypers):
        self.assertTrue(len(hypers) > 0, "No hypervisors found: %s" % hypers)

    @test.attr(type='gate')
    def test_get_hypervisor_list(self):
        # List of hypervisor and available hypervisors hostname
        hypers = self._list_hypervisors()
        self.assertHypervisors(hypers)

    @test.attr(type='gate')
    def test_get_hypervisor_list_details(self):
        # Display the details of the all hypervisor
        resp, hypers = self.client.get_hypervisor_list_details()
        self.assertEqual(200, resp.status)
        self.assertHypervisors(hypers)

    @test.attr(type='gate')
    def test_get_hypervisor_show_details(self):
        # Display the details of the specified hypervisor
        hypers = self._list_hypervisors()
        self.assertHypervisors(hypers)

        resp, details = (self.client.
                         get_hypervisor_show_details(hypers[0]['id']))
        self.assertEqual(200, resp.status)
        self.assertTrue(len(details) > 0)
        self.assertEqual(details['hypervisor_hostname'],
                         hypers[0]['hypervisor_hostname'])

    @test.attr(type='gate')
    def test_get_hypervisor_show_servers(self):
        # Show instances about the specific hypervisors
        hypers = self._list_hypervisors()
        self.assertHypervisors(hypers)

        hostname = hypers[0]['hypervisor_hostname']
        resp, hypervisors = self.client.get_hypervisor_servers(hostname)
        self.assertEqual(200, resp.status)
        self.assertTrue(len(hypervisors) > 0)

    @test.attr(type='gate')
    def test_get_hypervisor_stats(self):
        # Verify the stats of the all hypervisor
        resp, stats = self.client.get_hypervisor_stats()
        self.assertEqual(200, resp.status)
        self.assertTrue(len(stats) > 0)

    @test.attr(type='gate')
    def test_get_hypervisor_uptime(self):
        # Verify that GET shows the specified hypervisor uptime
        hypers = self._list_hypervisors()

        # Ironic will register each baremetal node as a 'hypervisor',
        # so the hypervisor list can contain many hypervisors of type
        # 'ironic'. If they are ALL ironic, skip this test since ironic
        # doesn't support hypervisor uptime. Otherwise, remove them
        # from the list of hypervisors to test.
        ironic_only = True
        hypers_without_ironic = []
        for hyper in hypers:
            resp, details = (self.client.
                             get_hypervisor_show_details(hypers[0]['id']))
            self.assertEqual(200, resp.status)
            if details['hypervisor_type'] != 'ironic':
                hypers_without_ironic.append(hyper)
                ironic_only = False

        if ironic_only:
            raise self.skipException(
                "Ironic does not support hypervisor uptime")

        has_valid_uptime = False
        for hyper in hypers_without_ironic:
            # because hypervisors might be disabled, this loops looking
            # for any good hit.
            try:
                resp, uptime = self.client.get_hypervisor_uptime(hyper['id'])
                if (resp.status == 200) and (len(uptime) > 0):
                    has_valid_uptime = True
                    break
            except Exception:
                pass
        self.assertTrue(
            has_valid_uptime,
            "None of the hypervisors had a valid uptime: %s" % hypers)

    @test.attr(type='gate')
    def test_search_hypervisor(self):
        hypers = self._list_hypervisors()
        self.assertHypervisors(hypers)
        resp, hypers = self.client.search_hypervisor(
            hypers[0]['hypervisor_hostname'])
        self.assertEqual(200, resp.status)
        self.assertHypervisors(hypers)


class HypervisorAdminTestXML(HypervisorAdminTestJSON):
    _interface = 'xml'
