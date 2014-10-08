# Copyright 2014 Midokura SARL.
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

import collections
import yaml
import os

from tempest import exceptions
from neutronclient.common import exceptions as NeutronClientException
from tempest.common.utils import data_utils
from tempest.common.utils.linux import remote_client
from tempest import config
from tempest.openstack.common import log
from tempest.scenario import manager
from tempest.services.network import resources as net_resources


CONF = config.CONF
LOG = log.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class AdvancedNetworkScenarioTest(manager.NetworkScenarioTest):
    """
    Base class for all Midokura network scenario tests
    """

    @classmethod
    def setUpClass(cls):
        cls.set_network_resources()
        super(AdvancedNetworkScenarioTest, cls).setUpClass()

    """
    Creation Methods
    """
    def _create_security_group_rule_list(self, rule_dict=None, secgroup=None):
        client = self.network_client
        rules = []
        if not rule_dict:
            rulesets = []
        else:
            rulesets = rule_dict['security_group_rules']
        for ruleset in rulesets:
            for r_direction in ['ingress', 'egress']:
                ruleset['direction'] = r_direction
                try:
                    sg_rule = self._create_security_group_rule(
                        client=client, secgroup=secgroup, **ruleset)
                except NeutronClientException as ex:
                    if not (ex.status_code is 409 and 'Security group rule'
                            ' already exists' in ex.message):
                        raise ex
                else:
                    self.assertEqual(r_direction, sg_rule.direction)
                    rules.append(sg_rule)
        return rules

    def _create_server(self, name, networks, tenant,
                       security_groups=None):

        keypair = self.create_keypair()
        if security_groups is None:
            raise Exception("No security group")

        nics = list()
        for net in networks:
            nic = {'uuid': net['id']}
            nics.append(nic)

        create_kwargs = {
            'networks': nics,
            'key_name': keypair['name'],
            'security_groups': security_groups,
        }
        server = self.create_server(name=name,
                                    create_kwargs=create_kwargs)

        return dict(server=server, keypair=keypair)

    """
    GateWay methods
    """
    def _set_access_point(self, tenant):
        """
        creates a server in a secgroup with rule allowing external ssh
        in order to access tenant internal network
        workaround ip namespace
        """
        network, _, _ = \
            self.create_networks(tenant_id=tenant)
        name = 'access_point'
        name = data_utils.rand_name(name)

        networks = self._get_tenant_networks(tenant)
        if networks[0]['name'] != network['name']:
            for i in xrange(len(networks)):
                if networks[i]['name'] == \
                        network['name'] and i != 0:
                            net = networks[i]
                            networks[i] = networks[0]
                            networks[0] = net
        self._create_security_group(tenant_id=tenant,
                namestart='gateway')
        security_groups = self._get_tenant_security_groups(tenant)
        serv_dict = self._create_server(name=name,
                                        networks=networks,
                                        security_groups=security_groups,
                                        tenant=tenant)
        access_point_FIP = \
            self._assign_access_point_floating_ip(
                serv_dict['server'],
                network_name=network.name)

        self._fix_access_point((access_point_FIP,
                                serv_dict['server']),
                                serv_dict['keypair'])

        return dict(server=serv_dict['server'],
                    keypair=serv_dict['keypair'],
                    FIP=access_point_FIP.floating_ip_address)

    def _assign_access_point_floating_ip(self, server, network_name):
        public_network_id = CONF.network.public_network_id
        server_ip = server['addresses'][network_name][0]['addr']
        port_id = self._get_custom_server_port_id(server,
                                                  ip_addr=server_ip)
        floating_ip = self._create_floating_ip(server,
                                               public_network_id,
                                               port_id=port_id)
        return floating_ip

    def _fix_access_point(self, access_point, keypair):
        """
        Hotfix for cirros images
        """
        access_point_ip, server = access_point
        private_key = keypair['private_key']
        ip = access_point_ip.floating_ip_address
        self.servers_client.wait_for_server_status(server_id=server['id'],
                                                   status='ACTIVE')
        access_point_ssh = remote_client.RemoteClient(
                server=ip,
                username='cirros',
                password='cubswin:)',
                pkey=private_key,
                )
        # fix for cirros image in order to enable a second eth
        for net in xrange(1, len(server['addresses'].keys())):
            if access_point_ssh.exec_command(
                    "cat /sys/class/net/eth{0}/operstate".format(net)) \
                    is not 'up\n':
                try:
                    result = access_point_ssh.exec_command("sudo /sbin/udhcpc -i eth{0}".format(net),10)
                    LOG.info(result)
                except exceptions.TimeoutException:
                    pass

    def build_gateway(self, tenant_id):
        return self._set_access_point(tenant_id)

    def setup_tunnel(self, tunnel_hops):
        """
        The details of the access point
        should be included in the tunnel_hops
        every element in the tunnel host is a
        tuple: (IP,PrivateKey)
        """
        GWS = []
        # last element is the final destination, which
        # is be passed tp the remote_client separately
        for host in tunnel_hops[:-1]:
            gw_host = {
                "username": "cirros",
                "ip": host[0],
                "password": "cubswin:)",
                "pkey": host[1],
                "key_filename": None
            }
            GWS.append(gw_host)

        ssh_client = remote_client.RemoteClient(
            server=tunnel_hops[-1][0],
            username='cirros',
            password='cubswin:)',
            pkey=tunnel_hops[-1][1],
            gws=GWS
        )
        return ssh_client

    """
    Get Methods
    """
    def _get_tenant_security_groups(self, tenant=None):
        client = self.network_client
        _, sgs = client.list_security_groups()
        return sgs['security_groups']

    def _get_tenant_networks(self, tenant=None):
        client = self.network_client
        _, nets = client.list_networks(tenant_id=tenant)
        return nets['networks']

    def _get_custom_server_port_id(self, server, ip_addr=None):
        ports = self._list_ports(device_id=server['id'])
        if ip_addr:
            for port in ports:
                if port['fixed_ips'][0]['ip_address'] == ip_addr:
                    return port['id']
        self.assertEqual(len(ports), 1,
                         "Unable to determine which port to target.")
        return ports[0]['id']

    def _get_network_by_name(self, net_name):
        nets = self._get_tenant_networks()
        return filter(lambda x: x['name'].startswith(net_name), nets)

    def _get_security_group_by_name(self, sg_name):
        sgs = self._get_tenant_security_groups()
        return filter(lambda x: x['name'].startswith(sg_name), sgs)

    """
    YAML parsing methods
    """
    def setup_topology(self, yaml_topology):
        with open(os.path.abspath(yaml_topology), 'r') as yaml_topology:
            topology = yaml.load(yaml_topology)
            networks = [n for n in topology['networks']]
            routers = []
            for network in networks:
                net = self._create_network(tenant_id=self.tenant_id,
                                           namestart=network['name'])
                for subnet in network['subnets']:
                    for router in subnet['routers']:
                        router_names = [r['name'] for r in
                                        self.network_client.list_routers()['routers']]
                        if not router['name'] in router_names:
                            router = self._create_router(namestart=router['name'],
                                                         tenant_id=self.tenant_id)
                            routers.append(router)
                    subnet_dic = \
                        dict(
                            name=subnet['name'],
                            ip_version=4,
                            network_id=net.id,
                            tenant_id=self.tenant_id,
                            cidr=subnet['cidr'],
                            dns_nameservers=subnet['dns_nameservers'],
                            host_routes=subnet['host_routes'],
                        )
                    subnet = self._create_subnet(network=net, **subnet_dic)
                    for router in routers:
                        subnet.add_to_router(router.id)

            for secgroup in topology['security_groups']:
                sgroups = self._get_tenant_security_groups(self.tenant_id)
                if secgroup['name'] in [r['name'] for r in sgroups]:
                    sg = filter(lambda x: x['name'] == secgroup['name'], sgroups)[0]
                else:
                    sg = self._create_empty_security_group(tenant_id=self.tenant_id,
                            namestart=secgroup['name'])
                    rules = \
                        self._create_security_group_rule_list(rule_dict=secgroup,
                                                              secgroup=sg)
            test_server = []
            for server in topology['servers']:
                s_nets = []
                for snet in server['networks']:
                    s_nets.extend(self._get_network_by_name(snet['name']))
                s_sg = []
                for sg in server['security_groups']:
                    s_sg.extend(self._get_security_group_by_name(sg['name']))
                for x in range(server['quantity']):
                    name = data_utils.rand_name('server-smoke-')
                    test_server.append(self._create_server(name=name,
                                                           networks=s_nets,
                                                           security_groups=s_sg,
                                                           tenant=self.tenant_id))
            if 'gateway' in topology.keys():
                test_server.append(self.build_gateway(self.tenant_id))

            return test_server
