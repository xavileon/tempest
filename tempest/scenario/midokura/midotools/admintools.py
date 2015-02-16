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

from tempest import clients


class TenantAdmin(object):
    __shared_state = {}
    _interface = 'json'

    def __init__(self):
        self.__dict__ = self.__shared_state
        if 'client' not in self.__dict__:
            self.client = clients.AdminManager(
                interface=self._interface).identity_client
        if 'tenants' not in self.__dict__:
            self.tenants = []

    def get_user_by_name(self, name):
        users = self.client.get_users()
        user = [u for u in users if u['name'] == name]
        if len(user) > 0:
            return user[0]

    def get_role_by_name(self, name):
        roles = self.client.list_roles()
        role = [r for r in roles if r['name'] == name]
        if len(role) > 0:
            return role[0]

    def assign_user_role(self, tenant_id, user_id, role_id):
        self.client.assign_user_role(tenant_id,
                                     user_id,
                                     role_id)
