# Ensure cirros 0.3.3 is the image in tempest
# Ensure that allow overlapping tenants is set to false?
# tempest.conf is configured properly, and tenants are clean

import os
import sys

sys.path.append(os.getcwd())

from simpleconfigparser import simpleconfigparser
from tempest import clients
from tempest import config
from tempest.common import cred_provider

CONF = config.CONF
image_ref = None
tenant = None


def main():
    credentials = cred_provider.get_configured_credentials('identity_admin')
    manager = clients.Manager(credentials=credentials)
    check_image_ref(manager)
    fix_tempest_conf(manager)


def check_image_ref(manager):
    global image_ref
    images = manager.image_client.image_list()
    image_checksum = '133eae9fb1c98f45894a4e60d8736619'
    matched_image = next((img for img in images
                          if img['checksum'] == image_checksum),
                         None)
    if matched_image:
        image_ref = matched_image['id']
    else:
        upload_image_ref(manager)


def upload_image_ref(manager):
    # create and image with cirros 0.3.3
    global image_ref
    kwargs = {
        'copy_from': 'http://download.cirros-cloud.net/0.3.3/cirros-0.3.3-x86_64-disk.img',
        'visibility': 'public',
        'is_public': True,
    }
    try:
        resp = manager.image_client.create_image(name='cirros 0.3.3',
                                                 container_format='bare',
                                                 disk_format='raw',
                                                 **kwargs)
    except:
        raise Exception("Cirros image not created")

    image_ref = resp['id']


def fix_tempest_conf(manager):
    DEFAULT_CONFIG_DIR = os.path.join(
        os.path.abspath(os.path.dirname(os.path.dirname(__file__))),
        "etc")

    DEFAULT_CONFIG_FILE = "/tempest.conf"
    _path = DEFAULT_CONFIG_DIR + DEFAULT_CONFIG_FILE

    _mido_path = "midokura/utils/tempest.conf.midokura"

    if not os.path.isfile(_path):
        raise Exception("No config file in %s", _path)

    if not os.path.isfile(_mido_path):
        raise Exception("No config file in %s", _mido_path)

    try:
        config = simpleconfigparser()
        midoconfig = simpleconfigparser()
        config.read(_path)
        midoconfig.read(_mido_path)
    except Exception as e:
        print(str(e))

    # get config params from deployment and set into midoconfig
    # TODO: add identity: admin_username, username
    # TODO: no need for public_net_id, query it ourselves
    sections = {'identity': ['admin_password', 'password', 'uri', 'uri_v3'],
                'dashboard': ['login_url', 'dashboard_url'],
                'network': ['public_network_id']}

    for section, keys in sections.items():
        for key in keys:
            value = config.get(section, key)
            midoconfig.set(section, key, value)

    # get neutron suported extensions
    extensions_dict = manager.network_client.list_extensions()
    extensions_unfiltered = [x['alias'] for x in extensions_dict['extensions']]
    # setup network extensions
    extensions = [x for x in extensions_unfiltered
                  if x not in ['lbaas', 'fwaas']]
    to_string = ""
    for ex in extensions[:-1]:
        if ex != "lbaas" or ex != "fwaas":
            to_string = str.format("{0},{1}", ex, to_string)
    to_string = str.format("{0}{1}", to_string, extensions[-1])

    if CONF.network_feature_enabled.api_extensions != to_string:
        # modify tempest.conf file
        midoconfig.set('network-feature-enabled',
                       'api_extensions', to_string)

    # set up image_ref
    if image_ref:
        midoconfig.set('compute', 'image_ref', image_ref)
        midoconfig.set('compute', 'image_ref_alt', image_ref)
    # set up flavor_ref
    flavors = manager.flavors_client.list_flavors_with_detail()
    flavors.sort(key=lambda x: x['ram'])
    smallest_flavor = flavors[0]
    if smallest_flavor['ram'] > 64:
        print "WARNING: smallest flavor available is greater than 64 mb"
    midoconfig.set('compute', 'flavor_ref', smallest_flavor['id'])

    with open(_path, 'w') as tempest_conf:
        midoconfig.write(tempest_conf)

if __name__ == "__main__":
    main()
