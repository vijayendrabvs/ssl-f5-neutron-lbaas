#!/usr/bin/env python
"""
iControl ssl client library.
"""

__version__ = '0.1'
__build__ = '0.1'

import requests
import json

from .f5.common import constants as const
from .f5.common.logger import Log
from .f5.bigip.bigip_interfaces import domain_address
from .f5.bigip.bigip_interfaces import icontrol_folder
from .f5.bigip.bigip_interfaces import icontrol_rest_folder
from .f5.bigip.bigip_interfaces import strip_folder_and_prefix

from suds import WebFault
import os
import time
import urllib


class SSL(object):

    """
        def __init__(self, hostname=None, username=None, password=None):
                self.hostname = hostname
                self.username = username
                self.password = password

                # REST resource for BIG-IP that all requests will use
                self.bigipREST = requests.session()
                self.bigipREST.auth = (self.username, self.password)
                self.bigipREST.verify = False
                self.bigipREST.headers.update({'Content-Type' : 'application/json'})

                # Requests requires a full URL to be sent as arg for every request, define base URL globally here
                self.bigipREST_url_base = 'https://%s/mgmt/tm' % self.hostname

                # SOAP resource for BIG-IP that select requests will use
                self.iControlSoapInterfaces = [
                        'Management.KeyCertificate',
                        'System.Session'
                ]
                self.bigipSOAP = pc.BIGIP(hostname=self.hostname, username=self.username, password=self.password, fromurl=True, wsdls=self.iControlSoapInterfaces)
    """

    def __init__(self, bigip):
        self.bigip = bigip

    @icontrol_folder
    def import_ssl_cert(self, cert, key, cert_name, folder='Common'):
        folder_path = '/' + folder
        # self.bigipSOAP.System.Session.set_active_folder(folder_path)
        # self.bigipSOAP.Management.KeyCertificate.certificate_import_from_pem(mode='MANAGEMENT_MODE_DEFAULT',cert_ids=[cert_name],pem_data=[cert],overwrite=True)
        # self.bigipSOAP.Management.KeyCertificate.key_import_from_pem(mode='MANAGEMENT_MODE_DEFAULT',key_ids=[cert_name],pem_data=[key],overwrite=True)
        self.bigip.icontrol.System.Session.set_active_folder(folder_path)
        self.bigip.icontrol.Management.KeyCertificate.certificate_import_from_pem(
            mode='MANAGEMENT_MODE_DEFAULT',
            cert_ids=[cert_name],
            pem_data=[cert],
            overwrite=True)
        self.bigip.icontrol.Management.KeyCertificate.key_import_from_pem(
            mode='MANAGEMENT_MODE_DEFAULT',
            key_ids=[cert_name],
            pem_data=[key],
            overwrite=True)

    def delete_cert(self, cert_name, folder):
        cert_path = '~' + folder + '~' + cert_name + '.crt'
        key_path = '~' + folder + '~' + cert_name + '.key'
        self.bigip.bigipREST.delete(
            '%s/sys/crypto/cert/%s' %
            (self.bigip.bigipREST_url_base, cert_path))
        self.bigip.bigipREST.delete(
            '%s/sys/crypto/key/%s' %
            (self.bigip.bigipREST_url_base, key_path))

    def import_intermediate_cert(self, cert, cert_name, folder='Common'):
        folder_path = '/' + folder
        self.bigip.icontrol.System.Session.set_active_folder(folder_path)
        self.bigip.icontrol.Management.KeyCertificate.certificate_import_from_pem(
            mode='MANAGEMENT_MODE_DEFAULT',
            cert_ids=[cert_name],
            pem_data=[cert],
            overwrite=True)

    def delete_intermediate_cert(self, cert_name, folder):
        cert_path = '~' + folder + '~' + cert_name + '.crt'
        self.bigip.bigipREST.delete(
            '%s/sys/crypto/cert/%s' %
            (self.bigip.bigipREST_url_base, cert_path))

    def create_cssl_profile(
            self,
            cssl_profile_name,
            cert_name,
            intermediate_cert_name=None,
            folder='Common'):
        cert_path = '/' + folder + '/' + cert_name + '.crt'
        key_path = '/' + folder + '/' + cert_name + '.key'
        payload = {}
        payload['kind'] = 'tm:ltm:profile:client-ssl:client-sslstate'
        payload['name'] = cssl_profile_name
        payload['partition'] = folder
        if intermediate_cert_name is not None:
            intermediate_cert_path = '/' + folder + \
                '/' + intermediate_cert_name + '.crt'
            payload['certKeyChain'] = [{'name': cert_name,
                                        'cert': cert_path,
                                        'key': key_path,
                                        'chain': intermediate_cert_path}]
        else:
            payload['certKeyChain'] = [
                {'name': cert_name, 'cert': cert_path, 'key': key_path}]

        rc = self.bigip.bigipREST.post(
            '%s/ltm/profile/client-ssl' %
            self.bigip.bigipREST_url_base,
            data=json.dumps(payload))
        print rc
        ##self.bigipSOAP.post('%s/ltm/profile/client-ssl' % self.bigipREST_url_base, data=json.dumps(payload))

    def delete_cssl_profile(self, cssl_profile_name, folder):
        cssl_profile_path = '~' + folder + '~' + cssl_profile_name
        self.bigip.bigipREST.delete(
            '%s/ltm/profile/client-ssl/%s' %
            (self.bigip.bigipREST_url_base, cssl_profile_path))

    def associate_cssl_profile(
            self, virtual_server_name, cssl_profile_name, folder='Common'):
        virtual_server_path = '~' + folder + '~' + virtual_server_name
        payload = {}
        payload['kind'] = 'tm:ltm:virtual:profiles:profilesstate'
        payload['name'] = cssl_profile_name
        payload['partition'] = folder
        self.bigip.bigipREST.post(
            '%s/ltm/virtual/%s/profiles' %
            (self.bigip.bigipREST_url_base,
             virtual_server_path),
            data=json.dumps(payload))

    def disassociate_cssl_profile(
            self, virtual_server_name, cssl_profile_name, folder='Common'):
        virtual_server_path = '~' + folder + '~' + virtual_server_name
        cssl_profile_path = '~' + folder + '~' + cssl_profile_name
        rc = self.bigip.bigipREST.delete(
            '%s/ltm/virtual/%s/profiles/%s' %
            (self.bigip.bigipREST_url_base,
             virtual_server_path,
             cssl_profile_path))
        print rc
