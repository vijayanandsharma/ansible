#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: k8s_namespace
short_description: Manages namespace in Kubernetes Cluster
description:
  - Retrieve the attributes of a server certificate
version_added: "2.7"
author: "Vijayanand Sharma (@vijayanandsharma)"
requirements: [kubernetes]
options:
  namespace:
    description:
      - The namespace that should be created in the Kubernetes Cluster.
    required: true
'''

EXAMPLES = '''
# Create Kubernetes namespace Cluster
- k8s_namespace:
    namespace: development
    state: present
    labes:
      key: value
  register: dev_namespace

# Delete Kubernetes namespace Cluster
- k8s_namespace:
    namespace: development
    state: absent
'''

RETURN = '''
{'api_version': 'v1',
 'kind': 'Namespace',
 'metadata': {'annotations': None,
              'cluster_name': None,
              'creation_timestamp': datetime.datetime(2018, 11, 13, 10, 5, 22, tzinfo=tzlocal()),
              'deletion_grace_period_seconds': None,
              'deletion_timestamp': None,
              'finalizers': None,
              'generate_name': None,
              'generation': None,
              'initializers': None,
              'labels': None,
              'name': 'development',
              'namespace': None,
              'owner_references': None,
              'resource_version': '3874',
              'self_link': '/api/v1/namespaces/development',
              'uid': 'a251645e-e72b-11e8-a723-024238b6658b'},
 'spec': {'finalizers': ['kubernetes']},
 'status': {'phase': 'Active'}}

api_version:
    description: APIVersion of versioned schema of the representation of an object.
    returned: success
    type: str
    sample: "v1"
kind:
    description: Kind is a string value representing the resource this object represents.
    returned: success
    type: str
    sample: "Namespace"
metadata:
    description: Standard kubernetes object's metadata
    returned: success
    type: complex
    sample: { 'annotations': None,
              'cluster_name': None,
              'creation_timestamp': datetime.datetime(2018, 11, 13, 10, 5, 22, tzinfo=tzlocal()),
              'deletion_grace_period_seconds': None,
              'deletion_timestamp': None,
              'finalizers': None,
              'generate_name': None,
              'generation': None,
              'initializers': None,
              'labels': None,
              'name': 'development',
              'namespace': None,
              'owner_references': None,
              'resource_version': '3874',
              'self_link': '/api/v1/namespaces/development',
              'uid': 'a251645e-e72b-11e8-a723-024238b6658b' }
    contains:
      annotations:
        type: str
        returned: always
        description: Metadata for Kubernetes
      cluster_name:
        type: str
        returned: always
        description: Metadata for Kubernetes
      creation_timestamp:
        type: datetime
        returned: always
        description: Metadata for Kubernetes
      deletion_grace_period_seconds:
        type: str
        returned: always
        description: Metadata for Kubernetes
      generate_name:
        type: str
        returned: always
        description: Metadata for Kubernetes
      generation:
        type: str
        returned: always
        description: Metadata for Kubernetes
      initializers:
        type: str
        returned: always
        description: Metadata for Kubernetes
      labels:
        type: str
        returned: always
        description: Metadata for Kubernetes
      name:
        type: str
        returned: always
        description: Metadata for Kubernetes
      namespace:
        type: str
        returned: always
        description: Metadata for Kubernetes
      owner_references:
        type: str
        returned: always
        description: Metadata for Kubernetes
      resource_version:
        type: str
        returned: always
        description: Metadata for Kubernetes
      self_link:
        type: str
        returned: always
        description: Metadata for Kubernetes
      uid:
        type: str
        returned: always
        description: Metadata for Kubernetes
spec:
   description: Standard kubernetes object's metadata
   returned: success
   type: complex
   sample: 'spec': {'finalizers': ['kubernetes']}
     contains:
       finalizers: 
         type: list
         returned: always
         description: Spec for Kubernetes API
status:
    description: The Amazon resource name of the server certificate
    returned: complex
    type: str
    sample: 'status': {'phase': 'Active'}
      contains:
        phase:
          type: str
          returned: always
          description: Status/Phase of the Object
'''

from kubernetes import client, config
from kubernetes.client.rest import ApiException

try:
    import kubernetes
    HAS_KUBERNETES = True
except ImportError:
    HAS_KUBERNETES = False

def create_or_update_namespace(iam, name=None):
    """Retrieve the attributes of a server certificate if it exists or all certs.
    Args:
        iam (botocore.client.IAM): The boto3 iam instance.

    Kwargs:
        name (str): The name of the server certificate.

    Basic Usage:

        {
            "upload_date": "2015-04-25T00:36:40+00:00",
            "server_certificate_id": "ADWAJXWTZAXIPIMQHMJPO",
            "certificate_body": "-----BEGIN CERTIFICATE-----\nbunch of random data\n-----END CERTIFICATE-----",
            "server_certificate_name": "server-cert-name",
            "expiration": "2017-06-15T12:00:00+00:00",
            "path": "/",
            "arn": "arn:aws:iam::911277865346:server-certificate/server-cert-name"
        }
    """
    results = dict()
    try:
        if name:
            server_certs = [iam.get_server_certificate(ServerCertificateName=name)['ServerCertificate']]
        else:
            server_certs = iam.list_server_certificates()['ServerCertificateMetadataList']

        for server_cert in server_certs:
            if not name:
                server_cert = iam.get_server_certificate(ServerCertificateName=server_cert['ServerCertificateName'])['ServerCertificate']
            cert_md = server_cert['ServerCertificateMetadata']
            results[cert_md['ServerCertificateName']] = {
                'certificate_body': server_cert['CertificateBody'],
                'server_certificate_id': cert_md['ServerCertificateId'],
                'server_certificate_name': cert_md['ServerCertificateName'],
                'arn': cert_md['Arn'],
                'path': cert_md['Path'],
                'expiration': cert_md['Expiration'].isoformat(),
                'upload_date': cert_md['UploadDate'].isoformat(),
            }

    except botocore.exceptions.ClientError:
        pass

    return results


def main():
    module = AnsibleModule(
        argument_spec = dict(
            namespace=dict(type='str'),
            state=dict(type='str', default='present', choices=['absent', 'present', 'replace', 'update']),
            label=dict(type='dict')
        )
    )

    if not HAS_KUBERNETES:
        module.fail_json(msg='kubernetes required for this module')

    config.load_incluster_config()

    state = module.params.get("state")

    if state == 'present':
        create_or_update_namespace(connection, module)
    else:
        destroy_namespace(connection, module)


if __name__ == '__main__':
    main()
