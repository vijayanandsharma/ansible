#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import traceback

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: k8s_namespace
short_description: Manages namespace Object in Kubernetes Cluster
description:
  - Manages namespace Object in Kubernetes Cluster. This module also assumes that the api server is running in https://localhost.
    It also assumes that the kube config file is available in the default location i.e. ~/.kube/config
version_added: "2.8"
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
    labels:
      key: value
  register: dev_namespace

# Delete Kubernetes namespace Cluster
- k8s_namespace:
    namespace: development
    state: absent
'''

RETURN = '''
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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from kubernetes import client, config
from kubernetes.client.rest import ApiException

try:
    import kubernetes
    HAS_KUBERNETES = True
except ImportError:
    HAS_KUBERNETES = False


def _read_namespace(namespace):
    api = client.CoreV1Api()
    api_namespace_response = api.read_namespace(name=namespace)
    return api_namespace_response

def _check_namespace_changed(api_namespace_response, labels):
    if cmp(api_namespace_response.metadata.labels, labels) == 0:
        return False
    else:
        return True

def create_or_update_namespace(module):
    """
    creates or patches the k8s namespace object.

    :param module:
    :return: V1Namespace Dict returned from k8s API
    """
    results = dict()

    namespace = module.params.get('namespace')
    labels = module.params.get('labels')
    api = client.CoreV1Api()


    try:
        api_namespace_response = _read_namespace(namespace)
        if _check_namespace_changed(api_namespace_response, labels) :
            try:
                results = api.patch_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace, labels=labels)))
                changed = True
            except ApiException as e:
                module.fail_json(msg="Unable to patch k8s Namespace: {0}".format(to_native(e)),
                                 exception=traceback.format_exc())
        else:
            results = api_namespace_response
            changed = False

    except ApiException as e:
        if e.status == 404:
            try:
                results = api.create_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace, labels=labels)))
                changed = True
            except ApiException as e:
                module.fail_json(msg="Unable to create k8s Namespace: {0}".format(to_native(e)),
                                 exception=traceback.format_exc())

    return changed, results


def destroy_namespace(module):
    """
    Deletes the k8s namespace object.

    :param module:
    :return: V1Namespace Dict returned from k8s API
    """
    results = dict()
    namespace = module.params.get('namespace')
    api = client.CoreV1Api()
    delete_options = client.V1DeleteOptions(propagation_policy="Background")

    try:
        api_namespace_response = _read_namespace(namespace)
        try:
            api_namespace_response = api.delete_namespace(name=namespace, body=delete_options)
        except ApiException as e:
            module.fail_json(msg="Unable to Delete k8s Namespace: {0}".format(to_native(e)),
                             exception=traceback.format_exc())
        results = api_namespace_response
        changed = True

    except ApiException as e:
        results = e.body
        if e.status != 404:
           changed = False

    return changed, results


def main():
    module = AnsibleModule(
        argument_spec = dict(
            namespace=dict(type='str', required=True),
            state=dict(type='str', default='present', choices=['absent', 'present']),
            labels=dict(type='dict')
        )
    )

    if not HAS_KUBERNETES:
        module.fail_json(msg='kubernetes required for this module')

    config.load_kube_config()

    state = module.params.get("state")

    if state == 'present':
        (changed, results) = create_or_update_namespace(module)
    else:
        (changed, results) = destroy_namespace(module)

    module.exit_json(changed=changed, result=results)


if __name__ == '__main__':
    main()
