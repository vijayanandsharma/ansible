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
module: k8s_service_account
short_description: Manages ServiceAccount Object in Kubernetes Cluster
description:
  - - Manages ServiceAccount Object in Kubernetes Cluster. This module also assumes that the api server is running in https://localhost.
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
- k8s_service_account:
    name: svc-admin-development
    namespace: development
    state: present
  
- k8s_service_account:
    name: svc-admin-development
    namespace: development
    image_pull_secrets:
      - development_secret_from_image
    secrets:
      - username
      - password
    state: present
    labels:
      key: value
  register: dev_namespace

# Delete Kubernetes namespace Cluster
- k8s_service_account:
    name: svc-admin-development
    namespace: development
    state: absent
'''

RETURN = '''
api_version:
    description: APIVersion of versioned schema of the representation of an object.
    returned: success
    type: str
    sample: "v1"
automount_service_account_token:
    description: APIVersion of versioned schema of the representation of an object.
    returned: success
    type: bool
    sample: "True"
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


def _read_service_account(name, namespace):
    api = client.CoreV1Api()
    api_service_account_response = api.read_namespaced_service_account(name=name, namespace=namespace)
    return api_service_account_response


def _check_service_account_changed(api_service_account_response, module):
    changed = False

    label_key_value_pairs_to_set = {}
    label_keys_to_unset = []

    new_labels = module.params.get("labels")
    current_labels = api_service_account_response.metadata.labels

    for key in current_labels.keys():
        if key not in new_labels:
            label_keys_to_unset.append(key)

    for key in set(new_labels.keys()) - set(label_keys_to_unset):
        if to_text(new_labels[key]) != current_labels.get(key):
            label_key_value_pairs_to_set[key] = new_labels[key]

    if label_key_value_pairs_to_set or label_keys_to_unset:
        return True

    secrets_list = []
    for secrets in api_service_account_response.secrets:
        secrets_list.append(secrets['name'])

    if set(secrets_list) == set(module.params.get('secrets')):
        changed = False
    else:
        return True

    pull_secrets_list = []
    for pull_secrets in api_service_account_response.image_pull_secrets:
        pull_secrets_list.append(pull_secrets['name'])

    if set(pull_secrets_list) == set(module.params.get('image_pull_secrets')):
        changed = False
    else:
        return True

    return changed


def create_or_update_service_account(module):
    """
    creates or patches the k8s ServiceAccount object.

    :param module:
    :return: V1ServiceAccount Dict returned from k8s API
    """
    results = dict()

    namespace = module.params.get('namespace')
    name = module.params.get('name')
    labels = module.params.get('labels')
    api = client.CoreV1Api()

    try:
        api_service_account_response = _read_service_account(name, namespace)
        if _check_service_account_changed(api_service_account_response, module):
            try:
                results = api.patch_namespaced_service_account(
                    client.V1ServiceAccount(metadata=client.V1ObjectMeta(name=namespace, labels=labels)))
                changed = True
            except ApiException as e:
                module.fail_json(msg="Unable to patch k8s ServiceAccount: {0}".format(to_native(e)),
                                 exception=traceback.format_exc())
        else:
            results = api_service_account_response
            changed = False

    except ApiException as e:
        if e.status == 404:
            try:
                results = api.create_namespaced_service_account(
                    client.V1ServiceAccount(metadata=client.V1ObjectMeta(name=namespace, labels=labels)))
                changed = True
            except ApiException as e:
                module.fail_json(msg="Unable to create k8s ServiceAccount: {0}".format(to_native(e)),
                                 exception=traceback.format_exc())

    return changed, results


def destroy_service_account(module):
    """
    Deletes the k8s ServiceAccount object.

    :param module:
    :return: V1ServiceAccount Dict returned from k8s API
    """

    results = dict()
    namespace = module.params.get('namespace')
    name = module.params.get('name')
    api = client.CoreV1Api()
    delete_options = client.V1DeleteOptions(propagation_policy="Background")

    try:
        api_service_account_response = _read_service_account(name, namespace)
        try:
            api_service_account_response = api.delete_namespaced_service_account(name=name, namespace=namespace,
                                                                                 body=delete_options)
        except ApiException as e:
            module.fail_json(msg="Unable to Delete k8s ServiceAccount: {0}".format(to_native(e)),
                             exception=traceback.format_exc())
        results = api_service_account_response
        changed = True

    except ApiException as e:
        results = e.body
        if e.status != 404:
            changed = False

    return changed, results


def main():
    module = AnsibleModule(
        argument_spec=dict(
            namespace=dict(type='str', required=True),
            name=dict(type='str', required=True),
            image_pull_secrets=dict(type='list', aliases=['pull_secrets']),
            secrets=dict(type='list'),
            state=dict(type='str', default='present', choices=['absent', 'present']),
            labels=dict(type='dict')
        )
    )

    if not HAS_KUBERNETES:
        module.fail_json(msg='kubernetes required for this module')

    config.load_kube_config()

    state = module.params.get("state")

    if state == 'present':
        (changed, results) = create_or_update_service_account(module)
    else:
        (changed, results) = destroy_service_account(module)

    module.exit_json(changed=changed, result=results)


if __name__ == '__main__':
    main()
