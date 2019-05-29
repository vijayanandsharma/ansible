#!/usr/bin/env bash

# We don't set -u here, due to pypa/virtualenv#150
set -ex

MYTMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'mytmpdir')

trap 'rm -rf "${MYTMPDIR}"' EXIT

# This is needed for the ubuntu1604py3 tests
# Ubuntu patches virtualenv to make the default python2
# but for the python3 tests we need virtualenv to use python3
PYTHON=${ANSIBLE_TEST_PYTHON_INTERPRETER:-python}

# Test graceful failure for older versions of botocore
export ANSIBLE_ROLES_PATH=../
virtualenv --system-site-packages --python "${PYTHON}" "${MYTMPDIR}/boto3-less-than-1.6.0"
source "${MYTMPDIR}/boto3-less-than-1.6.0/bin/activate"
"${PYTHON}" -m pip install 'boto3<1.6.0'
ansible-playbook -i ../../inventory -e @../../integration_config.yml -v playbooks/version_fail.yml "$@"

# Run full test suite
virtualenv --system-site-packages --python "${PYTHON}" "${MYTMPDIR}/boto3-recent"
source "${MYTMPDIR}/boto3-recent/bin/activate"
$PYTHON -m pip install 'boto3>1.6.0'
ansible-playbook -i ../../inventory -e @../../integration_config.yml -v playbooks/full_test.yml "$@"
