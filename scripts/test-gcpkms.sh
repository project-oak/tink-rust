#!/bin/bash
# Copyright 2020 The Tink-Rust Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o xtrace

# Default GCP KMS keyinfo
GCP_PROJECT="tink-rust-testing"
GCP_LOCATION="global"
GCP_KEYRING="test"
GCP_KEYNAME="tink-rust-$(uuidgen)"

GCP_KEY_URI="gcp-kms://projects/${GCP_PROJECT}/locations/${GCP_LOCATION}/keyRings/${GCP_KEYRING}/cryptoKeys/${GCP_KEYNAME}"

# Default to default credentials.  Credentials files can be obtained from:
#   https://console.cloud.google.com/apis/credentials/serviceaccountkey
# with permissions:
# - Cloud KMS Admin: to allow ephemeral key creation
# - Cloud KMS CryptoKey Encrypter/Decrypter: to allow encrypt/decrypt
GCP_CREDS=${GCP_CREDS:-""}
if [ -n "${GCP_CREDS}" ]; then
    export GOOGLE_APPLICATION_CREDENTIALS="${GCP_CREDS}"
fi

# Create an ephemeral key and ensure it's deleted on the way out
gcloud kms keys create "${GCP_KEYNAME}" --project="${GCP_PROJECT}" --keyring="${GCP_KEYRING}" --location="${GCP_LOCATION}" --purpose="encryption"
cleanup() {
    gcloud kms keys versions destroy 1 --project="${GCP_PROJECT}" --keyring="${GCP_KEYRING}" --location="${GCP_LOCATION}" --key="${GCP_KEYNAME}"
    # Show key status on exit so any non-pending-destruction keys might get spotted.
    gcloud kms keys list --project="${GCP_PROJECT}" --keyring="${GCP_KEYRING}" --location="${GCP_LOCATION}" | grep -v DESTROY_SCHEDULED | grep -v DESTROYED
}
trap cleanup EXIT

# Set environment variables that the test script picks up.
export TINK_GCP_TEST_KEY_URI="${GCP_KEY_URI}"
export TINK_GCP_TEST_CREDENTIALS="${GCP_CREDS}"
cargo test --manifest-path=integration/gcpkms/Cargo.toml -- --nocapture --ignored gcpkms

# If enabled via https://console.cloud.google.com/iam-admin/audit ("Cloud Key Management Service (KMS) API"),
# KMS logs should be visible at: https://console.cloud.google.com/logs
