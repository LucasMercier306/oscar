# test_script.py
"""
Script d’intégration mis à jour pour tester vos commandes S3 et Dell EMC ECS Management
sur le test drive, sans lever d’erreur HTTPError automatique.
Exécutez simplement :
    python3 test_script.py
"""

import time
import urllib3
from pprint import pprint

# Désactive les warnings TLS non sécurisés
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from requests.exceptions import RequestException
from ecs_client.request import NamespaceRequest, BucketRequest, S3Signer, LifecycleRequest
from ecs_client import ConfigEMC, ConfigS3

# --- Credentials Test Drive ---
EMC_ENDPOINT   = "https://portal.ecstestdrive.com"
EMC_USERNAME   = "133889366257974364-admin"
EMC_PASSWORD   = "YzEyNjE1NjYwMzczODM1Mjg1MzY4Mzg1ZmRkZGI2ZTI="
TEST_NAMESPACE = "133889366257974364"

S3_ENDPOINT   = "https://object.ecstestdrive.com"
S3_ACCESS_KEY = "133889366257974364@ecstestdrive.emc.com"
S3_SECRET_KEY = "pYgso94mb/vjJu1z7/J+C1ZgB0KwgtXFHSNI4sRn"
S3_REGION     = "us-east-1"

# --- Configurations clients ---
emc_cfg = ConfigEMC(
    username=EMC_USERNAME,
    password=EMC_PASSWORD,
    endpoint=EMC_ENDPOINT
)
s3_cfg = ConfigS3(
    name="testdrive",
    endpoint=S3_ENDPOINT,
    access_key=S3_ACCESS_KEY,
    secret_key=S3_SECRET_KEY,
    namespace=TEST_NAMESPACE,
    region=S3_REGION,
    prefix_list=[]
)

ns_req = NamespaceRequest(emc_cfg)
bk_req = BucketRequest(emc_cfg)
lc_req = LifecycleRequest(s3_cfg)

# --- 1. LIST NAMESPACES ---
print("\n1. LIST NAMESPACES")
try:
    namespaces = ns_req.list()
    pprint(namespaces)
except RequestException as e:
    print("Erreur lors de la liste des namespaces :", e)
    exit(1)

# --- 2. GET NAMESPACE ---
print("\n2. GET NAMESPACE")
try:
    ns_data = ns_req.get(TEST_NAMESPACE)
    pprint(ns_data)
except RequestException as e:
    print("Erreur lors de la récupération du namespace :", e)
    exit(1)


# --- 3. CREATE BUCKET ---
test_bucket = f"test-bucket-{int(time.time())}"
print(f"\n3. CREATE BUCKET '{test_bucket}'")
resp = bk_req.create(
    bucket=test_bucket,
    namespace=TEST_NAMESPACE,
    file_system_enabled=True,
    quota=5,
    retention=10,
    autocommit_period=10  # ≤ 10s maximum
)
print("Status:", resp.status_code)
print("Body:", resp.text)
if resp.status_code >= 400:
    print("Échec de la création du bucket, abort.")
    exit(1)
else:
    print("Bucket créé avec succès.")


# --- 5. GET BUCKET ---
print(f"\n5. GET BUCKET '{test_bucket}'")
resp = bk_req.get(test_bucket, TEST_NAMESPACE)
print("Status:", resp.status_code)
print("Body:", resp.text)
if resp.status_code >= 400:
    print("Échec GET bucket, abort.")
    exit(1)
else:
    pprint(resp.json())

# --- 6. SET METADATA ---
print(f"\n6. SET METADATA on '{test_bucket}'")
meta = {"owner": "test_user", "env": "ci"}
resp = bk_req.set_metadata(test_bucket, meta)
print("Status:", resp.status_code)
print("Body:", resp.text)
if resp.status_code >= 400:
    print("Échec SET METADATA, abort.")
    exit(1)
else:
    pprint(resp.json())

# --- 7. LIST LIFECYCLE RULES ---
print(f"\n7. LIST LIFECYCLE RULES on '{test_bucket}'")
rules = lc_req.list_rules(test_bucket)
pprint(rules)

# --- 8. CREATE LIFECYCLE RULE ---
print(f"\n8. CREATE LIFECYCLE RULE on '{test_bucket}'")
rule_id = "expire-old"
prefix = ""
date_str = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 24*3600))
resp = lc_req.create_rule_with_date(test_bucket, rule_id, prefix, date_str)
print("Status:", getattr(resp, "status_code", resp))
if hasattr(resp, "text"):
    print("Body:", resp.text)

# --- 9. LIST LIFECYCLE RULES ---
print(f"\n9. LIST LIFECYCLE RULES on '{test_bucket}'")
rules = lc_req.list_rules(test_bucket)
pprint(rules)

# --- 10. TEST SIGNATURE V2 standalone ---
print("\n10. TEST SIGNATURE V2")
method = "GET"
url = f"{S3_ENDPOINT}/{test_bucket}/dummy-object"
headers = {"Content-Type": "application/octet-stream"}
signed_headers = S3Signer.sign_request_v2(
    method, url, headers.copy(),
    S3_ACCESS_KEY, S3_SECRET_KEY, b""
)
pprint(signed_headers)

# --- 11. DELETE BUCKET ---
print(f"\n11. DELETE BUCKET '{test_bucket}'")
resp = bk_req.delete(test_bucket, TEST_NAMESPACE)
print("Status:", resp.status_code)
print("Body:", resp.text)
print("Deleted:", resp.status_code == 204)

print("\n--- Script terminé ---")