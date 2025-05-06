client = ECSClient(config_client, ecs_requests, emc_client)
# Lister
namespaces = client.list_namespaces()
# Créer
new_ns = client.create_namespace("ns-new", default_replication_group="rg1", namespace_admins=["admin1"])
# Mettre à jour (quota, encryption, etc.)
updated = client.update_namespace("ns-new", quota={"max":1000})
# Supprimer
ok = client.delete_namespace("ns-new")



# Lister
buckets = client.list_buckets("ns1")
# Créer
b = client.create_bucket("monbucket", namespace="ns1", retention=30)
# Mettre à jour
b2 = client.update_bucket("monbucket", quota=500)
# Métadonnées
md = client.set_bucket_metadata("monbucket", {"env":"prod"})
# Supprimer
ok = client.delete_bucket("monbucket")


# Lister les règles
rules = client.list_lifecycle_rules("monbucket")
# Créer une règle par date
client.create_lifecycle_rule_with_date("monbucket", "expireRule", "logs/", "2025-12-31T00:00:00Z")
# Créer une règle par jours
client.create_lifecycle_rule_with_days("monbucket", "oldRule", "archive/", 90)


