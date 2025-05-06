from ecs_client.models.bucket import Bucket
from ecs_client.models.metadata import Metadata


class BucketManager:
    def __init__(self, s3_client: S3Client, ecs_client: ECSClient):
        self.s3 = s3_client
        self.ecs = ecs_client

    # Namespace-level bucket operations via ECS management
    def get(self, namespace: str, name: str) -> Bucket:
        resp = self.ecs.get(f"/namespace/{namespace}/bucket/{name}")
        resp.raise_for_status()
        return Bucket(**resp.json())

    def create(self, bucket: Bucket) -> Bucket:
        resp = self.ecs.post(f"/namespace/{bucket.namespace}/bucket", json=bucket.__dict__)
        resp.raise_for_status()
        return Bucket(**resp.json())

    def update(self, bucket: Bucket) -> Bucket:
        resp = self.ecs.put(f"/namespace/{bucket.namespace}/bucket/{bucket.name}", json=bucket.properties)
        resp.raise_for_status()
        return Bucket(**resp.json())

    def delete(self, namespace: str, name: str):
        resp = self.ecs.delete(f"/namespace/{namespace}/bucket/{name}")
        resp.raise_for_status()

    # Metadata via S3 tagging
    def get_metadata(self, bucket_name: str) -> BucketMetadata:
        resp = self.s3.get_bucket_tagging(bucket_name)
        tags = resp.get('TagSet', [])
        return BucketMetadata(bucket=bucket_name, tags=tags)

    def update_metadata(self, meta: BucketMetadata) -> BucketMetadata:
        self.s3.put_bucket_tagging(meta.bucket, meta.tags)
        return meta

    # Lifecycle via S3
    def get_lifecycle(self, bucket_name: str) -> LifecyclePolicy:
        resp = self.s3.get_bucket_lifecycle(bucket_name)
        rules = resp.get('Rules', [])
        return LifecyclePolicy(bucket=bucket_name, rules=rules)

    def update_lifecycle(self, policy: LifecyclePolicy) -> LifecyclePolicy:
        self.s3.put_bucket_lifecycle(policy.bucket, policy.rules)
        return policy

    def delete_lifecycle(self, bucket_name: str):
        self.s3.delete_bucket_lifecycle(bucket_name)

    # Dump/load for Bucket, Metadata, Lifecycle
    def dump_bucket(self, namespace: str, name: str, path: str):
        b = self.get(namespace, name)
        dump_to_yaml(b, path)

    def load_bucket(self, path: str) -> Bucket:
        return load_from_yaml(path, Bucket)

    def apply_bucket(self, path: str):
        bucket = self.load_bucket(path)
        try:
            return self.update(bucket)
        except:
            return self.create(bucket)

    def dump_metadata(self, bucket_name: str, path: str):
        meta = self.get_metadata(bucket_name)
        dump_to_yaml(meta, path)

    def load_metadata(self, path: str) -> BucketMetadata:
        return load_from_yaml(path, BucketMetadata)

    def apply_metadata(self, path: str):
        meta = self.load_metadata(path)
        return self.update_metadata(meta)

    def dump_lifecycle(self, bucket_name: str, path: str):
        pol = self.get_lifecycle(bucket_name)
        dump_to_yaml(pol, path)

    def load_lifecycle(self, path: str) -> LifecyclePolicy:
        return load_from_yaml(path, LifecyclePolicy)

    def apply_lifecycle(self, path: str):
        policy = self.load_lifecycle(path)
        try:
            return self.update_lifecycle(policy)
        except:
            return None

