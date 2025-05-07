from ecs_client.models.namespace import Namespace
from ecs_client.request import ECSClient

class NamespaceManager:
    def __init__(self, client: ECSClient):
        self.client = client

    def get_all(self) -> Namespace:
        resp = self.client.get(f"/namespace/")
        resp.raise_for_status()
        return Namespace(**resp.json())

    def get(self, name: str) -> Namespace:
        resp = self.client.get(f"/namespace/{name}")
        resp.raise_for_status()
        return Namespace(**resp.json())

    def create(self, ns: Namespace) -> Namespace:
        resp = self.client.post(f"/namespace", json=ns.__dict__)
        resp.raise_for_status()
        return Namespace(**resp.json())

    def update(self, ns: Namespace) -> Namespace:
        resp = self.client.put(f"/namespace/{ns.name}", json=ns.properties)
        resp.raise_for_status()
        return Namespace(**resp.json())

    def delete(self, name: str):
        resp = self.client.delete(f"/namespace/{name}")
        resp.raise_for_status()