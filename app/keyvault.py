import os

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient


KEY_VAULT_NAME = os.getenv("KEY_VAULT_NAME", "kv-project1-henok")
KEY_VAULT_URL = f"https://{KEY_VAULT_NAME}.vault.azure.net"


def get_secret(secret_name: str) -> str:
    """
    Retrieve a secret value from Azure Key Vault.

    Local development:
        DefaultAzureCredential can use the current Azure CLI login.

    Azure VM:
        DefaultAzureCredential automatically uses the VM's
        system-assigned managed identity.
    """

    credential = DefaultAzureCredential()

    client = SecretClient(
        vault_url=KEY_VAULT_URL,
        credential=credential,
    )

    secret = client.get_secret(secret_name)

    return secret.value