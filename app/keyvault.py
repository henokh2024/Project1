import logging
import os

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

logger = logging.getLogger(__name__)


def get_secret_from_key_vault(secret_name: str) -> str:
    """
    Retrieve a secret securely from Azure Key Vault.

    In local development, DefaultAzureCredential can use the identity
    created by `az login`.

    In Azure App Service, it automatically uses the Web App's
    system-assigned managed identity.
    """

    key_vault_url = os.getenv("KEY_VAULT_URL")

    if not key_vault_url:
        raise RuntimeError(
            "KEY_VAULT_URL environment variable is not configured."
        )

    credential = DefaultAzureCredential()

    secret_client = SecretClient(
        vault_url=key_vault_url,
        credential=credential,
    )

    secret = secret_client.get_secret(secret_name)

    logger.info(
        "Successfully retrieved secret '%s' from Azure Key Vault.",
        secret_name,
    )

    return secret.value