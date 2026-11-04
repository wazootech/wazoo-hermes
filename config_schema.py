"""Dashboard config panel for the wazoo memory provider."""

FIELDS = [
    {"key": "world_id", "label": "World id", "type": "string",
     "description": "Target world (w_...). Leave empty with a platform token to auto-provision.", "required": False},
    {"key": "data_url", "label": "Data endpoint", "type": "string",
     "description": "Worlds data-plane endpoint.", "default": "https://data.wazoo.dev", "required": False},
]

SECRETS = [
    {"key": "world_token", "label": "World token (wzw_)", "env_var": "WORLDS_TOKEN",
     "description": "World-scoped data-plane token.", "required": False},
    {"key": "platform_token", "label": "Platform token (wzp_)", "env_var": "WAZOO_PLATFORM_TOKEN",
     "description": "Control-plane token; a world is provisioned and a wzw_ token minted automatically.", "required": False},
]
