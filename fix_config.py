import re

# 1. Update render.yaml
with open('render.yaml', 'r', encoding='utf-8') as f:
    r_yaml = f.read()

r_yaml = r_yaml.replace('value: gemini', 'value: groq')
r_yaml = r_yaml.replace('AI_FALLBACK_CHAIN\n        value: "cloudflare"', 'AI_FALLBACK_CHAIN\n        value: "nvidia,cloudflare,huggingface,freellmapi"')
r_yaml = r_yaml.replace('TRUSTED_PROXIES\n        value: "10.0.0.0/8,127.0.0.1"', 'TRUSTED_PROXIES\n        value: "[\\"10.0.0.0/8\\",\\"127.0.0.1\\"]"')
r_yaml = r_yaml.replace('AI_OPTIONAL_PROVIDERS\n        value: "groq,ollama,xai"', 'AI_OPTIONAL_PROVIDERS\n        value: ""')

env_vars_addition = '''
      - key: NVIDIA_API_KEY
        sync: false

      - key: HF_TOKEN
        sync: false

      - key: FREELLMAPI_ENABLED
        value: "false"

      - key: FREELLMAPI_API_KEY
        sync: false

      - key: FREELLMAPI_BASE_URL
        value: "http://localhost:3001/v1"
'''
if 'NVIDIA_API_KEY' not in r_yaml:
    r_yaml = r_yaml.replace('      - key: GROQ_API_KEY\n        sync: false', '      - key: GROQ_API_KEY\n        sync: false' + env_vars_addition)
    
r_yaml = re.sub(r'# Auto-failover: Gemini \(primary\) .*? automatically.', '# Auto-failover: Groq (primary) -> NVIDIA -> Cloudflare -> Hugging Face -> FreeLLMAPI', r_yaml, flags=re.DOTALL)

with open('render.yaml', 'w', encoding='utf-8') as f:
    f.write(r_yaml)

# 2. Update config.py
with open('backend/config.py', 'r', encoding='utf-8') as f:
    config_py = f.read()

pre_validator = '''
    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def parse_trusted_proxies(cls, v) -> list[str]:
        if isinstance(v, list):
            res = v
        elif isinstance(v, str):
            try:
                import json
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    res = parsed
                else:
                    res = [v]
            except json.JSONDecodeError:
                res = [x.strip() for x in v.split(",") if x.strip()]
        else:
            raise ValueError("trusted_proxies must be a list or a comma-separated string")
        
        valid_proxies = []
        import ipaddress
        for proxy in res:
            if proxy == "*":
                raise ValueError("Wildcard '*' is intentionally NOT supported for trusted_proxies")
            try:
                if "/" in proxy:
                    ipaddress.ip_network(proxy, strict=False)
                else:
                    ipaddress.ip_address(proxy)
                valid_proxies.append(proxy)
            except ValueError:
                raise ValueError(f"Invalid IP or CIDR network: {proxy}")
        return valid_proxies
'''

if 'def parse_trusted_proxies' not in config_py:
    config_py = config_py.replace('def is_trusted_proxy', pre_validator + '\n    def is_trusted_proxy')
    config_py = config_py.replace('from pydantic import Field', 'from pydantic import Field, field_validator')
    config_py = config_py.replace('from pydantic import BaseSettings, Field', 'from pydantic import BaseSettings, Field, field_validator')
    if 'field_validator' not in config_py:
        config_py = config_py.replace('from pydantic import model_validator', 'from pydantic import model_validator, field_validator')

# Deduplicate
config_py = re.sub(r'    # dY>.,\? Threat Intelligence \(Phase 9\)\n    enable_virustotal: bool = True.*?urlhaus_timeout_seconds: float = 5\.0\n\n', '', config_py, flags=re.DOTALL)
config_py = config_py.replace('cloudflare_account_id: str = ""\n    cloudflare_ai_gateway_id', 'cloudflare_ai_gateway_id')
config_py = config_py.replace('max_upload_size_mb: int = 500', 'max_upload_size_mb: int = 50')

with open('backend/config.py', 'w', encoding='utf-8') as f:
    f.write(config_py)

# 3. Update .env.example
with open('.env.example', 'r', encoding='utf-8') as f:
    env_ex = f.read()

env_ex = env_ex.replace('AI_PROVIDER=gemini', 'AI_PROVIDER=groq')
env_ex = env_ex.replace('MAX_UPLOAD_SIZE_MB=500', 'MAX_UPLOAD_SIZE_MB=50')

with open('.env.example', 'w', encoding='utf-8') as f:
    f.write(env_ex)

print("Scripts updated.")
