import re

with open('render.yaml', 'r', encoding='utf-8') as f:
    r_yaml = f.read()

r_yaml = r_yaml.replace('value: "${CLAMAV_MOCK_MODE:-false}"', 'value: "false"')
r_yaml = r_yaml.replace('Set to: gemini | groq | xai | ollama | none', 'Set to: groq | nvidia | cloudflare | huggingface | xai | ollama | none')
r_yaml = r_yaml.replace('Set GEMINI_API_KEY (or GROQ_API_KEY)', 'Set GROQ_API_KEY')

with open('render.yaml', 'w', encoding='utf-8') as f:
    f.write(r_yaml)

with open('.env.example', 'r', encoding='utf-8') as f:
    env_ex = f.read()

env_ex = env_ex.replace('AI_FALLBACK_CHAIN=nvidia,huggingface,cloudflare,xai,ollama,freellmapi', 'AI_FALLBACK_CHAIN=nvidia,cloudflare,huggingface,freellmapi')

with open('.env.example', 'w', encoding='utf-8') as f:
    f.write(env_ex)
