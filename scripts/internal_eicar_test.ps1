Write-Host "============================================="
Write-Host "INTERNAL EICAR PIPELINE TEST"
Write-Host "============================================="
Write-Host "Bypassing Windows Defender by testing entirely inside the Aegis Docker container."

$pythonScript = @"
import httpx
import json

EICAR = r'X5O!P%@AP[4\PZX54(P^)7CC)7}`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*'

with open('/tmp/eicar_internal.txt', 'w') as f:
    f.write(EICAR)

print('\n>>> UPLOADING EICAR TO AEGIS API...')
with open('/tmp/eicar_internal.txt', 'rb') as f:
    resp = httpx.post('http://localhost:8000/api/v1/datasets/upload', files={'file': ('eicar_internal.txt', f)}, timeout=60.0)

print(f'\nHTTP Status: {resp.status_code}')
try:
    data = resp.json()
    print('\nAPI Response:')
    print(json.dumps(data, indent=2))
    
    if data.get('scan_result', {}).get('clamav_status') == 'infected':
        print('\nSUCCESS! Real ClamAV correctly detected the EICAR file through Aegis!')
    else:
        print('\nFAILED! ClamAV did not detect the file as infected.')
except Exception as e:
    print(f'Error parsing response: {e}')
    print(resp.text)
"@

# Write the python script to a temp file on the host
Set-Content -Path ".\temp_eicar_test.py" -Value $pythonScript -Encoding UTF8

# Copy it into the container
docker cp .\temp_eicar_test.py aegis-node:/app/temp_eicar_test.py

# Run it inside the container
docker exec aegis-node python /app/temp_eicar_test.py

# Clean up
Remove-Item ".\temp_eicar_test.py"
docker exec aegis-node rm /app/temp_eicar_test.py /tmp/eicar_internal.txt

Write-Host "============================================="
