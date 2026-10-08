Write-Host "Killing processes on port 8000 and 5173..."
$ports = @(8000, 5173)
foreach ($port in $ports) {
    $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        Write-Host "Killing process ID $($conn.OwningProcess) on port $port"
        Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "Running Docker cleanup..."
docker compose down -v
Write-Host "Cleanup complete."
