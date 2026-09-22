$ErrorActionPreference = "Stop"
$API_KEY  = "changeme"
$ZAP_PORT = 8081
$ZAP_URL  = "http://localhost:$ZAP_PORT"
$CERT_PATH = Join-Path $PSScriptRoot "zap_root_ca.cer"

# 1. pull
Write-Host "[1/4] Pulling ZAP Docker image..."
docker pull zaproxy/zap-stable

# 2. remove existing container and restart
$existing = docker ps -a --filter "name=^zap$" --format "{{.Names}}"
if ($existing -eq "zap") {
    Write-Host "  Removing existing zap container..."
    docker stop zap | Out-Null
    docker rm zap | Out-Null
}

Write-Host "[2/4] Starting ZAP container..."
docker run -u zap --name zap `
    -p "${ZAP_PORT}:${ZAP_PORT}" `
    -e "ZAP_PORT=${ZAP_PORT}" `
    -v zap_home:/home/zap/.ZAP `
    -d zaproxy/zap-stable `
    zap.sh -daemon `
    -host 0.0.0.0 `
    -port $ZAP_PORT `
    "-config" "api.addrs.addr.name=.*" `
    "-config" "api.addrs.addr.regex=true" `
    "-config" "api.key=$API_KEY" `
    "-config" "formhandler.fields.field(13).value=IBDS test" `
    "-config" "formhandler.fields.field(14).value=IBDS test"  # Value Generator 기본 문장 단축 (13: comment 계열, 14: content 계열)

# 3. wait until ready (max 60s)
Write-Host "[3/4] Waiting for ZAP to initialize..."
$ready = $false
for ($i = 1; $i -le 30; $i++) {
    Start-Sleep -Seconds 2
    try {
        $res = Invoke-RestMethod "$ZAP_URL/JSON/core/view/version/?apikey=$API_KEY" -ErrorAction Stop
        Write-Host "  ZAP ready (v$($res.version))"
        $ready = $true
        break
    } catch {
        Write-Host "  Waiting... ($i/30)"
    }
}

if (-not $ready) {
    Write-Host "[ERROR] ZAP failed to start. Check: docker logs zap" -ForegroundColor Red
    exit 1
}

# 4. save certificate
Write-Host "[4/4] Saving ZAP root certificate..."
Invoke-WebRequest "$ZAP_URL/OTHER/core/other/rootcert/?apikey=$API_KEY" -OutFile $CERT_PATH
Write-Host "  Certificate saved: $CERT_PATH"

# 5. generate zap_config.json
$CONFIG_PATH = Join-Path $PSScriptRoot "config\zap_config.json"
@{
    host    = "127.0.0.1"
    port    = $ZAP_PORT
    api_key = $API_KEY
} | ConvertTo-Json | Set-Content -Path $CONFIG_PATH -Encoding utf8
Write-Host "[5/5] zap_config.json generated: $CONFIG_PATH"

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host "Please Set firefox proxy : your_local_ip:$ZAP_PORT" -ForegroundColor Red
Write-Host "Firefox cert path   : $CERT_PATH"
