# Render the brand PNGs from the SVGs in docs/assets/brand/ with headless
# Chrome (or Edge). Windows; run after scripts/gen_brand.py.
#
#   powershell -File scripts/render_brand_png.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$brand = Join-Path $root "docs\assets\brand"
$browser = @(
    "C:\Program Files\Google\Chrome\Application\chrome.exe",
    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $browser) { throw "Chrome or Edge is needed to render the PNGs" }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("provio-brand-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null

function Render($svgName, $w, $h, $out, $bg, $pad) {
    $svg = (Get-Content -Raw -Encoding UTF8 (Join-Path $brand $svgName))
    $html = @"
<!doctype html><html><head><style>
html,body{margin:0;padding:0;width:${w}px;height:${h}px;background:$bg;overflow:hidden}
.w{width:${w}px;height:${h}px;display:flex;align-items:center;justify-content:center;box-sizing:border-box;padding:${pad}px}
.w svg{width:100%;height:100%}
</style></head><body><div class="w">$svg</div></body></html>
"@
    $page = Join-Path $tmp "$out.html"
    Set-Content -Path $page -Value $html -Encoding utf8
    $png = Join-Path $brand $out
    $ErrorActionPreference = "Continue"   # the browser reports progress on stderr
    & $browser --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 `
        --default-background-color=00000000 --window-size="$w,$h" `
        --screenshot="$png" ("file:///" + ($page -replace '\\', '/')) 2>$null | Out-Null
    Start-Sleep -Milliseconds 300
    if (-not (Test-Path $png)) { throw "render failed: $out" }
    Write-Host "wrote $out ($w x $h)"
}

Render "icon.svg" 512 512 "icon-512.png" "transparent" 0
Render "icon.svg" 180 180 "icon-180.png" "transparent" 0
Render "icon.svg" 32 32 "icon-32.png" "transparent" 0
Render "hero.svg" 1280 640 "social-preview.png" "#0b0f14" 0
Remove-Item -Recurse -Force $tmp
