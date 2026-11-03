#requires -RunAsAdministrator
<#
  把 g3 MITM 根证书导入 Windows 本机"受信任的根证书颁发机构"。
  Chrome / Edge / 360 等用系统信任库的浏览器导完即生效（需重启浏览器）。
  Firefox 不用系统库，见脚本末尾提示。

  用法：把 myCA.crt 和本脚本放同一目录，双击旁边的 install-ca.bat；
        或管理员 PowerShell 里 .\windows-install-ca.ps1 [-CertPath 路径]
#>
param(
    [string]$CertPath
)

$ErrorActionPreference = 'Stop'

if (-not $CertPath) {
    $CertPath = Join-Path $PSScriptRoot 'myCA.crt'
}

if (-not (Test-Path -LiteralPath $CertPath)) {
    Write-Host "找不到证书文件：$CertPath" -ForegroundColor Red
    Write-Host "请先把服务器上的 /opt/zf/g3/conf/myCA.crt 拷到本脚本同目录（或 -CertPath 指定）。" -ForegroundColor Yellow
    exit 1
}

$full = (Resolve-Path -LiteralPath $CertPath).Path
Write-Host "导入根证书：$full" -ForegroundColor Cyan

# certutil -f 幂等：同名根已存在会先删再加，重复运行不会堆叠
& certutil.exe -f -addstore 'Root' $full | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "导入失败，certutil 退出码 $LASTEXITCODE" -ForegroundColor Red
    exit 1
}

# 校验确实进了本机 Root 库
$thumb = (Get-PfxCertificate -FilePath $full).Thumbprint
$found = Get-ChildItem -Path Cert:\LocalMachine\Root |
    Where-Object { $_.Thumbprint -eq $thumb }

if ($found) {
    Write-Host "已加入受信任的根证书颁发机构：" -ForegroundColor Green
    Write-Host "  主题： $($found.Subject)"
    Write-Host "  指纹： $($found.Thumbprint)"
} else {
    Write-Host "certutil 报成功但本机 Root 库里没找到，可能被组策略拦截。" -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host '下一步：完全退出并重启浏览器（Chrome/Edge 缓存证书链，不重启不生效）。' -ForegroundColor Yellow
Write-Host 'Firefox 不读系统库，需单独导入：设置 ▸ 隐私与安全 ▸ 证书 ▸ 查看证书 ▸ "权威" ▸ 导入，' -ForegroundColor Yellow
Write-Host '          并勾选"信任此 CA 标识的网站"。' -ForegroundColor Yellow
