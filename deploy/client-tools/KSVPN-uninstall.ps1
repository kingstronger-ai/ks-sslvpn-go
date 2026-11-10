#requires -Version 5.1
param(
    [string]$AppDir = ''
)
# KSVPN 客户端卸载：结束进程 -> 删快捷方式 -> 删卸载项 -> 删安装目录。
# 说明：OpenVPN Community 2.7.8 与 TAP 虚拟网卡属于系统级组件，本脚本不改动，
#       需要一并移除时请在「设置 -> 应用 -> 已安装的应用」里卸载 OpenVPN。
$ErrorActionPreference = 'Continue'

if ([string]::IsNullOrWhiteSpace($AppDir)) {
    $AppDir = Join-Path $env:LOCALAPPDATA 'KSVPN'
}
$AppDir = [IO.Path]::GetFullPath($AppDir)

$log = New-Object System.Collections.Generic.List[string]
function Note([string]$Message) {
    $script:log.Add($Message)
    Write-Host $Message
}

Note 'KSVPN 卸载开始'
Note ("目标安装目录：{0}" -f $AppDir)

# 1) 结束客户端主程序，以及由它启动的 OpenVPN 进程。
#    openvpn.exe 只按命令行里的 profiles 路径匹配，避免误杀其它 VPN 软件。
$markerScript = (Join-Path $AppDir 'KSVPN.ps1').ToLowerInvariant()
$markerProfiles = (Join-Path $AppDir 'profiles').ToLowerInvariant()
try {
    $targets = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.ProcessId -ne $PID -and $_.CommandLine -and (
            ($_.Name -in @('powershell.exe', 'pwsh.exe') -and $_.CommandLine.ToLowerInvariant().Contains($markerScript)) -or
            ($_.Name -eq 'openvpn.exe' -and $_.CommandLine.ToLowerInvariant().Contains($markerProfiles))
        )
    })
    foreach ($proc in $targets) {
        Stop-Process -Id ([int]$proc.ProcessId) -Force -ErrorAction SilentlyContinue
    }
    Note ("已结束 {0} 个客户端 / VPN 进程" -f $targets.Count)
} catch {
    Note ("进程枚举失败（可忽略）：{0}" -f $_.Exception.Message)
}
Start-Sleep -Milliseconds 600

# 2) 删除桌面与开始菜单快捷方式：按快捷方式实际指向判断，
#    既兼容改名前的旧命名，也不会误删其它软件。
try {
    $shell = New-Object -ComObject WScript.Shell
    $shortcutDirs = @(
        [Environment]::GetFolderPath('Desktop'),
        [Environment]::GetFolderPath('CommonDesktopDirectory'),
        [Environment]::GetFolderPath('Programs'),
        [Environment]::GetFolderPath('CommonPrograms')
    ) | Where-Object { $_ } | Select-Object -Unique
    $removed = 0
    foreach ($dir in $shortcutDirs) {
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        Get-ChildItem -LiteralPath $dir -Filter '*.lnk' -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $sc = $shell.CreateShortcut($_.FullName)
                $hint = "$($sc.Arguments) $($sc.TargetPath)"
                if ($hint -like '*launch-hidden.vbs*' -or $hint -like '*KSVPN-uninstall.ps1*') {
                    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
                    $script:removed++
                }
            } catch { }
        }
    }
    Note ("已删除 {0} 个桌面 / 开始菜单快捷方式" -f $removed)
} catch {
    Note ("快捷方式清理失败（可忽略）：{0}" -f $_.Exception.Message)
}

# 3) 移除「应用和功能」里的 KSVPN 卸载项
$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\KSVPN'
if (Test-Path -LiteralPath $regPath) {
    Remove-Item -LiteralPath $regPath -Force -ErrorAction SilentlyContinue
    Note '已移除「应用和功能」中的 KSVPN 卸载项'
}

# 4) 删除安装日志
$installLog = Join-Path $env:TEMP 'KSVPN-install.log'
if (Test-Path -LiteralPath $installLog -PathType Leaf) {
    Remove-Item -LiteralPath $installLog -Force -ErrorAction SilentlyContinue
    Note '已删除安装日志'
}

# 5) 收集待删目录：主目录 + 同级下含 launch-hidden.vbs 的历史版本安装目录。
#    用文件特征识别而不写死旧名字，可一并清掉品牌改名前的遗留目录。
$dirsToRemove = New-Object System.Collections.Generic.List[string]
if (Test-Path -LiteralPath $AppDir -PathType Container) { $dirsToRemove.Add($AppDir) }
$parent = Split-Path -Parent $AppDir
if (Test-Path -LiteralPath $parent -PathType Container) {
    Get-ChildItem -LiteralPath $parent -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        if (Test-Path -LiteralPath (Join-Path $_.FullName 'launch-hidden.vbs') -PathType Leaf) {
            if (-not $dirsToRemove.Contains($_.FullName)) { $dirsToRemove.Add($_.FullName) }
        }
    }
}

# 脚本若恰好位于待删目录内，交给临时 cmd 延迟删除，避免自身文件占用。
$selfDir = if ($PSCommandPath) { Split-Path -Parent $PSCommandPath } else { '' }
$deferred = @()
foreach ($dir in $dirsToRemove) {
    $same = $selfDir -and ($dir.TrimEnd([IO.Path]::DirectorySeparatorChar) -ieq $selfDir.TrimEnd([IO.Path]::DirectorySeparatorChar))
    if ($same) { $deferred += $dir; continue }
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    Note ("已删除 {0}" -f $dir)
}
if ($deferred.Count -gt 0) {
    $cleanup = Join-Path $env:TEMP 'KSVPN-cleanup.cmd'
    $lines = @('@echo off', 'ping -n 3 127.0.0.1 >nul')
    foreach ($dir in $deferred) { $lines += ('rd /s /q "{0}"' -f $dir) }
    $lines += 'del "%~f0"'
    [IO.File]::WriteAllLines($cleanup, $lines, [Text.Encoding]::Default)
    Start-Process -FilePath $env:ComSpec -ArgumentList ('/c "{0}"' -f $cleanup) -WindowStyle Hidden | Out-Null
    foreach ($dir in $deferred) { Note ("已排队删除（约 2 秒后完成）{0}" -f $dir) }
}

# 6) 结果提示
$summary = "KSVPN 客户端已卸载。`n`n" + ($log -join "`n") +
    "`n`nOpenVPN Community 2.7.8 与 TAP 虚拟网卡未改动。" +
    "`n如需一并移除，请到「设置 -> 应用 -> 已安装的应用」卸载 OpenVPN（会弹出 UAC）。"
try {
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show($summary, 'KSVPN 卸载', 'OK', 'Information') | Out-Null
} catch {
    Write-Host $summary
}
