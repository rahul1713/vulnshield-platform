# VulnShield Windows Agent - PowerShell Inventory Collector
# Outputs JSON to stdout for consumption by agent.py

$ErrorActionPreference = "SilentlyContinue"

function Get-OSInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    @{
        hostname = $env:COMPUTERNAME
        fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        caption = $os.Caption
        version = $os.Version
        build_number = $os.BuildNumber
        architecture = $os.OSArchitecture
        install_date = $os.InstallDate
        last_boot = $os.LastBootUpTime
        total_memory_gb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    }
}

function Get-InstalledSoftware {
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $software = foreach ($path in $paths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
    }
    @{
        count = ($software | Measure-Object).Count
        packages = @($software | Select-Object -First 2000 | ForEach-Object {
            @{
                name = $_.DisplayName
                version = $_.DisplayVersion
                vendor = $_.Publisher
                install_date = $_.InstallDate
                install_path = $_.InstallLocation
                package_manager = "windows_registry"
            }
        })
    }
}

function Get-RegistrySecurityInfo {
    $keys = @(
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LmCompatibilityLevel" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "RequireSecuritySignature" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableLUA" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConsentPromptBehaviorAdmin" }
    )
    $settings = @{}
    foreach ($key in $keys) {
        $value = (Get-ItemProperty -Path $key.Path -Name $key.Name -ErrorAction SilentlyContinue).($key.Name)
        $settings[$key.Name] = $value
    }
    @{ security_settings = $settings }
}

function Get-WindowsServices {
    $services = Get-Service | Select-Object Name, DisplayName, Status, StartType
    @{
        count = ($services | Measure-Object).Count
        services = @($services | ForEach-Object {
            @{
                name = $_.Name
                display_name = $_.DisplayName
                status = $_.Status.ToString()
                start_type = $_.StartType.ToString()
            }
        })
    }
}

function Get-ScheduledTasksInfo {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Select-Object TaskName, TaskPath, State, @{N="Author";E={$_.Author}}
    @{
        count = ($tasks | Measure-Object).Count
        tasks = @($tasks | Select-Object -First 500 | ForEach-Object {
            @{
                name = $_.TaskName
                path = $_.TaskPath
                state = $_.State.ToString()
                author = $_.Author
            }
        })
    }
}

function Get-OpenPortsInfo {
    $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, OwningProcess, State
    @{
        count = ($connections | Measure-Object).Count
        ports = @($connections | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            @{
                address = $_.LocalAddress
                port = $_.LocalPort
                protocol = "tcp"
                state = $_.State.ToString()
                process = $proc.ProcessName
                pid = $_.OwningProcess
            }
        })
    }
}

function Get-WindowsPatches {
    $hotfixes = Get-HotFix -ErrorAction SilentlyContinue |
        Select-Object HotFixID, Description, InstalledOn, InstalledBy
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $searcher = $updateSession.CreateUpdateSearcher()
    $pending = @()
    try {
        $result = $searcher.Search("IsInstalled=0")
        foreach ($update in $result.Updates) {
            $pending += @{
                title = $update.Title
                kb = ($update.KBArticleIDs | Select-Object -First 1)
                severity = $update.MsrcSeverity
            }
        }
    } catch {}

    @{
        installed_count = ($hotfixes | Measure-Object).Count
        installed_patches = @($hotfixes | Select-Object -First 200 | ForEach-Object {
            @{
                id = $_.HotFixID
                description = $_.Description
                installed_on = $_.InstalledOn.ToString()
            }
        })
        pending_count = $pending.Count
        pending_updates = $pending
    }
}

function Get-LocalUsersInfo {
    $users = Get-LocalUser -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet
    $sessions = query user 2>$null
    @{
        count = ($users | Measure-Object).Count
        users = @($users | ForEach-Object {
            @{
                username = $_.Name
                enabled = $_.Enabled
                last_logon = $_.LastLogon
                password_required = $_.PasswordRequired
            }
        })
        active_sessions = @($sessions)
    }
}

$inventory = @{
    os_info = Get-OSInfo
    installed_software = Get-InstalledSoftware
    registry_info = Get-RegistrySecurityInfo
    services = Get-WindowsServices
    scheduled_tasks = Get-ScheduledTasksInfo
    open_ports = Get-OpenPortsInfo
    patches = Get-WindowsPatches
    users = Get-LocalUsersInfo
    collected_at = (Get-Date).ToUniversalTime().ToString("o")
}

$inventory | ConvertTo-Json -Depth 6 -Compress
