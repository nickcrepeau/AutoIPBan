# ============================================================
# AUTO IP BAN - WINDOWS SERVER 20XX
# Download at: github.com/nickcrepeau/AutoIPBan
# ============================================================

$ErrorActionPreference = "Continue"

# ============================================================
# HIDE POWERSHELL CONSOLE WINDOW
# ============================================================

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class ConsoleWindow {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@

$consoleHandle = [ConsoleWindow]::GetConsoleWindow()

if ($consoleHandle -ne [IntPtr]::Zero) {
    [ConsoleWindow]::ShowWindow($consoleHandle, 0)
}

# ============================================================
# SINGLE INSTANCE PROTECTION
# ============================================================

$script:InstanceMutex = $null
$createdNew = $false

$script:InstanceMutex = New-Object System.Threading.Mutex(
    $true,
    "Local\AutoIPBan-Security-Monitor",
    [ref]$createdNew
)

if (-not $createdNew) {

    Write-Host "AutoIPBan is already running." -ForegroundColor Yellow

    $script:InstanceMutex.Dispose()
    exit
}

Write-Host "AutoIPBan single-instance protection acquired." `
    -ForegroundColor Green

# CONFIGURATION

$script:Threshold = 10
$script:WindowMinutes = 1440
$PollSeconds = 3
$BatchSize = 50000
$FirewallAuditMinutes = 5
$HistoryDays = 30
$MaxLiveEntries = 500

$TrustedIPs = @(
    "1.1.1.1"
)

$Folder = "C:\ProgramData\AutoIPBan"
$StateFile = "$Folder\state.xml"
$LogFile = "$Folder\activity.log"
$FirewallGroup = "Auto-IPBan-4625"

$LogonTypes = @("3", "10")

New-Item -ItemType Directory -Path $Folder -Force | Out-Null

# LOGGING

function Write-Log {
    param([string]$Message)

    try {
        if ((Test-Path $LogFile) -and
            (Get-Item $LogFile).Length -gt 5MB) {

            $archive = Join-Path $Folder (
                "activity-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log"
            )

            Move-Item $LogFile $archive -Force
        }

        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message" |
            Add-Content -Path $LogFile -ErrorAction Stop
    }
    catch {
        Write-Host "LOG ERROR: $_"
    }
}

# IP VALIDATION

function Test-PublicIPv4 {
    param([string]$IP)

    $addr = $null

    if (-not [System.Net.IPAddress]::TryParse($IP, [ref]$addr)) {
        return $false
    }

    if ($addr.AddressFamily -ne
        [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }

    $b = $addr.GetAddressBytes()

    $excluded = (
        $b[0] -eq 0 -or
        $b[0] -eq 10 -or
        $b[0] -eq 127 -or
        $b[0] -ge 224 -or
        ($b[0] -eq 169 -and $b[1] -eq 254) -or
        ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
        ($b[0] -eq 192 -and $b[1] -eq 168) -or
        ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or
        ($b[0] -eq 192 -and $b[1] -eq 0) -or
        ($b[0] -eq 192 -and $b[1] -eq 2) -or
        ($b[0] -eq 198 -and ($b[1] -eq 18 -or $b[1] -eq 19)) -or
        ($b[0] -eq 198 -and $b[1] -eq 51 -and $b[2] -eq 100) -or
        ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113)
    )

    return (-not $excluded)
}

function Test-TrustedIP {
    param([string]$IP)

    return (
        ($TrustedIPs -contains $IP) -or
        ($State.Whitelisted -contains $IP)
    )
}

# STATE

# ============================================================
# SAFE STATE SAVING
# ============================================================

function Save-State {

    $temp = Join-Path $Folder (
        "state-" + [guid]::NewGuid().ToString() + ".tmp"
    )

    $backup = Join-Path $Folder "state-backup.xml"

    $mutex = $null
    $mutexHeld = $false
	
	$backupInterval = [TimeSpan]::FromHours(1)

	$createBackup = (
		-not (Test-Path $backup) -or
		((Get-Date) - (Get-Item $backup).LastWriteTime) -ge $backupInterval
	)

    try {

        # PREVENT SIMULTANEOUS STATE WRITES

        $mutex = New-Object System.Threading.Mutex(
            $false,
            "Local\AutoIPBan-State-Writer"
        )

        try {
            $mutexHeld = $mutex.WaitOne(10000)
        }
        catch [System.Threading.AbandonedMutexException] {
            $mutexHeld = $true
        }

        if (-not $mutexHeld) {
            throw "Unable to acquire state file mutex."
        }

        # WRITE TO UNIQUE TEMPORARY FILE

        $State |
            Export-Clixml `
                -Path $temp `
                -Force `
                -ErrorAction Stop

        # VERIFY THE TEMPORARY XML BEFORE REPLACING STATE

        $null = Import-Clixml `
            -Path $temp `
            -ErrorAction Stop

        # REPLACE EXISTING STATE WITH BACKUP

	if (Test-Path $StateFile) {

		if ($createBackup) {

			[System.IO.File]::Replace(
				$temp,
				$StateFile,
				$backup
			)

			Write-Log "STATE SAVED. HOURLY BACKUP UPDATED."

		}
		else {

			Move-Item `
				-Path $temp `
				-Destination $StateFile `
				-Force `
				-ErrorAction Stop

			Write-Log "STATE SAVED. HOURLY BACKUP NOT DUE."

		}
	}
        else {

            Move-Item `
                -Path $temp `
                -Destination $StateFile `
                -ErrorAction Stop

            Write-Log "INITIAL STATE FILE CREATED."
        }

    }
    catch {

        Write-Log "STATE SAVE ERROR: $_"
    }
    finally {

        if ($mutexHeld -and $null -ne $mutex) {
            $mutex.ReleaseMutex()
        }

        if ($null -ne $mutex) {
            $mutex.Dispose()
        }

        if (Test-Path $temp) {
            Remove-Item $temp -Force -ErrorAction SilentlyContinue
        }
    }
}

function Initialize-State {

    if (Test-Path $StateFile) {

            try {

			$script:State = Import-Clixml `
				-Path $StateFile `
				-ErrorAction Stop

			if ($State -isnot [System.Collections.IDictionary]) {
				throw "State file does not contain a valid state dictionary."
			}

			Write-Log "STATE FILE SUCCESSFULLY LOADED."

		}
		catch {

			$corruptBackup = Join-Path $Folder (
				"CORRUPTED-STATE-" +
				(Get-Date -Format "yyyyMMdd-HHmmss") +
				".xml"
			)

			Copy-Item `
				-Path $StateFile `
				-Destination $corruptBackup `
				-Force

			Write-Log "FATAL STATE ERROR. ORIGINAL PRESERVED: $corruptBackup"

			throw "State file is corrupted. Original preserved at $corruptBackup. $($_.Exception.Message)"
		}

        foreach ($key in @("Failures", "Banned")) {
            if (-not $State.ContainsKey($key)) {
                $State[$key] = @{}
            }
        }

        if (-not $State.ContainsKey("BanHistory")) {
            $State.BanHistory = @()
        }

        if (-not $State.ContainsKey("Whitelisted")) {
            $State.Whitelisted = @()
        }

        Write-Log "EXISTING STATE RESTORED."

    }
    else {

        $latest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop

        $script:State = @{
            LastRecordId = [long]$latest.RecordId
            Failures = @{}
            Banned = @{}
            BanHistory = @()
            Whitelisted = @()
        }

        Save-State
        Write-Log "INITIALIZED. HISTORICAL EVENTS IGNORED."
    }

	foreach ($ip in $TrustedIPs) {
		if ($ip -notin $State.Whitelisted) {
			$State.Whitelisted += $ip
		}
	}

	# RESTORE SAVED SETTINGS

	if (-not $State.ContainsKey("Settings") -or
		$null -eq $State.Settings) {

		$State.Settings = @{}
	}

	# INITIALIZE DEFAULT SETTINGS IF MISSING

	$defaultSettings = @{
		Threshold = 10
		WindowMinutes = 1440
		FirewallAuditMinutes = 5
		InitialAuditDelay = 2
	}

	foreach ($key in $defaultSettings.Keys) {

		if (-not $State.Settings.ContainsKey($key) -or
			[int]$State.Settings[$key] -lt 1) {

			$State.Settings[$key] = $defaultSettings[$key]
		}
	}

	# RESTORE SETTINGS

	$script:Threshold = [int]$State.Settings.Threshold
	$script:WindowMinutes = [int]$State.Settings.WindowMinutes

	$script:FirewallAuditMinutes = [int]$State.Settings.FirewallAuditMinutes
	$script:InitialAuditDelay = [int]$State.Settings.InitialAuditDelay

	# SAVE COMPLETED SETTINGS

	Save-State

	# FIREWALL AUDIT SETTINGS

	if (-not $State.Settings.ContainsKey("FirewallAuditMinutes")) {
		$State.Settings.FirewallAuditMinutes = 5
	}

	if (-not $State.Settings.ContainsKey("InitialAuditDelay")) {
		$State.Settings.InitialAuditDelay = 2
	}

	$script:Threshold = [int]$State.Settings.Threshold
	$script:WindowMinutes = [int]$State.Settings.WindowMinutes


	$script:FirewallAuditMinutes = [int]$State.Settings.FirewallAuditMinutes
	$script:InitialAuditDelay = [int]$State.Settings.InitialAuditDelay

	# PREVENT INVALID INITIAL AUDIT DELAY

	if ($script:InitialAuditDelay -lt 1) {
		$script:InitialAuditDelay = 1
	}

	if ($script:InitialAuditDelay -gt 1000) {
		$script:InitialAuditDelay = 1000
	}

	$State.Settings.InitialAuditDelay = $script:InitialAuditDelay

	Save-State
}



# FIREWALL BAN

function Add-IPBan {
    param([string]$IP)

    if (Test-TrustedIP $IP) {
        Write-Log "WHITELISTED IP PROTECTED: $IP"
        return $false
    }

    if (-not (Test-PublicIPv4 $IP)) {
        return $false
    }

    $ruleName = "Auto-IPBan-4625-$IP"

    $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue

    if (-not $existing) {

        try {

            New-NetFirewallRule `
                -Name $ruleName `
                -DisplayName "Auto IP Ban - $IP" `
                -Group $FirewallGroup `
                -Direction Inbound `
                -Action Block `
                -RemoteAddress $IP `
                -Profile Any `
                -Enabled True `
                -ErrorAction Stop | Out-Null

            $State.BanHistory += [PSCustomObject]@{
                IP = $IP
                Date = Get-Date
            }

            Write-Log "PERMANENT FIREWALL BAN: $IP"

        }
        catch {
            Write-Log "FIREWALL ERROR: $IP - $_"
            return $false
        }
    }

    $State.Banned[$IP] = Get-Date
    Save-State

    return $true
}



function Audit-FirewallBans {

    Write-Log "FIREWALL AUDIT STARTED."

    $expectedRules = @{}
    $auditFailed = $false
    $auditWarning = $false

    foreach ($ip in @($State.Banned.Keys)) {

        if (-not (Test-PublicIPv4 $ip) -or
            (Test-TrustedIP $ip)) {

            Write-Log "AUDIT WARNING: INVALID OR PROTECTED IP IN BAN STATE: $ip"
            $auditWarning = $true
            continue
        }

        $ruleName = "Auto-IPBan-4625-$ip"
        $expectedRules[$ruleName] = $true

        try {

            $rules = @(
                Get-NetFirewallRule `
                    -Name $ruleName `
                    -ErrorAction Stop
            )

            $repairRequired = $false

            # MISSING OR DUPLICATE RULES

            if ($rules.Count -ne 1) {

                $repairRequired = $true

                if ($rules.Count -eq 0) {
                    Write-Log "AUDIT MISSING RULE: $ip"
                }
                else {
                    Write-Log "AUDIT DUPLICATE RULES FOUND: $ip COUNT=$($rules.Count)"
                }
            }
            else {

                $rule = $rules[0]

                $addressFilter = @(
                    Get-NetFirewallAddressFilter `
                        -AssociatedNetFirewallRule $rule `
                        -ErrorAction Stop
                )

                $remoteAddresses = @(
                    $addressFilter | ForEach-Object {
                        $_.RemoteAddress
                    }
                )

                $correctAddress = (
                    $remoteAddresses.Count -eq 1 -and
                    [string]$remoteAddresses[0] -eq $ip
                )

                if (
                    $rule.Enabled -ne "True" -or
                    $rule.Action -ne "Block" -or
                    $rule.Direction -ne "Inbound" -or
                    $rule.Profile -ne "Any" -or
                    $rule.Group -ne $FirewallGroup -or
                    -not $correctAddress
                ) {

                    $repairRequired = $true

                    Write-Log "AUDIT INCORRECT RULE: $ip"
                }
            }

            # REPAIR MISSING, INCORRECT OR DUPLICATE RULES

            if ($repairRequired) {

                Write-Log "AUDIT REPAIR STARTED: $ip"

                foreach ($existingRule in $rules) {

                    Remove-NetFirewallRule `
                        -InputObject $existingRule `
                        -ErrorAction Stop
                }

                New-NetFirewallRule `
                    -Name $ruleName `
                    -DisplayName "Auto IP Ban - $ip" `
                    -Group $FirewallGroup `
                    -Direction Inbound `
                    -Action Block `
                    -RemoteAddress $ip `
                    -Profile Any `
                    -Enabled True `
                    -ErrorAction Stop | Out-Null

                Write-Log "AUDIT REPAIR SUCCESSFUL: $ip"
            }
        }
        catch {

            $auditFailed = $true

            Write-Log "AUDIT REPAIR FAILED: IP=$ip ERROR=$_"
        }
    }

    # CHECK FOR UNEXPECTED RULES

    try {

        $managedRules = @(
            Get-NetFirewallRule `
                -Group $FirewallGroup `
                -ErrorAction Stop
        )

        foreach ($rule in $managedRules) {

            if (-not $expectedRules.ContainsKey($rule.Name)) {

                $auditWarning = $true

                Write-Log "AUDIT WARNING: UNEXPECTED FIREWALL RULE FOUND: $($rule.Name)"
            }
        }
    }
    catch {

        $auditFailed = $true

        Write-Log "FIREWALL GROUP AUDIT ERROR: $_"
    }

	# UPDATE FIREWALL AUDIT RESULT

	if ($auditFailed) {

		$script:FirewallAuditResult = "FAILED"

		Write-Log "FIREWALL AUDIT COMPLETED WITH ERRORS."
	}
	elseif ($auditWarning) {

		$script:FirewallAuditResult = "WARNING"

		Write-Log "FIREWALL AUDIT COMPLETED WITH WARNINGS."
	}
	else {

		$script:FirewallAuditResult = "OK"

		Write-Log "FIREWALL AUDIT COMPLETED SUCCESSFULLY."
	}

	Update-FirewallAuditDisplay
}

# FIREWALL AUDIT COUNTDOWN DISPLAY

$script:FirewallAuditResult = "PENDING"

function Update-FirewallAuditDisplay {

    if (-not $script:NextFirewallAudit) {
        return
    }

    $remaining = $script:NextFirewallAudit - (Get-Date)

    if ($remaining.TotalSeconds -lt 0) {
        $remaining = [TimeSpan]::Zero
    }

    $minutes = [int][Math]::Floor($remaining.TotalMinutes)
    $seconds = $remaining.Seconds

    $countdown = "{0:D2}:{1:D2}" -f $minutes, $seconds

    if ($script:FirewallAuditResult -eq "PENDING") {

        $auditStatus.Text = "FIREWALL AUDIT: PENDING - $countdown"
        $auditStatus.ForeColor = [System.Drawing.Color]::Orange

    }
    else {

        $auditStatus.Text = "FIREWALL AUDIT: $($script:FirewallAuditResult) - NEXT: $countdown"

        switch ($script:FirewallAuditResult) {

            "OK" {
                $auditStatus.ForeColor = [System.Drawing.Color]::LimeGreen
            }

            "WARNING" {
                $auditStatus.ForeColor = [System.Drawing.Color]::Orange
            }

            "FAILED" {
                $auditStatus.ForeColor = [System.Drawing.Color]::Red
            }
        }
    }
}

# ============================================================
# WINDOWS FORMS GUI
# ============================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic

[System.Windows.Forms.Application]::EnableVisualStyles()

$script:TotalSuccesses = 0
$script:TotalFailures = 0
$script:Monitoring = $true
$script:FeedLimit = 500

$form = New-Object System.Windows.Forms.Form

$form.Text = "AutoIPBan - Security Monitor"
$form.Size = New-Object System.Drawing.Size(1300,850)
$form.MinimumSize = New-Object System.Drawing.Size(1150,750)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(20,27,38)
$form.ForeColor = [System.Drawing.Color]::White

# LABEL HELPER

function New-GUILabel {
    param(
        [string]$Text,
        [int]$X,
        [int]$Y,
        [int]$Width,
        [int]$Height = 30,
        [int]$Size = 11
    )

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point($X,$Y)
    $label.Size = New-Object System.Drawing.Size($Width,$Height)
    $label.ForeColor = [System.Drawing.Color]::White
    $label.Font = New-Object System.Drawing.Font("Segoe UI",$Size)

    return $label
}

# HEADER

$header = New-GUILabel "AUTO IP BAN for Failed Logins" 25 15 500 40 22
$header.Font = New-Object System.Drawing.Font(
    "Segoe UI",22,[System.Drawing.FontStyle]::Bold
)
$form.Controls.Add($header)

# STATUS LABELS

$status = New-GUILabel "PROTECTION ACTIVE" 550 25 220 30 13
$status.ForeColor = [System.Drawing.Color]::LimeGreen
$form.Controls.Add($status)

$auditStatus = New-GUILabel "FIREWALL AUDIT: PENDING" 780 25 300 30 13
$auditStatus.ForeColor = [System.Drawing.Color]::Orange
$form.Controls.Add($auditStatus)

# SETTINGS BUTTON

$settingsButton = New-Object System.Windows.Forms.Button
$settingsButton.Text = "SETTINGS"
$settingsButton.Location = New-Object System.Drawing.Point(1105,20)
$settingsButton.Size = New-Object System.Drawing.Size(130,38)
$settingsButton.BackColor = [System.Drawing.Color]::FromArgb(45,65,90)
$settingsButton.ForeColor = [System.Drawing.Color]::White
$settingsButton.FlatStyle = "Flat"

$form.Controls.Add($settingsButton)

$settingsButton.Add_Click({
    Open-BanSettings
})

# AUTOMATIC WINDOW DISPLAY

function Get-WindowDisplay {

    if ($WindowMinutes -ge 60 -and $WindowMinutes % 60 -eq 0) {

        $hours = [int]($WindowMinutes / 60)

        if ($hours -eq 1) {
            return "1 HOUR"
        }

        return "$hours HOURS"
    }

    if ($WindowMinutes -eq 1) {
        return "1 MINUTE"
    }

    return "$WindowMinutes MINUTES"
}

# STATISTICS

function New-StatLabel {
    param($Title,$X,$Y,$Color)

    $label = New-GUILabel $Title $X $Y 250 65 13
    $label.BackColor = [System.Drawing.Color]::FromArgb(36,47,63)
    $label.Padding = New-Object System.Windows.Forms.Padding(10)
    $label.ForeColor = $Color

    return $label
}

$failedLabel = New-StatLabel "FAILED LOGINS: 0" 25 75 ([System.Drawing.Color]::Tomato)
$successLabel = New-StatLabel "SUCCESSFUL LOGINS: 0" 315 75 ([System.Drawing.Color]::LimeGreen)
$banLabel = New-StatLabel "ACTIVE BANS: 0" 640 75 ([System.Drawing.Color]::Orange)
$thresholdLabel = New-StatLabel "BAN AFTER: $Threshold FAILS / $(Get-WindowDisplay)" 895 75 ([System.Drawing.Color]::White)

# IMPROVED STATISTICS HEADER SIZING

$failedLabel.Height = 52
$successLabel.Height = 52
$banLabel.Height = 52
$thresholdLabel.Height = 52

# FONT SIZES

$failedLabel.Font = New-Object System.Drawing.Font("Segoe UI",16)
$successLabel.Font = New-Object System.Drawing.Font("Segoe UI",16)
$banLabel.Font = New-Object System.Drawing.Font("Segoe UI",16)
$thresholdLabel.Font = New-Object System.Drawing.Font("Segoe UI",16)

# WIDEN BAN AFTER DISPLAY

$failedLabel.Width = 270
$successLabel.Width = 305
$banLabel.Width = 235
$thresholdLabel.Width = 360

$form.Controls.AddRange(@(
    $failedLabel,
    $successLabel,
    $banLabel,
    $thresholdLabel
))

# IP MANAGEMENT HEADINGS

$whiteTitle = New-GUILabel "WHITELISTED IP ADDRESSES" 25 145 400 25 13
$whiteTitle.ForeColor = [System.Drawing.Color]::LightGreen
$form.Controls.Add($whiteTitle)

$banTitle = New-GUILabel "BANNED IP ADDRESSES" 725 145 600 25 13
$banTitle.ForeColor = [System.Drawing.Color]::Salmon
$form.Controls.Add($banTitle)

# WHITELIST LIST - MULTI COLUMNS

$whiteList = New-Object System.Windows.Forms.ListBox
$whiteList.Location = New-Object System.Drawing.Point(25,175)
$whiteList.Size = New-Object System.Drawing.Size(450,133)
$whiteList.BackColor = [System.Drawing.Color]::FromArgb(25,34,48)
$whiteList.ForeColor = [System.Drawing.Color]::LightGreen
$whiteList.BorderStyle = "FixedSingle"
$whiteList.Font = New-Object System.Drawing.Font("Consolas",10)

$whiteList.MultiColumn = $true
$whiteList.ColumnWidth = 128
$whiteList.HorizontalScrollbar = $true
$whiteList.IntegralHeight = $false

$form.Controls.Add($whiteList)

# OWNER DRAW - BOLD CONFIGURATION-PROTECTED IPs

$whiteList.Add_DrawItem({

    param($sender, $e)

    if ($e.Index -lt 0) {
        return
    }

    $ip = [string]$sender.Items[$e.Index]

    $isSelected = (
        ($e.State -band [System.Windows.Forms.DrawItemState]::Selected) -ne 0
    )

    if ($isSelected) {
        $e.Graphics.FillRectangle(
            [System.Drawing.SystemBrushes]::Highlight,
            $e.Bounds
        )
    }
    else {
        $e.Graphics.FillRectangle(
            [System.Drawing.SystemBrushes]::Window,
            $e.Bounds
        )
    }

    # PROTECTED IPs ARE BOLD

    if ($ip -in $TrustedIPs) {

        $font = New-Object System.Drawing.Font(
            "Consolas", 10, [System.Drawing.FontStyle]::Bold
        )

    }
    else {

        $font = New-Object System.Drawing.Font(
            "Consolas", 10, [System.Drawing.FontStyle]::Regular
        )

    }

    if ($isSelected) {
        $brush = [System.Drawing.SystemBrushes]::HighlightText
    }
    else {
        $brush = [System.Drawing.SystemBrushes]::WindowText
    }

    try {

        $e.Graphics.DrawString(
            $ip,
            $font,
            $brush,
            $e.Bounds.X + 2,
            $e.Bounds.Y + 2
        )

    }
    finally {
        $font.Dispose()
    }

    $e.DrawFocusRectangle()

})

# BAN LIST - MULTI COLUMNS

$banList = New-Object System.Windows.Forms.ListBox
$banList.Location = New-Object System.Drawing.Point(500,175)
$banList.Size = New-Object System.Drawing.Size(655,133)
$banList.BackColor = [System.Drawing.Color]::FromArgb(25,34,48)
$banList.ForeColor = [System.Drawing.Color]::Salmon
$banList.BorderStyle = "FixedSingle"
$banList.Font = New-Object System.Drawing.Font("Consolas",10)

$banList.MultiColumn = $true
$banList.ColumnWidth = 128
$banList.HorizontalScrollbar = $true
$banList.IntegralHeight = $false

$form.Controls.Add($banList)

# LIVE ACTIVITY TITLE

$feedTitle = New-GUILabel "LIVE LOGIN ACTIVITY" 25 365 600 30 15
$feedTitle.Font = New-Object System.Drawing.Font(
    "Segoe UI",14,[System.Drawing.FontStyle]::Bold
)
$form.Controls.Add($feedTitle)

# SCROLLING EVENT GRID

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(25,400)
$grid.Size = New-Object System.Drawing.Size(1130,300)
$grid.BackgroundColor = [System.Drawing.Color]::FromArgb(25,34,48)
$grid.ForeColor = [System.Drawing.Color]::White
$grid.GridColor = [System.Drawing.Color]::FromArgb(55,65,81)
$grid.BorderStyle = "None"
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false
$grid.ReadOnly = $true
$grid.RowHeadersVisible = $false
$grid.SelectionMode = "FullRowSelect"
$grid.MultiSelect = $false
$grid.AutoSizeColumnsMode = "Fill"
$grid.ScrollBars = "Vertical"
$grid.RowTemplate.Height = 28
$grid.ColumnHeadersHeight = 35
$grid.EnableHeadersVisualStyles = $false

$grid.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(36,47,63)
$grid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
$grid.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(25,34,48)
$grid.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
$grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(55,75,100)
$grid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
$grid.Font = New-Object System.Drawing.Font("Consolas",9)

$columns = @(
    "Time",
    "EventID",
    "Status",
    "SourceIP",
    "Username",
    "LogonType",
    "Failures"
)

foreach ($column in $columns) {
    $grid.Columns.Add($column,$column) | Out-Null
}

$form.Controls.Add($grid)

# LOGIN FEED

function Add-LoginFeed {
    param(
        [string]$Time,
        [int]$EventID,
        [string]$IP,
        [string]$Username,
        [string]$LogonType,
        [string]$Failures = "-"
    )

    $eventStatus = if ($EventID -eq 4624) {
        "SUCCESS"
    }
    else {
        "FAILED"
    }

    $grid.Rows.Insert(
        0,
        $Time,
        $EventID,
        $eventStatus,
        $IP,
        $Username,
        $LogonType,
        $Failures
    )

    $row = $grid.Rows[0]

    if ($EventID -eq 4624) {
        $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::LightGreen
    }
    else {
        $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Salmon
    }

    while ($grid.Rows.Count -gt $script:FeedLimit) {
        $grid.Rows.RemoveAt($grid.Rows.Count - 1)
    }

    return $row
}

# BAN NOTIFICATION

function Add-BanNotification {
    param([string]$IP)

    $index = $grid.Rows.Add(
        (Get-Date -Format "HH:mm:ss"),
        "",
        "BANNED!!!",
        $IP,
        "",
        "",
        "$Threshold/$Threshold"
    )

    $grid.Rows[$index].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red
    $grid.Rows[$index].DefaultCellStyle.Font = New-Object System.Drawing.Font(
        "Consolas",9,[System.Drawing.FontStyle]::Bold
    )

    while ($grid.Rows.Count -gt $script:FeedLimit) {
        $grid.Rows.RemoveAt($grid.Rows.Count - 1)
    }
}

# UPDATE IP LISTS

function Update-IPLists {

    $whiteList.Items.Clear()
    $banList.Items.Clear()

    # PROTECTED IPS FIRST

    foreach ($ip in $TrustedIPs) {

        if ($ip -in $State.Whitelisted) {
            [void]$whiteList.Items.Add("* $ip")
        }
    }

    # MANUALLY WHITELISTED IPS

    foreach ($ip in @(
        $State.Whitelisted |
        Where-Object { $_ -notin $TrustedIPs } |
        Sort-Object -Unique
    )) {

        [void]$whiteList.Items.Add($ip)
    }

    # BANNED IPS

    foreach ($ip in @($State.Banned.Keys | Sort-Object)) {
        [void]$banList.Items.Add($ip)
    }
}

# ============================================================
# IP MANAGEMENT
# ============================================================

# UNBAN IP

function Remove-IPBan {
    param([string]$IP)

    if ([string]::IsNullOrWhiteSpace($IP)) {
        return
    }

    $ruleName = "Auto-IPBan-4625-$IP"

    try {
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue

        if ($rule) {
            Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
        }

        if ($State.Banned.ContainsKey($IP)) {
            $State.Banned.Remove($IP)
        }

        if ($State.Failures.ContainsKey($IP)) {
            $State.Failures.Remove($IP)
        }

        Save-State
        Update-IPLists

        Write-Log "IP UNBANNED: $IP"

        [System.Windows.Forms.MessageBox]::Show(
            "$IP has been unbanned.",
            "AutoIPBan",
            "OK",
            "Information"
        )
    }
    catch {
        Write-Log "UNBAN ERROR: $IP - $_"
    }
}

# CLEAR ALL BANS

function Clear-AllBans {

    $confirm1 = [System.Windows.Forms.MessageBox]::Show(
        "WARNING!`n`n" +
        "You are about to remove ALL AutoIPBan firewall bans.`n`n" +
        "All saved banned IP addresses and failure counters will be cleared.`n`n" +
        "Your whitelist will NOT be affected.`n`n" +
        "Do you want to continue?",
        "CLEAR ALL BANS - WARNING 1 OF 2",
        "YesNo",
        "Warning"
    )

    if ($confirm1 -ne "Yes") {
        return
    }

    $confirm2 = [System.Windows.Forms.MessageBox]::Show(
        "FINAL WARNING!`n`n" +
        "This will permanently remove every firewall rule " +
        "belonging to the Auto-IPBan group.`n`n" +
        "This action cannot be undone automatically.`n`n" +
        "Are you absolutely sure?",
        "CLEAR ALL BANS - FINAL CONFIRMATION",
        "YesNo",
        "Warning"
    )

    if ($confirm2 -ne "Yes") {
        return
    }

    try {

        # REMOVE ALL RULES IN THE AUTOBAN FIREWALL GROUP

        $rules = @(
            Get-NetFirewallRule `
                -Group $FirewallGroup `
                -ErrorAction Stop
        )

        foreach ($rule in $rules) {

            Remove-NetFirewallRule `
                -InputObject $rule `
                -ErrorAction Stop
        }

        # CLEAR SAVED BAN AND FAILURE DATA

        $State.Banned.Clear()
        $State.Failures.Clear()

        Save-State

        Update-IPLists
        Update-GUIStatistics

        Write-Log "ALL AUTOBAN FIREWALL RULES REMOVED. BAN STATE CLEARED."

        [System.Windows.Forms.MessageBox]::Show(
            "All bans have been successfully cleared!`n`n" +
            "Firewall rules removed: $($rules.Count)`n" +
            "Banned IP list cleared.`n" +
            "Failure counters reset.`n" +
            "Whitelist preserved.",
            "AutoIPBan - Bans Cleared",
            "OK",
            "Information"
        )

    }
    catch {

        Write-Log "CLEAR ALL BANS ERROR: $_"

        [System.Windows.Forms.MessageBox]::Show(
            "Unable to complete the clear operation.`n`n" +
            "Some firewall rules may have already been removed.`n`n" +
            "$_",
            "Clear Bans Error",
            "OK",
            "Error"
        )
    }
}

# ADD IP TO WHITELIST

function Add-TrustedIP {
    param([string]$IP)

    $IP = $IP.Trim()

    if (-not (Test-PublicIPv4 $IP)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please enter a valid public IPv4 address.",
            "Invalid IP",
            "OK",
            "Warning"
        )
        return
    }

    if ($IP -in $State.Whitelisted) {
        [System.Windows.Forms.MessageBox]::Show(
            "$IP is already whitelisted.",
            "AutoIPBan",
            "OK",
            "Information"
        )
        return
    }

    try {
        $State.Whitelisted += $IP

        $ruleName = "Auto-IPBan-4625-$IP"
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue

        if ($rule) {
            Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
        }

        if ($State.Banned.ContainsKey($IP)) {
            $State.Banned.Remove($IP)
        }

        if ($State.Failures.ContainsKey($IP)) {
            $State.Failures.Remove($IP)
        }

        Save-State
        Update-IPLists

        Write-Log "IP ADDED TO WHITELIST: $IP"

        [System.Windows.Forms.MessageBox]::Show(
            "$IP has been added to the whitelist.",
            "AutoIPBan",
            "OK",
            "Information"
        )
    }
    catch {
        Write-Log "WHITELIST ERROR: $IP - $_"

        [System.Windows.Forms.MessageBox]::Show(
            "Unable to update $IP.`n$_",
            "AutoIPBan Error",
            "OK",
            "Error"
        )
    }
}

# REMOVE IP FROM WHITELIST

function Remove-TrustedIP {
    param([string]$IP)

    if ([string]::IsNullOrWhiteSpace($IP)) {
        return
    }

    if ($IP -in $TrustedIPs) {
        [System.Windows.Forms.MessageBox]::Show(
            "This IP is protected in the script configuration and cannot be removed here.",
            "Protected IP",
            "OK",
            "Warning"
        )
        return
    }

    $State.Whitelisted = @(
        $State.Whitelisted | Where-Object { $_ -ne $IP }
    )

    Save-State
    Update-IPLists

    Write-Log "IP REMOVED FROM WHITELIST: $IP"
}


# ============================================================
# IMPORT / EXPORT IP LISTS
# ============================================================

function Export-IPLists {

    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Title = "Export AutoIPBan Lists"
    $dialog.Filter = "JSON Files (*.json)|*.json"
    $dialog.FileName = "AutoIPBan-Lists-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

    if ($dialog.ShowDialog() -ne "OK") {
        return
    }

    try {

        $exportData = [PSCustomObject]@{
            Version = 1
            ExportedAt = (Get-Date).ToString("o")

            Whitelisted = @(
                $State.Whitelisted | Sort-Object -Unique
            )

            Banned = @(
                $State.Banned.Keys |
                Where-Object {
                    $_ -notin $State.Whitelisted
                } |
                Sort-Object -Unique
            )
        }

        $exportData |
            ConvertTo-Json -Depth 5 |
            Set-Content -Path $dialog.FileName -Encoding UTF8 -ErrorAction Stop

        Write-Log "IP LISTS EXPORTED: $($dialog.FileName)"

        [System.Windows.Forms.MessageBox]::Show(
            "Lists successfully exported.`n`n$($dialog.FileName)",
            "AutoIPBan Export",
            "OK",
            "Information"
        )

    }
    catch {

        Write-Log "EXPORT ERROR: $_"

        [System.Windows.Forms.MessageBox]::Show(
            "Export failed.`n$_",
            "Export Error",
            "OK",
            "Error"
        )
    }
}

function Import-IPLists {

    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = "Import AutoIPBan Lists"
    $dialog.Filter = "JSON Files (*.json)|*.json"

    if ($dialog.ShowDialog() -ne "OK") {
        return
    }

    try {

        $data = Get-Content -Path $dialog.FileName -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop

        if ($data.Version -ne 1) {
            throw "Unsupported or invalid backup version."
        }

        if ($null -eq $data.Whitelisted -or
            $null -eq $data.Banned) {
            throw "Backup is missing required IP lists."
        }

        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Import IP lists from:`n$($dialog.FileName)`n`n" +
            "Existing lists will be merged, not replaced.`n`nContinue?",
            "Confirm Import",
            "YesNo",
            "Question"
        )

        if ($confirm -ne "Yes") {
            return
        }

        $addedWhitelist = 0
        $addedBans = 0

        # IMPORT WHITELIST FIRST
        # Whitelisted IPs always take priority over bans.

        foreach ($ip in @($data.Whitelisted)) {

            $ip = [string]$ip

            if (-not (Test-PublicIPv4 $ip)) {
                continue
            }

            if ($ip -notin $State.Whitelisted) {
                $State.Whitelisted += $ip
                $addedWhitelist++
            }

            # Remove any existing ban for this IP.

            $ruleName = "Auto-IPBan-4625-$ip"

            $rule = Get-NetFirewallRule `
                -Name $ruleName `
                -ErrorAction SilentlyContinue

            if ($rule) {
                Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
            }

            if ($State.Banned.ContainsKey($ip)) {
                $State.Banned.Remove($ip)
            }

            if ($State.Failures.ContainsKey($ip)) {
                $State.Failures.Remove($ip)
            }
        }

        Save-State

        # IMPORT BANNED IPS
        # Add-IPBan validates addresses and protects whitelisted IPs.

        foreach ($ip in @($data.Banned)) {

            $ip = [string]$ip

            if (-not (Test-PublicIPv4 $ip)) {
                continue
            }

            if (Test-TrustedIP $ip) {
                continue
            }

			$alreadyBanned = $State.Banned.ContainsKey($ip)

			if (Add-IPBan -IP $ip) {

				if (-not $alreadyBanned) {
					$addedBans++
				}
			}
        }

        Save-State
        Update-IPLists
        Update-GUIStatistics

        Write-Log "IP LISTS IMPORTED: WHITELIST=$addedWhitelist BANS=$addedBans"

        [System.Windows.Forms.MessageBox]::Show(
            "Import completed successfully!`n`n" +
            "New whitelisted IPs: $addedWhitelist`n" +
            "New banned IPs: $addedBans",
            "AutoIPBan Import",
            "OK",
            "Information"
        )

    }
    catch {

        Write-Log "IMPORT ERROR: $_"

        [System.Windows.Forms.MessageBox]::Show(
            "Import failed.`n`n$_",
            "Import Error",
            "OK",
            "Error"
        )
    }
}

# MANUALLY BAN IP

function Add-ManualBan {

    $IP = [Microsoft.VisualBasic.Interaction]::InputBox(
        "Enter the public IPv4 address you want to ban:",
        "Manually Ban IP",
        ""
    ).Trim()

    if ([string]::IsNullOrWhiteSpace($IP)) {
        return
    }

    if (-not (Test-PublicIPv4 $IP)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please enter a valid public IPv4 address.",
            "Invalid IP",
            "OK",
            "Warning"
        )
        return
    }

    if (Test-TrustedIP $IP) {
        [System.Windows.Forms.MessageBox]::Show(
            "$IP is whitelisted and cannot be banned.",
            "Protected IP",
            "OK",
            "Warning"
        )
        return
    }

    if (Add-IPBan -IP $IP) {

        Write-Log "MANUAL BAN: $IP"

        Add-BanNotification -IP $IP

        Update-IPLists

        [System.Windows.Forms.MessageBox]::Show(
            "$IP has been manually banned.",
            "AutoIPBan",
            "OK",
            "Information"
        )
    }
}

# MANUALLY ADD TO WHITELIST

function Add-ManualWhitelist {

    $IP = [Microsoft.VisualBasic.Interaction]::InputBox(
        "Enter the public IPv4 address you want to whitelist:",
        "Add IP to Whitelist",
        ""
    ).Trim()

    if ([string]::IsNullOrWhiteSpace($IP)) {
        return
    }

    Add-TrustedIP -IP $IP
}

# ============================================================
# MANAGEMENT BUTTONS
# ============================================================

# REMOVE WHITELIST

$removeWhitelistButton = New-Object System.Windows.Forms.Button
$removeWhitelistButton.Text = "REMOVE WHITELIST"
$removeWhitelistButton.Size = New-Object System.Drawing.Size(230,35)
$removeWhitelistButton.BackColor = [System.Drawing.Color]::FromArgb(70,55,55)
$removeWhitelistButton.ForeColor = [System.Drawing.Color]::White
$removeWhitelistButton.FlatStyle = "Flat"
$form.Controls.Add($removeWhitelistButton)

$removeWhitelistButton.Add_Click({

    if ($null -eq $whiteList.SelectedItem) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select an IP from the whitelist.",
            "Select IP",
            "OK",
            "Warning"
        )
        return
    }

    $selectedIP = ([string]$whiteList.SelectedItem) -replace '^\* ', ''

	Remove-TrustedIP -IP $selectedIP
})

# ADD WHITELIST

$addWhitelistButton = New-Object System.Windows.Forms.Button
$addWhitelistButton.Text = "ADD WHITELIST IP"
$addWhitelistButton.Size = New-Object System.Drawing.Size(230,35)
$addWhitelistButton.BackColor = [System.Drawing.Color]::FromArgb(30,90,55)
$addWhitelistButton.ForeColor = [System.Drawing.Color]::White
$addWhitelistButton.FlatStyle = "Flat"
$form.Controls.Add($addWhitelistButton)

$addWhitelistButton.Add_Click({
    Add-ManualWhitelist
})

# UNBAN

$unbanButton = New-Object System.Windows.Forms.Button
$unbanButton.Text = "UNBAN SELECTED IP"
$unbanButton.Size = New-Object System.Drawing.Size(180,35)
$unbanButton.BackColor = [System.Drawing.Color]::DarkGreen
$unbanButton.ForeColor = [System.Drawing.Color]::White
$unbanButton.FlatStyle = "Flat"
$form.Controls.Add($unbanButton)

$unbanButton.Add_Click({

    if ($null -eq $banList.SelectedItem) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select an IP from the banned list.",
            "Select IP",
            "OK",
            "Warning"
        )
        return
    }

    Remove-IPBan -IP ([string]$banList.SelectedItem)
})

# MANUAL BAN

$manualBanButton = New-Object System.Windows.Forms.Button
$manualBanButton.Text = "MANUALLY BAN IP"
$manualBanButton.Size = New-Object System.Drawing.Size(200,35)
$manualBanButton.BackColor = [System.Drawing.Color]::DarkRed
$manualBanButton.ForeColor = [System.Drawing.Color]::White
$manualBanButton.FlatStyle = "Flat"
$form.Controls.Add($manualBanButton)

$manualBanButton.Add_Click({
    Add-ManualBan
})

# BAN SELECTED IP FROM LIVE ACTIVITY

$banSelectedButton = New-Object System.Windows.Forms.Button
$banSelectedButton.Text = "BAN SELECTED IP"
$banSelectedButton.Size = New-Object System.Drawing.Size(180,35)
$banSelectedButton.BackColor = [System.Drawing.Color]::FromArgb(150,45,35)
$banSelectedButton.ForeColor = [System.Drawing.Color]::White
$banSelectedButton.FlatStyle = "Flat"

$form.Controls.Add($banSelectedButton)

$banSelectedButton.Add_Click({

    if ($grid.SelectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select a login event first.",
            "Select Event",
            "OK",
            "Warning"
        )
        return
    }

    $IP = [string]$grid.SelectedRows[0].Cells["SourceIP"].Value

    if (-not (Test-PublicIPv4 $IP)) {
        [System.Windows.Forms.MessageBox]::Show(
            "The selected event does not contain a valid public IPv4 address.",
            "Invalid IP",
            "OK",
            "Warning"
        )
        return
    }

    if (Test-TrustedIP $IP) {
        [System.Windows.Forms.MessageBox]::Show(
            "$IP is protected by the whitelist and cannot be banned.",
            "Protected IP",
            "OK",
            "Warning"
        )
        return
    }

    if ($State.Banned.ContainsKey($IP)) {
        [System.Windows.Forms.MessageBox]::Show(
            "$IP is already banned.",
            "Already Banned",
            "OK",
            "Information"
        )
        return
    }

    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Permanently ban $IP?",
        "Confirm Ban",
        "YesNo",
        "Warning"
    )

    if ($confirm -ne "Yes") {
        return
    }

    if (Add-IPBan -IP $IP) {

        Write-Log "MANUAL BAN FROM LIVE ACTIVITY: $IP"

        Add-BanNotification -IP $IP

        Update-GUIStatistics

        [System.Windows.Forms.MessageBox]::Show(
            "$IP has been banned successfully.",
            "AutoIPBan",
            "OK",
            "Information"
        )
    }
})

# EXPORT BUTTON

$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Text = "EXPORT LISTS"
$exportButton.Size = New-Object System.Drawing.Size(120,35)
$exportButton.BackColor = [System.Drawing.Color]::FromArgb(35,75,110)
$exportButton.ForeColor = [System.Drawing.Color]::White
$exportButton.FlatStyle = "Flat"
$form.Controls.Add($exportButton)

$exportButton.Add_Click({
    Export-IPLists
})

# IMPORT BUTTON

$importButton = New-Object System.Windows.Forms.Button
$importButton.Text = "IMPORT LISTS"
$importButton.Size = New-Object System.Drawing.Size(120,35)
$importButton.BackColor = [System.Drawing.Color]::FromArgb(30,90,55)
$importButton.ForeColor = [System.Drawing.Color]::White
$importButton.FlatStyle = "Flat"
$form.Controls.Add($importButton)

$importButton.Add_Click({
    Import-IPLists
})

# CLEAR ALL BANS BUTTON

$clearAllBansButton = New-Object System.Windows.Forms.Button
$clearAllBansButton.Text = "CLEAR ALL BANS"
$clearAllBansButton.Size = New-Object System.Drawing.Size(115,28)
$clearAllBansButton.BackColor = [System.Drawing.Color]::FromArgb(150,25,25)
$clearAllBansButton.ForeColor = [System.Drawing.Color]::White
$clearAllBansButton.FlatStyle = "Flat"

$form.Controls.Add($clearAllBansButton)

$clearAllBansButton.Add_Click({
    Clear-AllBans
})

# ============================================================
# STATISTICS
# ============================================================

function Update-GUIStatistics {

    $failedLabel.Text = "FAILED LOGINS: $script:TotalFailures"
    $successLabel.Text = "SUCCESSFUL LOGINS: $script:TotalSuccesses"
    $banLabel.Text = "ACTIVE BANS: $($State.Banned.Count)"

    $thresholdLabel.Text = "BAN AFTER: $Threshold FAILS / $(Get-WindowDisplay)"

    Update-IPLists
}


# ============================================================
# LIVE BAN SETTINGS WINDOW
# ============================================================

function Open-BanSettings {

    $settingsForm = New-Object System.Windows.Forms.Form
    $settingsForm.Text = "AutoIPBan Settings"
    $settingsForm.Size = New-Object System.Drawing.Size(380,440)
    $settingsForm.StartPosition = "CenterParent"
    $settingsForm.FormBorderStyle = "FixedDialog"
    $settingsForm.MaximizeBox = $false
    $settingsForm.BackColor = [System.Drawing.Color]::FromArgb(20,27,38)
    $settingsForm.ForeColor = [System.Drawing.Color]::White

    $label1 = New-GUILabel "Failed attempts before ban:" 20 20 320 25 11
    $settingsForm.Controls.Add($label1)

    $thresholdInput = New-Object System.Windows.Forms.NumericUpDown
    $thresholdInput.Location = New-Object System.Drawing.Point(20,50)
    $thresholdInput.Size = New-Object System.Drawing.Size(320,30)
    $thresholdInput.Minimum = 1
    $thresholdInput.Maximum = 1000
    $thresholdInput.Value = $Threshold
    $settingsForm.Controls.Add($thresholdInput)

    $label2 = New-GUILabel "Detection window (minutes):" 20 95 320 25 11
    $settingsForm.Controls.Add($label2)

    $windowInput = New-Object System.Windows.Forms.NumericUpDown
    $windowInput.Location = New-Object System.Drawing.Point(20,125)
    $windowInput.Size = New-Object System.Drawing.Size(320,30)
    $windowInput.Minimum = 1
    $windowInput.Maximum = 10080
    $windowInput.Value = $WindowMinutes
    $settingsForm.Controls.Add($windowInput)
	
	# FIREWALL AUDIT FREQUENCY

	$label3 = New-GUILabel "Firewall audit frequency (minutes):" 20 165 320 25 11
	$settingsForm.Controls.Add($label3)

	$auditFrequencyInput = New-Object System.Windows.Forms.NumericUpDown
	$auditFrequencyInput.Location = New-Object System.Drawing.Point(20,195)
	$auditFrequencyInput.Size = New-Object System.Drawing.Size(320,30)
	$auditFrequencyInput.Minimum = 1
	$auditFrequencyInput.Maximum = 1440
	$auditFrequencyInput.Value = $FirewallAuditMinutes
	$settingsForm.Controls.Add($auditFrequencyInput)

	# INITIAL FIREWALL AUDIT DELAY

	$label4 = New-GUILabel "Initial firewall audit delay (minutes):" 20 235 320 25 11
	$settingsForm.Controls.Add($label4)

	$initialDelayInput = New-Object System.Windows.Forms.NumericUpDown
	$initialDelayInput.Location = New-Object System.Drawing.Point(20,265)
	$initialDelayInput.Size = New-Object System.Drawing.Size(320,30)
	$initialDelayInput.Minimum = 1
	$initialDelayInput.Maximum = 1000
	$initialDelayInput.Value = $InitialAuditDelay
	$settingsForm.Controls.Add($initialDelayInput)

    $saveButton = New-Object System.Windows.Forms.Button
    $saveButton.Text = "SAVE SETTINGS"
    $saveButton.Location = New-Object System.Drawing.Point(20,345)
    $saveButton.Size = New-Object System.Drawing.Size(150,35)
    $saveButton.BackColor = [System.Drawing.Color]::FromArgb(30,90,55)
    $saveButton.ForeColor = [System.Drawing.Color]::White
    $saveButton.FlatStyle = "Flat"
    $settingsForm.Controls.Add($saveButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "CANCEL"
    $cancelButton.Location = New-Object System.Drawing.Point(190,345)
    $cancelButton.Size = New-Object System.Drawing.Size(150,35)
    $cancelButton.BackColor = [System.Drawing.Color]::FromArgb(70,55,55)
    $cancelButton.ForeColor = [System.Drawing.Color]::White
    $cancelButton.FlatStyle = "Flat"
    $settingsForm.Controls.Add($cancelButton)

    $saveButton.Add_Click({

        $script:Threshold = [int]$thresholdInput.Value
        $script:WindowMinutes = [int]$windowInput.Value

		$script:FirewallAuditMinutes = [int]$auditFrequencyInput.Value
		$script:InitialAuditDelay = [int]$initialDelayInput.Value

		$State.Settings = @{
			Threshold = $script:Threshold
			WindowMinutes = $script:WindowMinutes
			FirewallAuditMinutes = $script:FirewallAuditMinutes
			InitialAuditDelay = $script:InitialAuditDelay
		}

        Save-State
        Update-GUIStatistics

        Write-Log "SETTINGS UPDATED: THRESHOLD=$Threshold WINDOW=$WindowMinutes MINUTES"

        $settingsForm.Close()
    })

    $cancelButton.Add_Click({
        $settingsForm.Close()
    })

    [void]$settingsForm.ShowDialog($form)
}

# ============================================================
# RESPONSIVE LAYOUT
# ============================================================

function Set-GUILayout {

    $clientWidth = $form.ClientSize.Width
    $clientHeight = $form.ClientSize.Height

	$margin = 25
	$gap = 20

    # WHITELIST GETS LESS WIDTH
    # BAN LIST GETS MORE WIDTH

    $whiteWidth = [int](($clientWidth - ($margin * 2) - $gap) * 0.424)
    $banWidth = $clientWidth - ($margin * 2) - $gap - $whiteWidth

    $rightX = $margin + $whiteWidth + $gap

    $whiteTitle.Location = New-Object System.Drawing.Point($margin,145)
    $whiteTitle.Size = New-Object System.Drawing.Size($whiteWidth,25)

	$banTitle.Location = New-Object System.Drawing.Point($rightX,145)
	$banTitle.Size = New-Object System.Drawing.Size(($banWidth - 165),25)

	# CLEAR ALL BANS - BESIDE BAN LIST HEADING

	$clearAllBansButton.Location = New-Object System.Drawing.Point(
		($rightX + $banWidth - 120),140
	)
	
	# SETTINGS - RIGHT ANCHORED

	$settingsButton.Location = New-Object System.Drawing.Point(
		($clientWidth - $margin - $settingsButton.Width),
		20
	)
	
    $whiteList.Location = New-Object System.Drawing.Point($margin,175)
    $whiteList.Size = New-Object System.Drawing.Size($whiteWidth,140)

    $banList.Location = New-Object System.Drawing.Point($rightX,175)
    $banList.Size = New-Object System.Drawing.Size($banWidth,140)

	# WHITELIST BUTTONS

	$removeWhitelistButton.Location = New-Object System.Drawing.Point($margin,318)

	$addWhitelistButton.Location = New-Object System.Drawing.Point(
		($margin + 240),318
	)

    # BAN BUTTONS

    $unbanButton.Location = New-Object System.Drawing.Point($rightX,318)

    $manualBanButton.Location = New-Object System.Drawing.Point(
        ($rightX + 190),318
    )
	
	# FOOTER

	$toggleButton.Location = New-Object System.Drawing.Point(
		$margin,($clientHeight - 65)
	)

	# LOG LABEL - LEAVE ROOM FOR BAN SELECTED BUTTON

	$banSelectedButton.Location = New-Object System.Drawing.Point(
		($clientWidth - $margin - 190),
		($clientHeight - 65)
	)
	
	# RUNTIME DISPLAY - LEFT OF BAN SELECTED BUTTON

	$runtimeLabel.Location = New-Object System.Drawing.Point(
		($banSelectedButton.Left - 200),
		($clientHeight - 58)
	)

	$runtimeLabel.Size = New-Object System.Drawing.Size(200,30)
	$runtimeLabel.BringToFront()

	$logLabel.Location = New-Object System.Drawing.Point(
		270,($clientHeight - 55)
	)

	$logLabel.Width = [Math]::Max(
		200,
		($banSelectedButton.Left - 285)
	)
	
	# IMPORT / EXPORT BUTTONS - RIGHT ANCHORED

	$importButton.Location = New-Object System.Drawing.Point(
		($clientWidth - $margin - 120),318
	)

	$exportButton.Location = New-Object System.Drawing.Point(
		($importButton.Left - 130),318
	)

    # LIVE ACTIVITY

    $feedTitle.Location = New-Object System.Drawing.Point($margin,365)

    $grid.Location = New-Object System.Drawing.Point($margin,400)

    $grid.Size = New-Object System.Drawing.Size(
        ($clientWidth - ($margin * 2)),
        [Math]::Max(150,($clientHeight - 500))
    )

    # FOOTER

    $toggleButton.Location = New-Object System.Drawing.Point(
        $margin,($clientHeight - 65)
    )

    $logLabel.Location = New-Object System.Drawing.Point(
        270,($clientHeight - 55)
    )
}

$form.Add_Resize({
    Set-GUILayout
})

# ============================================================
# EVENT PROCESSING
# ============================================================

function Process-Event {
    param($Event)

    $xml = [xml]$Event.ToXml()
    $data = @{}

    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = $item.InnerText
    }

    $eventID = [int]$xml.Event.System.EventID
    $type = [string]$data["LogonType"]
    $ip = [string]$data["IpAddress"]
    $username = [string]$data["TargetUserName"]

    if ($type -notin $LogonTypes) {
        return
    }

    if (-not (Test-PublicIPv4 $ip)) {
        return
    }

    $isTrusted = Test-TrustedIP $ip

    # SUCCESSFUL LOGIN

    if ($eventID -eq 4624) {

        $script:TotalSuccesses++

        Add-LoginFeed `
            -Time $Event.TimeCreated.ToString("HH:mm:ss") `
            -EventID 4624 `
            -IP $ip `
            -Username $username `
            -LogonType $type

        if ($State.Failures.ContainsKey($ip)) {

            $State.Failures.Remove($ip)

            Write-Log "SUCCESSFUL LOGIN - COUNTER RESET: IP=$ip USER=$username TYPE=$type"

            Save-State
        }

        return
    }

    # FAILED LOGIN

    if ($eventID -ne 4625) {
        return
    }

# SHOW WHITELISTED FAILED LOGINS BUT NEVER BAN THEM

if ($isTrusted) {

    Add-LoginFeed `
        -Time $Event.TimeCreated.ToString("HH:mm:ss") `
        -EventID 4625 `
        -IP $ip `
        -Username $username `
        -LogonType $type `
        -Failures "WHITELISTED"

    return
}

    if ($State.Banned.ContainsKey($ip)) {
        return
    }

    $eventTime = $Event.TimeCreated
    $cutoff = $eventTime.AddMinutes(-$WindowMinutes)

    if (-not $State.Failures.ContainsKey($ip)) {
        $State.Failures[$ip] = @()
    }

    $recent = @(
        $State.Failures[$ip] |
        Where-Object {
            $_ -gt $cutoff -and $_ -le $eventTime
        }
    )

    $recent += $eventTime
    $State.Failures[$ip] = $recent

    $count = $recent.Count

    $script:TotalFailures++

    $failureDisplay = "$count/$Threshold"

    $row = Add-LoginFeed `
        -Time $eventTime.ToString("HH:mm:ss") `
        -EventID 4625 `
        -IP $ip `
        -Username $username `
        -LogonType $type `
        -Failures $failureDisplay

    Write-Log "FAILED LOGIN: IP=$ip USER=$username TYPE=$type COUNT=$count/$Threshold"

    # BAN THRESHOLD

    if ($count -ge $Threshold) {

        if (Add-IPBan -IP $ip) {

            Write-Log "BAN TRIGGERED BY EVENT 4625: $ip"

            $row.Cells["Status"].Value = "BANNED!!!"
            $row.Cells["Failures"].Value = "BANNED!!!"

            $row.DefaultCellStyle.ForeColor =
                [System.Drawing.Color]::Red

            Add-BanNotification -IP $ip

            if ($State.Failures.ContainsKey($ip)) {
                $State.Failures.Remove($ip)
            }
        }
    }

    Save-State
}

# ============================================================
# START / STOP BUTTON
# ============================================================

$toggleButton = New-Object System.Windows.Forms.Button
$toggleButton.Text = "STOP MONITORING"
$toggleButton.Size = New-Object System.Drawing.Size(220,45)
$toggleButton.BackColor = [System.Drawing.Color]::DarkRed
$toggleButton.ForeColor = [System.Drawing.Color]::White
$toggleButton.FlatStyle = "Flat"

$toggleButton.Font = New-Object System.Drawing.Font(
    "Segoe UI",10,[System.Drawing.FontStyle]::Bold
)

$form.Controls.Add($toggleButton)

$logLabel = New-GUILabel "LOG: $LogFile" 270 670 850 25 9
$logLabel.ForeColor = [System.Drawing.Color]::Silver
$form.Controls.Add($logLabel)

# RUNTIME DISPLAY

$script:StartTime = Get-Date

$runtimeLabel = New-GUILabel "RUNTIME: 00:00:00" 900 670 200 25 11
$runtimeLabel.ForeColor = [System.Drawing.Color]::Silver
$runtimeLabel.Font = New-Object System.Drawing.Font(
    "Segoe UI",10,[System.Drawing.FontStyle]::Bold
)

$form.Controls.Add($runtimeLabel)

# RUNTIME UPDATE TIMER

$script:RuntimeTimer = New-Object System.Windows.Forms.Timer
$script:RuntimeTimer.Interval = 1000

$script:RuntimeTimer.Add_Tick({

    $elapsed = (Get-Date) - $script:StartTime

    $runtimeLabel.Text = "RUNTIME: {0:D2}:{1:D2}:{2:D2}" -f `
        [int]$elapsed.TotalHours,
        $elapsed.Minutes,
        $elapsed.Seconds

})

$script:RuntimeTimer.Start()

$toggleButton.Add_Click({

    if ($script:Monitoring) {

        $script:Monitoring = $false

        $toggleButton.Text = "START MONITORING"
        $toggleButton.BackColor = [System.Drawing.Color]::DarkGreen

        $status.Text = "MONITORING PAUSED"
        $status.ForeColor = [System.Drawing.Color]::Orange

        Write-Log "MONITORING PAUSED BY USER."

    }
    else {

        $script:Monitoring = $true

        $toggleButton.Text = "STOP MONITORING"
        $toggleButton.BackColor = [System.Drawing.Color]::DarkRed

        $status.Text = "PROTECTION ACTIVE"
        $status.ForeColor = [System.Drawing.Color]::LimeGreen

        Write-Log "MONITORING RESUMED BY USER."
    }
})

# ============================================================
# STARTUP AND MONITORING
# ============================================================

try {

    Initialize-State

	# SCHEDULE FIRST FIREWALL AUDIT

	$script:FirewallAuditResult = "PENDING"

	$script:NextFirewallAudit = (
		Get-Date
	).AddMinutes($InitialAuditDelay)

	Update-FirewallAuditDisplay

	Write-Log "INITIAL FIREWALL AUDIT SCHEDULED IN $InitialAuditDelay MINUTES."

    Write-Log "AUTOBAN GUI SERVICE STARTED."

    Update-IPLists
    Update-GUIStatistics
    Set-GUILayout

    # WINDOWS FORMS TIMER

    $script:MonitorTimer = New-Object System.Windows.Forms.Timer
    $script:MonitorTimer.Interval = $PollSeconds * 1000

    $script:MonitorTimer.Add_Tick({

		try {

	# UPDATE FIREWALL AUDIT COUNTDOWN

	Update-FirewallAuditDisplay

	# PERIODIC FIREWALL AUDIT

	if ((Get-Date) -ge $script:NextFirewallAudit) {

			$script:NextFirewallAudit = (
				Get-Date
			).AddMinutes($FirewallAuditMinutes)

			Audit-FirewallBans
		}

        # PAUSE LOGIN EVENT MONITORING ONLY

        if (-not $script:Monitoring) {
            return
        }


            $lastId = [long]$State.LastRecordId

            $xpath = "*[System[(EventID=4625 or EventID=4624) and (EventRecordID > $lastId)]]"

            $events = @(
                Get-WinEvent `
                    -LogName Security `
                    -FilterXPath $xpath `
                    -MaxEvents $BatchSize `
                    -ErrorAction SilentlyContinue |
                Sort-Object RecordId
            )

            foreach ($event in $events) {

                Process-Event -Event $event

                $State.LastRecordId = [long]$event.RecordId

                Save-State
            }

            # PRUNE EXPIRED FAILURE TIMESTAMPS

            $now = Get-Date

            foreach ($ip in @($State.Failures.Keys)) {

                $cutoff = $now.AddMinutes(-$WindowMinutes)

                $State.Failures[$ip] = @(
                    $State.Failures[$ip] |
                    Where-Object { $_ -gt $cutoff }
                )

                if ($State.Failures[$ip].Count -eq 0) {
                    $State.Failures.Remove($ip)
                }
            }

            # RETAIN LAST 30 DAYS OF HISTORY

            $historyCutoff = (Get-Date).AddDays(-$HistoryDays)

            $State.BanHistory = @(
                $State.BanHistory |
                Where-Object { $_.Date -ge $historyCutoff }
            )

            Save-State
            Update-GUIStatistics

        }
        catch {
            Write-Log "MONITOR ERROR: $_"
        }
    })

    $script:Monitoring = $true

    # START TIMER

    $script:MonitorTimer.Start()

    # CLOSE WINDOW

	$form.Add_FormClosing({

		$script:Monitoring = $false

		$script:MonitorTimer.Stop()
		$script:RuntimeTimer.Stop()

		Save-State

		Write-Log "AUTOBAN GUI SERVICE STOPPED."
	})

    # DISPLAY GUI

    [System.Windows.Forms.Application]::Run($form)
	
	# RELEASE SINGLE INSTANCE PROTECTION

	if ($null -ne $script:InstanceMutex) {

		try {
			$script:InstanceMutex.ReleaseMutex()
		}
		catch {}

		$script:InstanceMutex.Dispose()

		$script:InstanceMutex = $null
	}

}

catch {

    Write-Log "FATAL ERROR: $_"

    Write-Host "FATAL ERROR: $_" -ForegroundColor Red
	
	# RELEASE SINGLE INSTANCE PROTECTION

	if ($null -ne $script:InstanceMutex) {

		try {
			$script:InstanceMutex.ReleaseMutex()
		}
		catch {}

		$script:InstanceMutex.Dispose()

		$script:InstanceMutex = $null
	}

    Read-Host "Press ENTER to close"
}
