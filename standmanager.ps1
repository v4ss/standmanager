#requires -Version 5.1

<#
.SYNOPSIS
    StandManager - Outil de collecte forensique et de durcissement pour postes Windows isoles.

.DESCRIPTION
    Application PowerShell unique, conçue pour s'executer depuis une cle USB.
    Elle propose un menu interactif et un mode CLI permettant :
      - le durcissement par desactivation guidee de services Windows superflus ;
      - la restauration de l'etat des services a partir d'une sauvegarde CSV ;
      - l'export des journaux Windows (EVTX) avec empreintes SHA-256 ;
      - l'export recursif des logs AV ;
      - un audit systeme (OS, pare-feu, BitLocker, AV, correctifs, admins) ;
      - une analyse differentielle (services, processus, reseau, taches) ;
      - l'archivage des donnees collectees et leur depot sur un partage reseau.

.PARAMETER Action
    Action a executer directement (Triage, Restore, Export, Hayabusa, Save, Dashboard, Quit).
    Hayabusa lance une analyse de rattrapage sur le repertoire d'un poste deja exporte.
    Si omis et que -Interactive est absent, le menu interactif est lance par defaut.

.PARAMETER Interactive
    Force l'affichage du menu interactif, meme si -Action est fourni.

.PARAMETER Analyze
    Lance systematiquement l'analyse Hayabusa apres l'export EVTX.

.PARAMETER NoAnalyze
    Desactive l'analyse Hayabusa apres l'export EVTX.
    Si ni -Analyze ni -NoAnalyze n'est specifie, l'utilisateur est interroge apres l'export pour choisir.

.PARAMETER SIName
    Nom du systeme d'information cible (ex. SI03). Pre-remplit le contexte d'export.

.PARAMETER ComputerName
    Nom du poste cible (ex. LAP-001). Pre-remplit le contexte d'export.

.PARAMETER CreateBaseline
    Cree automatiquement toutes les baselines manquantes sans interroger l'utilisateur.

.EXAMPLE
    .\standmanager.ps1 -Interactive

.EXAMPLE
    .\standmanager.ps1 -Action Export -SIName SI03 -ComputerName LAP-001 -Analyze

.EXAMPLE
    .\standmanager.ps1 -Action Save -SIName SI03

.EXAMPLE
    .\standmanager.ps1 -Action Hayabusa -SIName SI03 -ComputerName LAP-001

.EXAMPLE
    .\standmanager.ps1 -Action Dashboard
#>

[CmdletBinding()]
param (
    [ValidateSet('Triage','Restore','Export','Hayabusa','Save','Dashboard','Quit')]
    [string]$Action,

    [switch]$Interactive,
    [switch]$Analyze,
    [switch]$NoAnalyze,
    [string]$SIName,
    [string]$ComputerName,
    [switch]$CreateBaseline
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:AppName       = 'StandManager'
$Script:AppVersion    = '2.4.0'
$Script:ScriptRoot    = $PSScriptRoot
$Script:ConfigPath    = Join-Path -Path $Script:ScriptRoot -ChildPath 'standmanager.config.json'
$Script:LogPath       = Join-Path -Path $Script:ScriptRoot -ChildPath 'standmanager.log'
$Script:Config        = $null

# Services critiques que l'on refuse de desactiver, quelle que soit la reponse de l'utilisateur.
$Script:CriticalServices = @(
    'WinDefend','SecurityHealthService','wuauserv','MpsSvc','EventLog','RpcSs',
    'RpcEptMapper','DcomLaunch','LSM','PlugPlay','Schedule','BFE','CryptSvc',
    'Dnscache','LanmanWorkstation','Netman','NlaSvc','nsi','Power','ProfSvc'
)

# ============================================================================
# region Utilitaires de base
# ============================================================================

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-IsAdministrator)) {
        Write-StandLog "Privileges administrateur requis pour cette operation." -Level 'ERROR'
        Write-Host ''
        Write-Host "Cette action necessite les privileges administrateur." -ForegroundColor Red
        Write-Host "Fermez puis relancez le script via 'Executer en tant qu''administrateur'." -ForegroundColor Yellow
        throw 'Privileges administrateur requis.'
    }
}

function Confirm-Directory {
    param (
        [Parameter(Mandatory)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Write-StandLog {
    param (
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG','OK')]
        [string]$Level = 'INFO',
        [switch]$Quiet
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "$timestamp [$Level] $Message"

    try {
        Add-Content -LiteralPath $Script:LogPath -Value $entry -Encoding UTF8 -ErrorAction Stop
    } catch {
        # Impossible d'ecrire dans le fichier de log : on n'interrompt pas le script.
    }

    if ($Quiet) { return }

    switch ($Level) {
        'ERROR' { Write-Host $entry -ForegroundColor Red }
        'WARN'  { Write-Host $entry -ForegroundColor Yellow }
        'OK'    { Write-Host $entry -ForegroundColor Green }
        'DEBUG' { Write-Verbose $entry }
        default { Write-Host $entry }
    }
}

function Read-YesNoChoice {
    param (
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('O','N')][string]$Default = 'O'
    )

    $suffix = if ($Default -eq 'O') { '[O/n]' } else { '[o/N]' }
    while ($true) {
        $response = Read-Host "$Message $suffix"
        if ([string]::IsNullOrWhiteSpace($response)) { $response = $Default }
        switch -Regex ($response.Trim().ToUpper()) {
            '^(O|OUI|Y|YES)$' { return $true }
            '^(N|NON|NO)$'    { return $false }
            default { Write-Host "Reponse invalide. Tapez O ou N." -ForegroundColor Yellow }
        }
    }
}

function Read-NonEmptyString {
    param (
        [Parameter(Mandatory)][string]$Prompt,
        [string]$Default
    )
    while ($true) {
        $value = Read-Host $Prompt
        if ([string]::IsNullOrWhiteSpace($value) -and $Default) { return $Default }
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value.Trim() }
        Write-Host "Une valeur est requise." -ForegroundColor Yellow
    }
}

function Get-SafeName {
    param ([Parameter(Mandatory)][string]$Name)
    $invalid = [IO.Path]::GetInvalidFileNameChars() + @(' ', '\', '/', ':', '*', '?', '"', '<', '>', '|')
    $clean = $Name
    foreach ($c in $invalid) { $clean = $clean.Replace([string]$c, '_') }
    return $clean.Trim('_')
}

function Format-DisplayDateTime {
    # Affichage francais jj/MM/aaaa HH:mm:ss, independant de la culture de la
    # machine (evite l'affichage en MM/jj/aaaa sur les postes en culture en-US).
    param ([Parameter(Mandatory)][DateTime]$Value)
    return $Value.ToString('dd/MM/yyyy HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Write-Banner {
    param ([Parameter(Mandatory)][string]$Title)
    $bar = '=' * 70
    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan
    Write-Host (' {0,-68} ' -f $Title) -ForegroundColor Cyan
    Write-Host $bar -ForegroundColor Cyan
}

# ============================================================================
# region Configuration et initialisation
# ============================================================================

function Get-DefaultConfig {
    return [ordered]@{
        AVLogsPath      = 'C:\ProgramData\McAfee\Endpoint Security\Logs'
        HayabusaRelativePath = 'hayabusa-3.7.0-win-x86\hayabusa-3.7.0-win-x86.exe'
        SaveDestination      = 'L:\RSSI\SI-ISOLES\LOGS'
        CompressionLevel     = 'Optimal'
        HayabusaProfile      = 'standard'
        EventLogs            = @('System','Application','Setup','Security')
    }
}

function Import-StandManagerConfig {
    $defaults = Get-DefaultConfig

    if (-not (Test-Path -LiteralPath $Script:ConfigPath)) {
        ($defaults | ConvertTo-Json -Depth 4) | Out-File -FilePath $Script:ConfigPath -Encoding UTF8 -Force
        Write-StandLog "Fichier de configuration cree : $Script:ConfigPath" -Level 'INFO' -Quiet
        return [PSCustomObject]$defaults
    }

    try {
        $raw = Get-Content -LiteralPath $Script:ConfigPath -Raw -Encoding UTF8
        $cfg = $raw | ConvertFrom-Json
    } catch {
        Write-StandLog "Impossible de lire la configuration ($_). Utilisation des valeurs par defaut." -Level 'WARN'
        return [PSCustomObject]$defaults
    }

    foreach ($key in $defaults.Keys) {
        if (-not ($cfg.PSObject.Properties.Name -contains $key)) {
            $cfg | Add-Member -MemberType NoteProperty -Name $key -Value $defaults[$key] -Force
        }
    }

    return $cfg
}

function Initialize-StandManager {
    Confirm-Directory -Path $Script:ScriptRoot
    if (-not (Test-Path -LiteralPath $Script:LogPath)) {
        '' | Out-File -FilePath $Script:LogPath -Encoding UTF8 -Force
    }
    $Script:Config = Import-StandManagerConfig
    Write-StandLog "$Script:AppName v$Script:AppVersion demarre. Admin=$((Test-IsAdministrator))." -Level 'INFO' -Quiet
}

function Get-DriveRoot {
    return Split-Path -Path $Script:ScriptRoot -Qualifier
}

function Get-HayabusaPath {
    if (-not $Script:Config.HayabusaRelativePath) { return $null }
    $path = Join-Path -Path $Script:ScriptRoot -ChildPath $Script:Config.HayabusaRelativePath
    if (Test-Path -LiteralPath $path) { return $path }
    return $null
}

function Get-OperationContext {
    param (
        [string]$SIName,
        [string]$ComputerName
    )

    if (-not $SIName)       { $SIName       = Read-NonEmptyString -Prompt "Nom du systeme d'information (ex. SI03)" }
    if (-not $ComputerName) { $ComputerName = Read-NonEmptyString -Prompt 'Nom du poste (ex. LAP-001)' -Default $env:COMPUTERNAME }

    return [PSCustomObject]@{
        SIName       = Get-SafeName -Name $SIName
        ComputerName = Get-SafeName -Name $ComputerName
    }
}

function Get-SaveOperationContext {
    param (
        [string]$SIName
    )

    if (-not $SIName)       { $SIName       = Read-NonEmptyString -Prompt "Nom du systeme d'information (ex. SI03)" }

    return [PSCustomObject]@{
        SIName       = Get-SafeName -Name $SIName
    }
}

function Resolve-ComputerExportPath {
    param (
        [Parameter(Mandatory)][string]$BasePath,
        [Parameter(Mandatory)][string]$SIName,
        [Parameter(Mandatory)][string]$ComputerName
    )
    $path = Join-Path -Path (Join-Path -Path $BasePath -ChildPath $SIName) -ChildPath $ComputerName
    Confirm-Directory -Path $path
    return $path
}

# ============================================================================
# region Export des journaux d'evenements Windows
# ============================================================================

function Get-LastExportTimestamp {
    param ([Parameter(Mandatory)][string]$ComputerPath)

    $file = Join-Path -Path $ComputerPath -ChildPath 'last_export.txt'
    if (-not (Test-Path -LiteralPath $file)) { return $null }

    $text = (Get-Content -LiteralPath $file -ErrorAction SilentlyContinue | Select-Object -First 1)
    if (-not $text) { return $null }

    try {
        return [DateTime]::ParseExact($text.Trim(), 'yyyy-MM-dd HH:mm:ss', $null)
    } catch {
        Write-StandLog "Format invalide dans last_export.txt : '$text'. Export complet realise." -Level 'WARN'
        return $null
    }
}

function Save-LastExportTimestamp {
    param ([Parameter(Mandatory)][string]$ComputerPath)
    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $file = Join-Path -Path $ComputerPath -ChildPath 'last_export.txt'
    $now | Out-File -FilePath $file -Encoding UTF8 -Force
    return $now
}

function Invoke-WevtutilExport {
    param (
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][string]$FilePath,
        [Nullable[DateTime]]$Since
    )

    $argsList = @('epl', $LogName, $FilePath, '/ow:true')
    if ($Since) {
        $xmlDate = $Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        $query = "*[System[TimeCreated[@SystemTime>='$xmlDate']]]"
        $argsList += "/q:$query"
    }
    & wevtutil.exe @argsList
    if ($LASTEXITCODE -ne 0) {
        throw "wevtutil a renvoye le code $LASTEXITCODE pour le journal $LogName."
    }
}

function Export-WindowsEventLogs {
    param (
        [Parameter(Mandatory)][string]$BasePath,
        [Parameter(Mandatory)][string]$SIName,
        [Parameter(Mandatory)][string]$ComputerName
    )

    Assert-Administrator

    $computerPath = Resolve-ComputerExportPath -BasePath $BasePath -SIName $SIName -ComputerName $ComputerName
    $logNames = @($Script:Config.EventLogs)
    if (-not $logNames -or $logNames.Count -eq 0) {
        $logNames = @('System','Application','Setup','Security')
    }

    $lastExport = Get-LastExportTimestamp -ComputerPath $computerPath
    if ($lastExport) {
        Write-Host "Derniere exportation detectee : $(Format-DisplayDateTime $lastExport). Export incremental." -ForegroundColor Cyan
    } else {
        Write-Host "Aucune exportation precedente. Export complet." -ForegroundColor Cyan
    }

    $exported = @()
    $hashReport = @()
    $i = 0

    foreach ($log in $logNames) {
        $i++
        Write-Progress -Activity 'Export des journaux Windows' `
            -Status "$log ($i/$($logNames.Count))" `
            -PercentComplete (($i / $logNames.Count) * 100)

        $fileName = "{0}-{1}.evtx" -f $log, (Get-Date -Format 'yyyyMMdd-HHmmss')
        $filePath = Join-Path -Path $computerPath -ChildPath $fileName

        try {
            Invoke-WevtutilExport -LogName $log -FilePath $filePath -Since $lastExport

            if (Test-Path -LiteralPath $filePath) {
                $hash = Get-FileHash -LiteralPath $filePath -Algorithm SHA256
                $exported += $filePath
                $hashReport += [PSCustomObject]@{
                    FilePath = $filePath
                    SHA256   = $hash.Hash
                    SizeKB   = [math]::Round((Get-Item -LiteralPath $filePath).Length / 1KB, 2)
                    Date     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                }
                Write-Host (" - {0,-12} OK  ({1} KB)  {2}" -f $log, $hashReport[-1].SizeKB, $hash.Hash) -ForegroundColor Green
            } else {
                Write-Host " - $log : fichier introuvable apres export." -ForegroundColor Yellow
                Write-StandLog "Export $log : fichier $filePath introuvable." -Level 'WARN'
            }
        } catch {
            Write-Host " - $log : ERREUR ($_)" -ForegroundColor Red
            Write-StandLog "Erreur export $log : $_" -Level 'ERROR'
        }
    }
    Write-Progress -Activity 'Export des journaux Windows' -Completed

    $exportTime = Save-LastExportTimestamp -ComputerPath $computerPath

    # Rapport texte d'export, immuable par convention
    $reportPath = Join-Path -Path $computerPath -ChildPath ("Rapport_Export_{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $header = @(
        "Rapport d'exportation des journaux Windows",
        "-------------------------------------------",
        "Date          : $exportTime",
        "Utilisateur   : $env:USERNAME",
        "Hote          : $env:COMPUTERNAME",
        "SI            : $SIName",
        "Poste         : $ComputerName",
        "Export depuis : $(if ($lastExport) { Format-DisplayDateTime $lastExport } else { 'export complet' })",
        ""
        "Fichiers exportes (chemin : SHA-256) :"
    )
    $lines = $hashReport | ForEach-Object { " - {0} : {1}" -f $_.FilePath, $_.SHA256 }
    ($header + $lines) | Out-File -FilePath $reportPath -Encoding UTF8 -Force
    Write-StandLog "Rapport d'export genere : $reportPath" -Level 'OK'

    # Manifest CSV pour verification d'integrite ulterieure
    $manifestPath = Join-Path -Path $computerPath -ChildPath 'export_manifest.csv'
    $hashReport | Export-Csv -Path $manifestPath -NoTypeInformation -Encoding UTF8 -Force

    # Analyse Hayabusa
    $doAnalyze = if ($Analyze)        { $true }
                 elseif ($NoAnalyze)  { $false }
                 else                 { Read-YesNoChoice -Message 'Voulez-vous analyser les logs avec Hayabusa ?' -Default 'O' }

    if ($doAnalyze) {
        Invoke-HayabusaAnalysis -ComputerPath $computerPath -SIName $SIName -ComputerName $ComputerName
    }

    return [PSCustomObject]@{
        ExportedLogs = $exported
        HashReport   = $hashReport
        ReportPath   = $reportPath
    }
}

function Get-AnalysisOutputPath {
    param (
        [Parameter(Mandatory)][string]$ComputerPath,
        [Parameter(Mandatory)][string]$SIName,
        [Parameter(Mandatory)][string]$ComputerName
    )
    return Join-Path -Path $ComputerPath -ChildPath ("Analyse_{0}_{1}.csv" -f $SIName, $ComputerName)
}

function Invoke-HayabusaAnalysis {
    param (
        [Parameter(Mandatory)][string]$ComputerPath,
        [Parameter(Mandatory)][string]$SIName,
        [Parameter(Mandatory)][string]$ComputerName
    )

    $hayabusa = Get-HayabusaPath
    if (-not $hayabusa) {
        Write-Host "Hayabusa introuvable ($($Script:Config.HayabusaRelativePath)). Analyse ignoree." -ForegroundColor Yellow
        Write-StandLog "Hayabusa absent : analyse non executee." -Level 'WARN'
        return
    }

    $hayProfile = if ($Script:Config.HayabusaProfile) { $Script:Config.HayabusaProfile } else { 'standard' }
    $output     = Get-AnalysisOutputPath -ComputerPath $ComputerPath -SIName $SIName -ComputerName $ComputerName

    Write-Host "Analyse Hayabusa en cours (profil $hayProfile)..." -ForegroundColor Cyan
    try {
        & $hayabusa csv-timeline -d $ComputerPath -o $output --profile $hayProfile -q -w
        if (Test-Path -LiteralPath $output) {
            Write-Host "Analyse terminee. Rapport : $output" -ForegroundColor Green
            Write-StandLog "Analyse Hayabusa OK : $output" -Level 'OK'
        } else {
            Write-Host "Hayabusa n'a produit aucun rapport." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Erreur Hayabusa : $_" -ForegroundColor Red
        Write-StandLog "Erreur Hayabusa : $_" -Level 'ERROR'
    }
}

function Invoke-StandaloneAnalysis {
    <#
        Analyse Hayabusa de rattrapage : relance une analyse sur le repertoire
        d'un poste deja exporte (cas ou l'on a repondu "non" a l'analyse lors
        de l'export). N'exporte aucun journal et ne cree pas de repertoire.
    #>
    param (
        [Parameter(Mandatory)][string]$BasePath
    )

    Write-Banner -Title 'ANALYSE HAYABUSA D''UN POSTE (RATTRAPAGE)'

    # Inutile de demander quoi que ce soit si Hayabusa n'est pas disponible.
    $hayabusa = Get-HayabusaPath
    if (-not $hayabusa) {
        Write-Host "Hayabusa introuvable ($($Script:Config.HayabusaRelativePath))." -ForegroundColor Red
        Write-Host "Placez Hayabusa a cote du script ou corrigez HayabusaRelativePath dans la config." -ForegroundColor Yellow
        Write-StandLog "Analyse rattrapage : Hayabusa introuvable." -Level 'WARN'
        return
    }

    $ctx = Get-OperationContext -SIName $SIName -ComputerName $ComputerName
    $computerPath = Join-Path -Path (Join-Path -Path $BasePath -ChildPath $ctx.SIName) -ChildPath $ctx.ComputerName

    if (-not (Test-Path -LiteralPath $computerPath -PathType Container)) {
        Write-Host "Repertoire du poste introuvable : $computerPath" -ForegroundColor Red
        Write-Host "Verifiez le nom du SI et du poste, ou lancez d'abord un export." -ForegroundColor Yellow
        Write-StandLog "Analyse rattrapage : $computerPath introuvable." -Level 'WARN'
        return
    }

    $evtxCount = @(Get-ChildItem -LiteralPath $computerPath -Filter '*.evtx' -File -Recurse -ErrorAction SilentlyContinue).Count
    if ($evtxCount -eq 0) {
        Write-Host "Aucun fichier EVTX a analyser dans $computerPath." -ForegroundColor Yellow
        Write-Host "Lancez d'abord l'export des journaux." -ForegroundColor Yellow
        Write-StandLog "Analyse rattrapage : aucun EVTX dans $computerPath." -Level 'WARN'
        return
    }
    Write-Host "$evtxCount fichier(s) EVTX detecte(s) dans $computerPath." -ForegroundColor Cyan

    # Si un rapport existe deja, demander avant d'ecraser (sinon Hayabusa
    # bloquerait sur une invite d'ecrasement en mode non interactif).
    $existing = Get-AnalysisOutputPath -ComputerPath $computerPath -SIName $ctx.SIName -ComputerName $ctx.ComputerName
    if (Test-Path -LiteralPath $existing) {
        Write-Host "Un rapport d'analyse existe deja : $existing" -ForegroundColor Yellow
        if (-not (Read-YesNoChoice -Message 'Le remplacer ?' -Default 'N')) {
            Write-Host 'Analyse annulee.' -ForegroundColor Yellow
            return
        }
        Remove-Item -LiteralPath $existing -Force -ErrorAction SilentlyContinue
    }

    Invoke-HayabusaAnalysis -ComputerPath $computerPath -SIName $ctx.SIName -ComputerName $ctx.ComputerName
}

# ============================================================================
# region Export AV
# ============================================================================

function Export-AVLogs {
    param (
        [Parameter(Mandatory)][string]$BasePath,
        [Parameter(Mandatory)][string]$SIName,
        [Parameter(Mandatory)][string]$ComputerName
    )

    $source = $Script:Config.AVLogsPath
    if (-not $source -or -not (Test-Path -LiteralPath $source -PathType Container)) {
        Write-StandLog "AV : dossier source introuvable ($source). Export ignore." -Level 'WARN'
        Write-Host "AV introuvable : $source" -ForegroundColor Yellow
        return
    }

    $computerPath = Resolve-ComputerExportPath -BasePath $BasePath -SIName $SIName -ComputerName $ComputerName
    $avPath  = Join-Path -Path $computerPath -ChildPath 'AV'
    Confirm-Directory -Path $avPath

    try {
        Write-Host "Copie AV : $source -> $avPath" -ForegroundColor Cyan
        $sourcePattern = Join-Path -Path $source -ChildPath '*'
        Copy-Item -Path $sourcePattern -Destination $avPath -Recurse -Force
        Write-Host "Logs AV copies." -ForegroundColor Green
        Write-StandLog "Export AV : $source -> $avPath" -Level 'OK'
    } catch {
        Write-Host "Erreur copie AV : $_" -ForegroundColor Red
        Write-StandLog "Erreur export AV : $_" -Level 'ERROR'
    }
}

# ============================================================================
# region Audit systeme
# ============================================================================

function Invoke-SystemAudit {
    param (
        [Parameter(Mandatory)][string]$BasePath,
        [Parameter(Mandatory)][string]$SIName,
        [Parameter(Mandatory)][string]$ComputerName
    )

    $computerPath = Resolve-ComputerExportPath -BasePath $BasePath -SIName $SIName -ComputerName $ComputerName
    $auditPath = Join-Path -Path $computerPath -ChildPath 'Audit'
    Confirm-Directory -Path $auditPath

    $audit = [ordered]@{
        AuditDate    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Operator     = $env:USERNAME
        Host         = $env:COMPUTERNAME
        SIName       = $SIName
        ComputerName = $ComputerName
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $audit.OS = [ordered]@{
            Caption        = $os.Caption
            Version        = $os.Version
            BuildNumber    = $os.BuildNumber
            Architecture   = $os.OSArchitecture
            LastBootUpTime = $os.LastBootUpTime
            InstallDate    = $os.InstallDate
        }
    } catch { Write-StandLog "Audit OS indisponible : $_" -Level 'WARN' }

    try {
        $audit.Firewall = Get-NetFirewallProfile |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    } catch { Write-StandLog "Audit pare-feu indisponible : $_" -Level 'WARN' }

    try {
        $audit.BitLocker = Get-BitLockerVolume |
            Select-Object MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus
    } catch { Write-StandLog "Audit BitLocker indisponible : $_" -Level 'WARN' }

    try {
        $audit.Antivirus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop |
            Select-Object displayName, pathToSignedProductExe, productState
    } catch { Write-StandLog "Audit antivirus indisponible : $_" -Level 'WARN' }

    try {
        $audit.HotFixes = Get-HotFix |
            Sort-Object InstalledOn -Descending |
            Select-Object HotFixID, InstalledOn, Description -First 50
    } catch { Write-StandLog "Audit correctifs indisponible : $_" -Level 'WARN' }

    $admins = $null
    foreach ($group in @('Administrateurs','Administrators')) {
        try {
            $admins = Get-LocalGroupMember -Group $group -ErrorAction Stop |
                Select-Object Name, ObjectClass, PrincipalSource
            break
        } catch { continue }
    }
    if (-not $admins) {
        Write-StandLog "Membres du groupe Administrateurs indisponibles." -Level 'WARN'
        $admins = @('Non disponible')
    }
    $audit.LocalAdmins = $admins

    try {
        $audit.PendingReboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
                               (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    } catch { }

    $jsonPath = Join-Path -Path $auditPath -ChildPath 'system_audit.json'
    $txtPath  = Join-Path -Path $auditPath -ChildPath 'system_audit.txt'

    ($audit | ConvertTo-Json -Depth 6) | Out-File -FilePath $jsonPath -Encoding UTF8 -Force

    $summary = @()
    $summary += "==== Audit systeme : $($audit.AuditDate) ===="
    $summary += "Hote : $($audit.Host) / SI=$($audit.SIName) / Poste=$($audit.ComputerName)"
    if ($audit.PSObject.Properties.Name -contains 'OS' -and $audit.OS) {
        $summary += "OS    : $($audit.OS.Caption) ($($audit.OS.Version) build $($audit.OS.BuildNumber), $($audit.OS.Architecture))"
        $summary += "Boot  : $($audit.OS.LastBootUpTime)"
    }
    if ($audit.PSObject.Properties.Name -contains 'Antivirus' -and $audit.Antivirus) {
        foreach ($av in $audit.Antivirus) { $summary += "AV    : $($av.displayName)" }
    }
    if ($audit.PSObject.Properties.Name -contains 'Firewall' -and $audit.Firewall) {
        foreach ($fw in $audit.Firewall) { $summary += "Pare-feu $($fw.Name) : Enabled=$($fw.Enabled)" }
    }
    if ($audit.PSObject.Properties.Name -contains 'BitLocker' -and $audit.BitLocker) {
        foreach ($bl in $audit.BitLocker) { $summary += "BitLocker $($bl.MountPoint) : $($bl.VolumeStatus) ($($bl.EncryptionPercentage)%)" }
    }
    if ($audit.PSObject.Properties.Name -contains 'PendingReboot') {
        $summary += "Redemarrage en attente : $($audit.PendingReboot)"
    }
    $summary += ''
    $summary += "Details complets : $jsonPath"

    $summary | Out-File -FilePath $txtPath -Encoding UTF8 -Force
    Write-Host "Audit systeme : $txtPath" -ForegroundColor Green
    Write-StandLog "Audit systeme genere : $jsonPath / $txtPath" -Level 'OK'
}

# ============================================================================
# region Analyse differentielle
# ============================================================================

function Invoke-DifferentialAnalysis {
    param (
        [Parameter(Mandatory)][string]$BasePath,
        [Parameter(Mandatory)][string]$SIName,
        [Parameter(Mandatory)][string]$ComputerName
    )

    if (-not $CreateBaseline) {
        if (-not (Read-YesNoChoice -Message 'Lancer une analyse differentielle par rapport aux baselines ?' -Default 'N')) {
            Write-Host 'Analyse differentielle ignoree.' -ForegroundColor Yellow
            return
        }
    }

    $computerPath = Resolve-ComputerExportPath -BasePath $BasePath -SIName $SIName -ComputerName $ComputerName
    $baselinePath = Join-Path -Path $computerPath -ChildPath 'baseline'
    Confirm-Directory -Path $baselinePath

    # Chaque check produit une LISTE DE CLES UNIQUES (chaines), pas une collection d'objets.
    # Cela evite les faux positifs sur :
    #   - les processus multi-instances (csrss, svchost, ...) ;
    #   - les colonnes nullables qui deviennent '' apres Import-Csv ;
    #   - les connexions TCP client qui changent en permanence.
    # On ne signale QUE les ajouts (clefs presentes dans le snapshot courant
    # et absentes de la baseline).
    $checks = @(
        [PSCustomObject]@{
            DisplayName  = 'services'
            BaselineFile = 'services.baseline'
            OutputFile   = 'diff-services.txt'
            Prompt       = "Aucune baseline pour les services. La creer maintenant ?"
            AddedLabel   = 'Nouveaux services apparus depuis la baseline'
            Collect      = {
                @(Get-Service -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Name |
                    Sort-Object -Unique)
            }
        },
        [PSCustomObject]@{
            DisplayName  = 'processus'
            BaselineFile = 'processes.baseline'
            OutputFile   = 'diff-processes.txt'
            Prompt       = "Aucune baseline pour les processus. La creer maintenant ?"
            AddedLabel   = 'Nouveaux processus apparus depuis la baseline'
            Collect      = {
                @(Get-Process -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Name |
                    Sort-Object -Unique)
            }
        },
        [PSCustomObject]@{
            DisplayName  = 'ports en ecoute'
            BaselineFile = 'listening-ports.baseline'
            OutputFile   = 'diff-network.txt'
            Prompt       = "Aucune baseline pour les ports en ecoute. La creer maintenant ?"
            AddedLabel   = 'Nouveaux ports en ecoute depuis la baseline'
            Collect      = {
                @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                    ForEach-Object { '{0}:{1}' -f $_.LocalAddress, $_.LocalPort } |
                    Sort-Object -Unique)
            }
        },
        [PSCustomObject]@{
            DisplayName  = 'taches planifiees'
            BaselineFile = 'scheduled-tasks.baseline'
            OutputFile   = 'diff-scheduled.txt'
            Prompt       = "Aucune baseline pour les taches planifiees. La creer maintenant ?"
            AddedLabel   = 'Nouvelles taches planifiees depuis la baseline'
            Collect      = {
                @(Get-ScheduledTask -ErrorAction SilentlyContinue |
                    ForEach-Object { '{0}{1}' -f $_.TaskPath, $_.TaskName } |
                    Sort-Object -Unique)
            }
        }
    )

    foreach ($check in $checks) {
        $baselineFile = Join-Path -Path $baselinePath -ChildPath $check.BaselineFile
        $createdNow = $false

        if (-not (Test-Path -LiteralPath $baselineFile)) {
            $shouldCreate = $CreateBaseline -or (Read-YesNoChoice -Message $check.Prompt -Default 'N')
            if (-not $shouldCreate) {
                Write-Host "Baseline '$($check.DisplayName)' non creee. Suivant." -ForegroundColor Yellow
                continue
            }
            $items = @(& $check.Collect)
            $items | Out-File -FilePath $baselineFile -Encoding UTF8 -Force
            Write-Host ("Baseline creee : {0} ({1} entrees)" -f $baselineFile, $items.Count) -ForegroundColor Green
            Write-StandLog "Baseline '$($check.DisplayName)' creee : $baselineFile ($($items.Count) entrees)" -Level 'OK'
            $createdNow = $true
        }

        if ($createdNow) {
            Write-Host "Pas de diff pour '$($check.DisplayName)' (baseline fraichement creee)." -ForegroundColor Cyan
            continue
        }

        Write-Host ""
        Write-Host ("--- Diff : {0} ---" -f $check.DisplayName) -ForegroundColor Cyan

        $baseline = @(Get-Content -LiteralPath $baselineFile -Encoding UTF8 -ErrorAction SilentlyContinue |
            Where-Object { $_ -and $_.Trim() })
        $current  = @(& $check.Collect)
        $outputFile = Join-Path -Path $computerPath -ChildPath $check.OutputFile

        # Set-based lookup pour O(n) au lieu de O(n*m)
        $baselineSet = New-Object 'System.Collections.Generic.HashSet[string]' (
            [string[]]$baseline,
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $added = @($current | Where-Object { -not $baselineSet.Contains($_) })

        if ($added.Count -eq 0) {
            "Aucun ajout detecte ($($check.DisplayName)) - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" |
                Out-File -FilePath $outputFile -Encoding UTF8 -Force
            Write-Host "Aucun ajout." -ForegroundColor Green
        } else {
            $header = @(
                $check.AddedLabel,
                "Detecte le : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
                "Baseline   : $baselineFile",
                "Nombre     : $($added.Count)",
                '',
                '--------------------------------------'
            )
            ($header + $added) | Out-File -FilePath $outputFile -Encoding UTF8 -Force

            Write-Host ("{0} nouvel(s) element(s) :" -f $added.Count) -ForegroundColor Yellow
            $added | ForEach-Object { Write-Host "  + $_" -ForegroundColor Yellow }
            Write-Host "Diff enregistree : $outputFile" -ForegroundColor Green
            Write-StandLog "Diff '$($check.DisplayName)' : $($added.Count) ajout(s)" -Level 'WARN'
        }
    }
}

# ============================================================================
# region Sauvegarde reseau
# ============================================================================

function Copy-LatestArtifacts {
    <#
        Copie les artefacts les plus recents d'un poste vers <dest>\<SI>\<Poste>\latest\
        pour alimenter le dashboard meteo sans avoir a ouvrir les archives ZIP.
        Conserve uniquement la derniere version de chaque type d'artefact.
    #>
    param (
        [Parameter(Mandatory)][string]$PosteDir,
        [Parameter(Mandatory)][string]$LatestDir,
        [Parameter(Mandatory)][string]$SIName,
        [Parameter(Mandatory)][string]$ComputerName
    )

    try {
        # Vider l'ancien latest\ pour ne pas melanger des versions differentes
        Get-ChildItem -LiteralPath $LatestDir -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

        # 1. Derniere analyse Hayabusa
        $analyse = Get-ChildItem -LiteralPath $PosteDir -Filter 'Analyse_*.csv' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($analyse) {
            Copy-Item -LiteralPath $analyse.FullName -Destination (Join-Path $LatestDir 'hayabusa.csv') -Force
        }

        # 2. Dernier audit systeme
        $auditFile = Join-Path -Path (Join-Path -Path $PosteDir -ChildPath 'Audit') -ChildPath 'system_audit.json'
        if (Test-Path -LiteralPath $auditFile) {
            Copy-Item -LiteralPath $auditFile -Destination (Join-Path $LatestDir 'system_audit.json') -Force
        }

        # 3. Horodatage de la derniere collecte
        $lastExport = Join-Path -Path $PosteDir -ChildPath 'last_export.txt'
        if (Test-Path -LiteralPath $lastExport) {
            Copy-Item -LiteralPath $lastExport -Destination (Join-Path $LatestDir 'last_export.txt') -Force
        }

        # 4. Dernier rapport d'export
        $report = Get-ChildItem -LiteralPath $PosteDir -Filter 'Rapport_Export_*.txt' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($report) {
            Copy-Item -LiteralPath $report.FullName -Destination (Join-Path $LatestDir 'rapport_export.txt') -Force
        }

        # 5. Manifest d'export (integrite EVTX)
        $manifest = Join-Path -Path $PosteDir -ChildPath 'export_manifest.csv'
        if (Test-Path -LiteralPath $manifest) {
            Copy-Item -LiteralPath $manifest -Destination (Join-Path $LatestDir 'export_manifest.csv') -Force
        }

        # 6. Meta JSON pour le dashboard (identification rapide)
        $meta = [PSCustomObject]@{
            SIName       = $SIName
            ComputerName = $ComputerName
            RefreshedAt  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Operator     = $env:USERNAME
            BackupHost   = $env:COMPUTERNAME
        }
        $meta | ConvertTo-Json | Out-File -FilePath (Join-Path $LatestDir 'meta.json') -Encoding UTF8 -Force

        Write-Host "  Artefacts dashboard rafraichis dans latest\" -ForegroundColor DarkGray
    } catch {
        Write-StandLog "Copy-LatestArtifacts ($SIName/$ComputerName) : $_" -Level 'WARN'
    }
}

function Invoke-NetworkBackup {
    param (
        [Parameter(Mandatory)][string]$SIName
    )
    try {
        $usbDrive = Get-DriveRoot

        $siPath = Join-Path -Path $usbDrive -ChildPath $SIName

        if (-not (Test-Path -LiteralPath $siPath -PathType Container)) {
            Write-Host "Erreur : le repertoire $siPath n'existe pas sur la cle." -ForegroundColor Red
            Write-StandLog "Sauvegarde reseau : $siPath introuvable." -Level 'WARN'
            return
        }

        $posteDirs = @(Get-ChildItem -LiteralPath $siPath -Directory -ErrorAction SilentlyContinue)
        if ($posteDirs.Count -eq 0) {
            Write-Host "Aucun poste trouve dans $siPath." -ForegroundColor Yellow
            return
        }

        $destBase = $Script:Config.SaveDestination
        if (-not $destBase) {
            Write-Host "SaveDestination n'est pas configure." -ForegroundColor Red
            return
        }

        if (-not (Test-Path -LiteralPath $destBase)) {
            Write-Host "Destination reseau inaccessible : $destBase" -ForegroundColor Red
            Write-StandLog "Sauvegarde reseau : $destBase inaccessible." -Level 'ERROR'
            return
        }

        $compressionLevel = if ($Script:Config.CompressionLevel) { $Script:Config.CompressionLevel } else { 'Optimal' }
        $current = 0

        foreach ($posteDir in $posteDirs) {
            $current++
            Write-Progress -Activity 'Sauvegarde reseau' `
                -Status "Poste $($posteDir.Name) ($current/$($posteDirs.Count))" `
                -PercentComplete (($current / $posteDirs.Count) * 100)

            $posteName = $posteDir.Name
            Write-Host ""
            Write-Host "--- Poste : $posteName ---" -ForegroundColor Cyan

            $destSiPath    = Join-Path -Path $destBase -ChildPath $siName
            $destPostePath = Join-Path -Path $destSiPath -ChildPath $posteName
            $destLatest    = Join-Path -Path $destPostePath -ChildPath 'latest'
            Confirm-Directory -Path $destSiPath
            Confirm-Directory -Path $destPostePath
            Confirm-Directory -Path $destLatest

            $lastExportFile = Join-Path -Path $posteDir.FullName -ChildPath 'last_export.txt'
            $baselineDir    = Join-Path -Path $posteDir.FullName -ChildPath 'baseline'
            $keep = @($lastExportFile, $baselineDir)

            # Extraction des artefacts recents pour alimenter le dashboard meteo
            # (sans avoir besoin de dezipper les archives)
            Copy-LatestArtifacts -PosteDir $posteDir.FullName -LatestDir $destLatest -SIName $siName -ComputerName $posteName

            $itemsToArchive = @(
                Get-ChildItem -LiteralPath $posteDir.FullName -Force -ErrorAction SilentlyContinue |
                    Where-Object { $keep -notcontains $_.FullName }
            )

            if ($itemsToArchive.Count -eq 0) {
                Write-Host "Rien a archiver pour $posteName." -ForegroundColor Yellow
                continue
            }

            $timestamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
            $zipFileName = "{0}-{1}.zip" -f $posteName, $timestamp
            $zipFilePath = Join-Path -Path $destPostePath -ChildPath $zipFileName

            try {
                Write-Host "Creation de l'archive : $zipFileName" -ForegroundColor Cyan
                Compress-Archive `
                    -Path ($itemsToArchive | ForEach-Object { $_.FullName }) `
                    -DestinationPath $zipFilePath `
                    -CompressionLevel $compressionLevel `
                    -Force

                # Empreinte de l'archive deposee
                $hash = Get-FileHash -LiteralPath $zipFilePath -Algorithm SHA256
                $manifest = [PSCustomObject]@{
                    Archive    = $zipFilePath
                    SHA256     = $hash.Hash
                    SizeMB     = [math]::Round((Get-Item -LiteralPath $zipFilePath).Length / 1MB, 2)
                    SIName     = $siName
                    Poste      = $posteName
                    SourceDir  = $posteDir.FullName
                    Operator   = $env:USERNAME
                    CreatedAt  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                }
                $manifestFile = "$zipFilePath.sha256.txt"
                "$($hash.Hash)  $zipFileName" | Out-File -FilePath $manifestFile -Encoding UTF8 -Force
                $manifest | ConvertTo-Json -Depth 4 |
                    Out-File -FilePath "$zipFilePath.manifest.json" -Encoding UTF8 -Force

                Write-Host "Archive creee ($($manifest.SizeMB) Mo) - SHA256 : $($hash.Hash)" -ForegroundColor Green
                Write-StandLog "Archive $zipFilePath ($($manifest.SizeMB) Mo) SHA256=$($hash.Hash)" -Level 'OK'

                # Nettoyage des elements archives (on conserve baseline\ et last_export.txt)
                $itemsToArchive | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Nettoyage local effectue (baseline\ et last_export.txt conserves)." -ForegroundColor Yellow
            } catch {
                Write-Host "Erreur sur $posteName : $_" -ForegroundColor Red
                Write-StandLog "Erreur archivage $posteName : $_" -Level 'ERROR'
            }
        }

        Write-Progress -Activity 'Sauvegarde reseau' -Completed
        Write-Host ""
        Write-Host "Sauvegarde terminee." -ForegroundColor Green
    } catch {
        Write-Host "Erreur sauvegarde reseau : $_" -ForegroundColor Red
        Write-StandLog "Erreur sauvegarde reseau : $_" -Level 'ERROR'
    }
}

# ============================================================================
# region Durcissement / triage des services
# ============================================================================

function Get-ServiceTriageQuestions {
    return @(
        # MODE SIMPLE
        [PSCustomObject]@{ Tier='Base'; Prompt="1. Avez-vous une imprimante branchee ou utilisez la fonction 'Imprimer en PDF' ?"; Services=@('Spooler'); Desc='Impression (physique et PDF)' },
        [PSCustomObject]@{ Tier='Base'; Prompt="2. Doit-on pouvoir prendre le controle de ce PC a distance (RDP) ?"; Services=@('TermService','SessionEnv','UmRdpService'); Desc='Bureau a distance (RDP)' },
        [PSCustomObject]@{ Tier='Base'; Prompt="3. Utilisez-vous des jeux Microsoft Store ou la barre Xbox (Win+G) ?"; Services=@('XblAuthManager','XblGameSave','XboxNetApiSvc','XboxGipSvc'); Desc='Fonctionnalites Xbox' },
        [PSCustomObject]@{ Tier='Base'; Prompt="4. Utilisez-vous des appareils Bluetooth (souris, casque) ?"; Services=@('bthserv','BthHFSrv'); Desc='Bluetooth' },
        [PSCustomObject]@{ Tier='Base'; Prompt="5. Autorisez-vous Microsoft a collecter de la telemetrie ?"; Services=@('DiagTrack','dmwappushservice'); Desc='Telemetrie' },
        [PSCustomObject]@{ Tier='Base'; Prompt="6. Avez-vous un Fax connecte a ce poste ?"; Services=@('Fax'); Desc='Service Fax' },
        [PSCustomObject]@{ Tier='Base'; Prompt="7. Utilisez-vous la geolocalisation (Meteo, Cartes) ?"; Services=@('lfsvc'); Desc='Localisation' },
        # MODE EXPERT
        [PSCustomObject]@{ Tier='Expert'; Prompt="8. Utilisez-vous Windows Hello (empreinte, reconnaissance faciale) ?"; Services=@('WbioSrvc'); Desc='Biometrie' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="9. Avez-vous un ecran tactile ou un stylet ?"; Services=@('TabletInputService'); Desc='Saisie tactile/stylet' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="10. Utilisez-vous l'app 'Cartes' hors-connexion ?"; Services=@('MapsBroker'); Desc='Cartes Windows' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="11. Le PC doit-il ajuster sa luminosite automatiquement ou tourner l'ecran ?"; Services=@('SensorService','SensorDataService','SensorsSvc'); Desc='Capteurs' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="12. Diffusez-vous l'ecran sans fil (Miracast / Projection) ?"; Services=@('WFDSvc'); Desc='Projection sans fil' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="13. Utilisez-vous des VM Hyper-V ?"; Services=@('hvhost','vmickvpexchange','vmicguestinterface','vmicshutdown','vmictimesync','vmicrdv','vmicvmsession','vmicvss'); Desc='Hyper-V' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="14. L'indexation instantanee de fichiers est-elle utile ?"; Services=@('WSearch'); Desc='Indexation Windows' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="15. Le PC dispose-t-il d'une carte SIM 4G/5G ?"; Services=@('WwanSvc','PhoneSvc'); Desc='Cellulaire' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="16. Utilisez-vous le partage bibliotheque Windows Media Player ?"; Services=@('WMPNetworkSvc'); Desc='Partage WMP' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="17. Doit-on envoyer les rapports d'erreurs a Microsoft ?"; Services=@('WerSvc'); Desc='Rapport erreurs Windows' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="18. Utilisez-vous l'app 'Portefeuille' ?"; Services=@('WalletService'); Desc='Portefeuille' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="19. Le PC doit-il etre pilotable a distance via WinRM ?"; Services=@('WinRM','RemoteRegistry'); Desc='WinRM/RemoteRegistry' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="20. Disque dur mecanique (HDD) ? Repondre NON si SSD."; Services=@('SysMain'); Desc='SysMain (HDD)' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="21. Utilisez-vous le partage de connexion (Hotspot) ?"; Services=@('icssvc'); Desc='ICS' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="22. Utilisez-vous des transitions IPv6 (Teredo, IP-HTTPS) ?"; Services=@('iphlpsvc'); Desc='IP Helper' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="23. Partagez-vous des dossiers/fichiers depuis ce PC ?"; Services=@('LanmanServer'); Desc='Serveur SMB' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="24. Decouverte UPnP des autres appareils du reseau ?"; Services=@('SSDPSrv','upnphost'); Desc='UPnP' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="25. Utilisez-vous des cartes a puce pour vous connecter ?"; Services=@('SCardSvr','ScDeviceEnum','SCPolicySvc'); Desc='Smart Cards' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="26. 'Executer en tant qu''autre utilisateur' est-il necessaire ?"; Services=@('seclogon'); Desc='Connexion secondaire' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="27. Le controle parental Windows est-il utilise ?"; Services=@('WpcMonSvc'); Desc='Controle parental' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="28. Garder le mode demo magasin (Retail Demo) ?"; Services=@('RetailDemo'); Desc='Retail Demo' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="29. Le suivi des liens NTFS reseau est-il utile ?"; Services=@('TrkWks'); Desc='Suivi liens NTFS' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="30. etes-vous inscrit au programme Windows Insider ?"; Services=@('wisvc'); Desc='Insider' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="31. Voulez-vous garder l'assistant de compatibilite de programmes ?"; Services=@('PcaSvc'); Desc='Compatibilite' },
        [PSCustomObject]@{ Tier='Expert'; Prompt="32. Avez-vous un scanner physique connecte ?"; Services=@('StiSvc'); Desc='Scanner' }
    )
}
 
function Invoke-ServiceTriage {
    param (
        [Parameter(Mandatory)][string]$BasePath
    )
 
    Assert-Administrator
 
    Write-Banner -Title 'DeSACTIVATION DES SERVICES INUTILES'
    Write-Host " Ce module pose des questions pour identifier les services a desactiver."
    Write-Host " 1. Mode SIMPLE  : questions de base (7 questions)"
    Write-Host " 2. Mode EXPERT  : nettoyage complet (32 questions)"
    Write-Host ('=' * 70)
 
    $mode = $null
    while ($mode -notin '1','2') {
        $mode = Read-Host 'Choisissez votre mode (1 ou 2)'
        if ($mode -notin '1','2') { Write-Host 'Saisissez 1 ou 2.' -ForegroundColor Yellow }
    }
 
    $all = Get-ServiceTriageQuestions
    $questions = if ($mode -eq '2') { $all } else { $all | Where-Object { $_.Tier -eq 'Base' } }
 
    $siName   = Get-SafeName -Name (Read-NonEmptyString -Prompt 'Entrez le nom du SI (ex. SI03)')
    $hostName = Get-SafeName -Name (Read-NonEmptyString -Prompt 'Entrez le nom de la machine (ex. LAP-001)' -Default $env:COMPUTERNAME)
 
    $toDisable = @()
    Write-Host ""
    Write-Host "QUESTIONNAIRE (O = je m'en sers, garder / N = desactiver)" -ForegroundColor Yellow
    Write-Host ""
 
    foreach ($q in $questions) {
        if (-not (Read-YesNoChoice -Message $q.Prompt -Default 'O')) {
            $toDisable += [PSCustomObject]@{ Services = $q.Services; Desc = $q.Desc }
        }
    }
 
    if ($toDisable.Count -eq 0) {
        Write-Host "Aucun service a desactiver. Tout est conserve." -ForegroundColor Green
        return
    }
 
    # Filtrage : on ne touche jamais aux services critiques
    $allRequested = $toDisable | ForEach-Object { $_.Services } | Select-Object -Unique
    $blocked = $allRequested | Where-Object { $Script:CriticalServices -contains $_ }
    if ($blocked) {
        Write-Host ""
        Write-Host "Services critiques exclus de la desactivation : $($blocked -join ', ')" -ForegroundColor Yellow
    }
    $targets = $allRequested | Where-Object { $Script:CriticalServices -notcontains $_ }
 
    Write-Banner -Title 'ReCAPITULATIF'
    Write-Host "Services a desactiver :"
    foreach ($item in $toDisable) {
        Write-Host (" [OFF] -> {0}" -f $item.Desc) -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Une sauvegarde sera creee AVANT toute modification." -ForegroundColor Green
 
    if (-not (Read-YesNoChoice -Message 'Valider et appliquer les changements ?' -Default 'N')) {
        Write-Host "Annule. Aucun changement effectue." -ForegroundColor Red
        return
    }
 
    $postePath = Resolve-ComputerExportPath -BasePath $BasePath -SIName $siName -ComputerName $hostName
    $baselineFolder = Join-Path -Path $postePath -ChildPath 'baseline'
    Confirm-Directory -Path $baselineFolder
 
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmm'
    $backupPath = Join-Path -Path $baselineFolder -ChildPath "Sauvegarde_Services_$timestamp.csv"
 
    $existing = Get-Service -Name $targets -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Host "Aucun des services cibles n'est present sur ce poste." -ForegroundColor Yellow
        return
    }
 
    $existing | Select-Object Name, StartType, Status |
        Export-Csv -Path $backupPath -NoTypeInformation -Encoding UTF8 -Force
    Write-StandLog "Sauvegarde des services ecrite : $backupPath" -Level 'OK'
 
    Write-Host ""
    Write-Host "Application en cours..." -ForegroundColor Cyan
    $modified = @()
    foreach ($svcName in ($existing | Select-Object -ExpandProperty Name)) {
        try {
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            Set-Service  -Name $svcName -StartupType Disabled -ErrorAction Stop
            Write-Host "  [OK]   $svcName" -ForegroundColor Green
            $modified += $svcName
        } catch {
            Write-Host "  [WARN] $svcName : $_" -ForegroundColor Yellow
            Write-StandLog "Desactivation $svcName echouee : $_" -Level 'WARN'
        }
    }
 
    Write-Host ""
    Write-Host "$($modified.Count) service(s) desactive(s). Sauvegarde : $backupPath" -ForegroundColor Green
    Write-StandLog "Triage services : $($modified.Count) desactives ($($modified -join ', '))" -Level 'OK'
}
 
function Restore-ServiceStartup {
    Assert-Administrator
 
    Write-Banner -Title 'RESTAURATION DES SERVICES'
 
    $siName   = Get-SafeName -Name (Read-NonEmptyString -Prompt 'Entrez le nom du SI (ex. SI03)')
    $hostName = Get-SafeName -Name (Read-NonEmptyString -Prompt 'Entrez le nom de la machine (ex. LAP-001)' -Default $env:COMPUTERNAME)
 
    $basePath = Get-DriveRoot
    $baselineFolder = Join-Path -Path (Join-Path -Path (Join-Path -Path $basePath -ChildPath $siName) -ChildPath $hostName) -ChildPath 'baseline'
 
    $fileToLoad = $null
    if (Test-Path -LiteralPath $baselineFolder) {
        $backups = @(Get-ChildItem -LiteralPath $baselineFolder -Filter 'Sauvegarde_Services_*.csv' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending)
        if ($backups.Count -gt 0) {
            $fileToLoad = $backups[0].FullName
            Write-Host "Sauvegarde la plus recente : $($backups[0].Name)" -ForegroundColor Cyan
        }
    }
 
    if (-not $fileToLoad) {
        Write-Host "Aucune sauvegarde automatique trouvee dans : $baselineFolder" -ForegroundColor Yellow
        $manual = Read-Host 'Chemin du fichier CSV (Entree pour annuler)'
        if ([string]::IsNullOrWhiteSpace($manual)) { return }
        if (-not (Test-Path -LiteralPath $manual)) {
            Write-Host "Fichier introuvable." -ForegroundColor Red
            return
        }
        $fileToLoad = $manual
    }
 
    if (-not (Read-YesNoChoice -Message "Restaurer les services depuis $fileToLoad ?" -Default 'N')) {
        Write-Host "Annule."
        return
    }
 
    $data = Import-Csv -LiteralPath $fileToLoad
    Write-Host ""
    Write-Host "Restauration en cours..." -ForegroundColor Cyan
 
    $count = 0
    foreach ($row in $data) {
        $svcName = $row.Name
        $oldStartType = $row.StartType
        try {
            Set-Service -Name $svcName -StartupType $oldStartType -ErrorAction Stop
            Write-Host ("  [OK]   {0,-25} -> {1}" -f $svcName, $oldStartType) -ForegroundColor Green
            $count++
        } catch {
            Write-Host ("  [WARN] {0} : {1}" -f $svcName, $_) -ForegroundColor Yellow
            Write-StandLog "Restore $svcName echoue : $_" -Level 'WARN'
        }
    }
 
    Write-Host ""
    Write-Host "$count service(s) restaure(s). Un redemarrage est conseille." -ForegroundColor Cyan
    Write-StandLog "Restauration depuis $fileToLoad : $count service(s) traites." -Level 'OK'
}
 
# ============================================================================
# region Dashboard meteo SSI
# ============================================================================
 
function ConvertTo-HtmlSafe {
    param ([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}
 
function Get-HayabusaSummary {
    <#
        Parse un CSV Hayabusa (csv-timeline) et retourne :
          - compteurs par niveau (Crit, High, Med, Low, Info)
          - liste agregee des regles (rule, level, count)
          - timestamp du dernier evenement detecte
    #>
    param ([Parameter(Mandatory)][string]$CsvPath)
 
    $summary = [ordered]@{
        Crit          = 0
        High          = 0
        Med           = 0
        Low           = 0
        Info          = 0
        Total         = 0
        Rules         = @()
        LastEventTime = $null
    }
 
    if (-not (Test-Path -LiteralPath $CsvPath)) { return $summary }
 
    try {
        # @() garantit un tableau meme pour un CSV a 0 ou 1 ligne
        # (sinon $rows.Count plante sous Set-StrictMode).
        $rows = @(Import-Csv -LiteralPath $CsvPath)
    } catch {
        Write-StandLog "Lecture Hayabusa CSV echouee ($CsvPath) : $_" -Level 'WARN'
        return $summary
    }

    if ($rows.Count -eq 0) { return $summary }
 
    $ruleCounts = @{}
    $maxTs = $null
 
    foreach ($r in $rows) {
        $summary.Total++
 
        $lvl = ''
        if ($r.PSObject.Properties.Name -contains 'Level') { $lvl = "$($r.Level)".ToLower().Trim() }
 
        switch -Regex ($lvl) {
            '^(crit|critical)$'   { $summary.Crit++ }
            '^high$'              { $summary.High++ }
            '^med(ium)?$'         { $summary.Med++ }
            '^low$'               { $summary.Low++ }
            '^info(rmational)?$'  { $summary.Info++ }
            default               { }
        }
 
        $ruleName = $null
        foreach ($col in @('RuleTitle','RuleName','Title')) {
            if ($r.PSObject.Properties.Name -contains $col -and $r.$col) {
                $ruleName = "$($r.$col)".Trim()
                break
            }
        }
        if ($ruleName) {
            if (-not $ruleCounts.ContainsKey($ruleName)) {
                $ruleCounts[$ruleName] = [PSCustomObject]@{
                    Rule  = $ruleName
                    Level = $lvl
                    Count = 0
                }
            }
            $ruleCounts[$ruleName].Count++
        }
 
        if ($r.PSObject.Properties.Name -contains 'Timestamp' -and $r.Timestamp) {
            try {
                $ts = [DateTime]::Parse($r.Timestamp)
                if (-not $maxTs -or $ts -gt $maxTs) { $maxTs = $ts }
            } catch { }
        }
    }
 
    $summary.Rules = @($ruleCounts.Values)
    $summary.LastEventTime = $maxTs
    return $summary
}
 
function Get-PosteWeather {
    <#
        Retourne l'etat meteo d'un poste a partir de ses compteurs Hayabusa
        et de l'anciennete de la derniere collecte.
            ⛈️ Orage      : ≥ 1 critique OU ≥ 5 eleves
            🌧️ Pluie      : ≥ 1 eleve
            ⛅ Nuageux    : ≥ 10 moyens
            🌤️ eclaircies : ≥ 1 moyen
            ☀️ Clair      : 0 alerte significative
            ❓ Obsolete   : derniere analyse > 90 jours
            ❌ Sans data  : aucune analyse Hayabusa
    #>
    param (
        [int]$Crit,
        [int]$High,
        [int]$Med,
        [int]$AgeDays,
        [bool]$HasAnalysis
    )
 
    $vs = [char]::ConvertFromUtf32(0xFE0F)
    $iStorm    = [char]::ConvertFromUtf32(0x26C8) + $vs
    $iRain     = [char]::ConvertFromUtf32(0x1F327) + $vs
    $iCloudy   = [char]::ConvertFromUtf32(0x26C5)
    $iPartly   = [char]::ConvertFromUtf32(0x1F324) + $vs
    $iClear    = [char]::ConvertFromUtf32(0x2600) + $vs
    $iObsolete = [char]::ConvertFromUtf32(0x2754)
    $iNoData   = [char]::ConvertFromUtf32(0x274C)
 
    if (-not $HasAnalysis) { return [PSCustomObject]@{ Code='nodata';   Icon=$iNoData;   Label='Sans donnees'; Class='wx-nodata';   Severity=0 } }
    if ($AgeDays -gt 90)   { return [PSCustomObject]@{ Code='obsolete'; Icon=$iObsolete; Label='Obsolete';     Class='wx-obsolete'; Severity=0 } }
    if ($Crit -ge 1)       { return [PSCustomObject]@{ Code='storm';    Icon=$iStorm;    Label='Orage';        Class='wx-storm';    Severity=5 } }
    if ($High -ge 5)       { return [PSCustomObject]@{ Code='storm';    Icon=$iStorm;    Label='Orage';        Class='wx-storm';    Severity=5 } }
    if ($High -ge 1)       { return [PSCustomObject]@{ Code='rain';     Icon=$iRain;     Label='Pluie';        Class='wx-rain';     Severity=4 } }
    if ($Med  -ge 10)      { return [PSCustomObject]@{ Code='cloudy';   Icon=$iCloudy;   Label='Nuageux';      Class='wx-cloudy';   Severity=3 } }
    if ($Med  -ge 1)       { return [PSCustomObject]@{ Code='partly';   Icon=$iPartly;   Label='Eclaircies';   Class='wx-partly';   Severity=2 } }
                             return [PSCustomObject]@{ Code='clear';    Icon=$iClear;    Label='Clair';        Class='wx-clear';    Severity=1 }
}
 
function Get-SiWeather {
    param ([Parameter(Mandatory)][object[]]$Postes)
 
    $active = @($Postes | Where-Object { $_.Weather.Severity -gt 0 })
    if ($active.Count -gt 0) {
        return ($active | Sort-Object { $_.Weather.Severity } -Descending | Select-Object -First 1).Weather
    }
    $obs = @($Postes | Where-Object { $_.Weather.Code -eq 'obsolete' })
    if ($obs.Count -gt 0) {
        return [PSCustomObject]@{ Code='obsolete'; Icon=([char]::ConvertFromUtf32(0x2754)); Label='Obsolete';     Class='wx-obsolete'; Severity=0 }
    }
    return     [PSCustomObject]@{ Code='nodata';   Icon=([char]::ConvertFromUtf32(0x274C)); Label='Sans donnees'; Class='wx-nodata';   Severity=0 }
}
 
function New-SeverityBarSvg {
    param (
        [int]$Crit, [int]$High, [int]$Med, [int]$Low, [int]$Info
    )
    $data = @(
        [PSCustomObject]@{ Label='Critique'; Value=$Crit; Color='#DC2626' },
        [PSCustomObject]@{ Label='eleve';    Value=$High; Color='#EA580C' },
        [PSCustomObject]@{ Label='Moyen';    Value=$Med;  Color='#D97706' },
        [PSCustomObject]@{ Label='Faible';   Value=$Low;  Color='#0EA5E9' },
        [PSCustomObject]@{ Label='Info';     Value=$Info; Color='#94A3B8' }
    )
    $max = [math]::Max(1, ($data | Measure-Object -Property Value -Maximum).Maximum)
    $w = 460; $h = 220; $padL = 50; $padR = 20; $padT = 30; $padB = 40
    $slot = ($w - $padL - $padR) / $data.Count
    $barW = $slot - 16
 
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<svg viewBox='0 0 $w $h' xmlns='http://www.w3.org/2000/svg' role='img' aria-label='Distribution par criticite'>")
    [void]$sb.Append("<rect x='0' y='0' width='$w' height='$h' fill='#FFFFFF'/>")
 
    # Axe Y leger
    for ($t = 0; $t -le 4; $t++) {
        $y = $padT + ($h - $padT - $padB) * $t / 4
        [void]$sb.Append("<line x1='$padL' y1='$y' x2='$($w - $padR)' y2='$y' stroke='#F1F5F9' stroke-width='1'/>")
        $val = [math]::Round($max * (1 - $t/4))
        [void]$sb.Append("<text x='$($padL - 8)' y='$($y + 3)' text-anchor='end' font-size='10' fill='#94A3B8' font-family='Segoe UI, Arial, sans-serif'>$val</text>")
    }
 
    for ($i = 0; $i -lt $data.Count; $i++) {
        $d = $data[$i]
        $bh = if ($max -gt 0) { ($d.Value / $max) * ($h - $padT - $padB) } else { 0 }
        $x = [math]::Round($padL + $i * $slot + ($slot - $barW)/2, 2)
        $y = [math]::Round($h - $padB - $bh, 2)
        [void]$sb.Append("<rect x='$x' y='$y' width='$barW' height='$([math]::Round($bh,2))' fill='$($d.Color)' rx='3'/>")
        $tx = [math]::Round($x + $barW/2, 2)
        [void]$sb.Append("<text x='$tx' y='$($h - 18)' text-anchor='middle' font-size='12' fill='#475569' font-family='Segoe UI, Arial, sans-serif'>$($d.Label)</text>")
        [void]$sb.Append("<text x='$tx' y='$($y - 6)' text-anchor='middle' font-size='12' font-weight='600' fill='#1E293B' font-family='Segoe UI, Arial, sans-serif'>$($d.Value)</text>")
    }
 
    [void]$sb.Append("</svg>")
    return $sb.ToString()
}
 
function Format-Age {
    param ([Nullable[DateTime]]$LastExport)
    if (-not $LastExport) { return 'jamais' }
    $age = (Get-Date) - $LastExport
    if ($age.TotalDays -ge 1)  { return "il y a $([math]::Floor($age.TotalDays)) j" }
    if ($age.TotalHours -ge 1) { return "il y a $([math]::Floor($age.TotalHours)) h" }
    return "il y a $([math]::Floor($age.TotalMinutes)) min"
}
 
function New-DashboardHtml {
    param (
        [Parameter(Mandatory)][object[]]$Postes,
        [Parameter(Mandatory)][DateTime]$GeneratedAt,
        [Parameter(Mandatory)][string]$SaveDestination
    )
 
    # ---------- Agregations ----------
    $totalPostes  = $Postes.Count
    $sumCrit = 0; $sumHigh = 0; $sumMed = 0; $sumLow = 0; $sumInfo = 0
    foreach ($p in $Postes) {
        $sumCrit += $p.Summary.Crit
        $sumHigh += $p.Summary.High
        $sumMed  += $p.Summary.Med
        $sumLow  += $p.Summary.Low
        $sumInfo += $p.Summary.Info
    }
 
    $withAnalysis    = @($Postes | Where-Object { $_.HasAnalysis }).Count
    $freshAnalysis   = @($Postes | Where-Object { $_.HasAnalysis -and $_.AgeDays -le 90 }).Count
    $coverage        = if ($totalPostes -gt 0) { [math]::Round(($freshAnalysis / $totalPostes) * 100, 0) } else { 0 }
    $forgotten       = @($Postes | Where-Object { $_.AgeDays -gt 90 })
 
    $siGroups = @($Postes | Group-Object SI | Sort-Object Name)

    # ---------- Top regles globales ----------
    $ruleAgg = @{}
    foreach ($p in $Postes) {
        foreach ($r in $p.Summary.Rules) {
            $k = $r.Rule
            if (-not $ruleAgg.ContainsKey($k)) {
                $ruleAgg[$k] = [PSCustomObject]@{
                    Rule   = $k
                    Level  = $r.Level
                    Count  = 0
                    Postes = New-Object System.Collections.Generic.HashSet[string]
                }
            }
            $ruleAgg[$k].Count += $r.Count
            [void]$ruleAgg[$k].Postes.Add("$($p.SI)/$($p.Poste)")
        }
    }
    $levelOrder = @{ 'crit'=0; 'critical'=0; 'high'=1; 'med'=2; 'medium'=2; 'low'=3; 'info'=4; 'informational'=4 }
    $topRules = @($ruleAgg.Values |
        Sort-Object @{Expression={ if ($levelOrder.ContainsKey($_.Level)) { $levelOrder[$_.Level] } else { 5 } }}, @{Expression={ $_.Count }; Descending=$true} |
        Select-Object -First 20)
 
    # ---------- HTML : CSS ----------
    $css = @'
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { background: #F4F6F9; color: #1E293B; font-family: 'Segoe UI', -apple-system, Roboto, Arial, sans-serif; font-size: 14px; line-height: 1.45; }
a { color: #2563EB; text-decoration: none; }
a:hover { text-decoration: underline; }
header { background: #FFFFFF; border-bottom: 1px solid #E2E8F0; padding: 1.25rem 2rem; }
header .title-row { display: flex; align-items: center; gap: 0.75rem; }
header h1 { color: #1E3A8A; font-size: 1.35rem; font-weight: 600; }
header .badge-version { background: #DBEAFE; color: #1E3A8A; font-size: 0.7rem; padding: 0.15rem 0.5rem; border-radius: 999px; font-weight: 600; letter-spacing: 0.03em; }
header .subtitle { color: #64748B; font-size: 0.8rem; margin-top: 0.35rem; }
main { max-width: 1500px; margin: 0 auto; padding: 1.25rem 2rem; }
section { background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03); }
section h2 { color: #1E3A8A; font-size: 1.05rem; font-weight: 600; margin-bottom: 1rem; padding-bottom: 0.6rem; border-bottom: 2px solid #EFF6FF; display: flex; align-items: center; justify-content: space-between; }
section h2 .meta { font-size: 0.75rem; color: #94A3B8; font-weight: 400; text-transform: none; letter-spacing: 0; }
.kpi-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.85rem; }
.kpi { background: #FFFFFF; border: 1px solid #E2E8F0; border-left: 4px solid #2563EB; border-radius: 8px; padding: 0.85rem 1rem; }
.kpi-value { font-size: 1.85rem; font-weight: 700; color: #1E3A8A; line-height: 1.1; font-variant-numeric: tabular-nums; }
.kpi-label { color: #64748B; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em; margin-top: 0.3rem; font-weight: 600; }
.kpi.crit { border-left-color: #DC2626; } .kpi.crit .kpi-value { color: #DC2626; }
.kpi.high { border-left-color: #EA580C; } .kpi.high .kpi-value { color: #EA580C; }
.kpi.warn { border-left-color: #D97706; } .kpi.warn .kpi-value { color: #B45309; }
.kpi.ok   { border-left-color: #0EA5E9; } .kpi.ok   .kpi-value { color: #0369A1; }
.si-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 0.85rem; }
.si-card { background: #F8FAFC; border: 1px solid #E2E8F0; border-left: 4px solid #94A3B8; border-radius: 8px; padding: 0.85rem 1rem; }
.si-card .si-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 0.5rem; }
.si-card .si-name { font-weight: 700; color: #1E3A8A; font-size: 1rem; }
.si-card .si-icon { font-size: 2rem; line-height: 1; }
.si-card .si-label { color: #475569; font-size: 0.8rem; font-weight: 600; margin-top: 0.15rem; }
.si-card .si-stats { color: #64748B; font-size: 0.75rem; margin-top: 0.55rem; display: flex; gap: 0.6rem; flex-wrap: wrap; }
.si-card .si-stats span { display: inline-flex; gap: 0.25rem; align-items: center; }
.wx-storm    { border-left-color: #DC2626; background: #FEF2F2; }
.wx-rain     { border-left-color: #EA580C; background: #FFF7ED; }
.wx-cloudy   { border-left-color: #D97706; background: #FFFBEB; }
.wx-partly   { border-left-color: #0EA5E9; background: #F0F9FF; }
.wx-clear    { border-left-color: #2563EB; background: #EFF6FF; }
.wx-obsolete { border-left-color: #94A3B8; background: #F8FAFC; }
.wx-nodata   { border-left-color: #CBD5E1; background: #F8FAFC; }
.toolbar { display: flex; gap: 0.6rem; margin-bottom: 1rem; align-items: center; flex-wrap: wrap; }
.toolbar input, .toolbar select { padding: 0.45rem 0.7rem; border: 1px solid #CBD5E1; border-radius: 6px; font-size: 0.85rem; background: #FFFFFF; font-family: inherit; color: #1E293B; }
.toolbar input { flex: 1; max-width: 320px; }
.toolbar input:focus, .toolbar select:focus { outline: none; border-color: #2563EB; box-shadow: 0 0 0 3px #DBEAFE; }
.toolbar .count { color: #64748B; font-size: 0.8rem; margin-left: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { background: #F1F5F9; color: #475569; text-align: left; padding: 0.55rem 0.75rem; font-weight: 600; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.05em; cursor: pointer; user-select: none; border-bottom: 1px solid #E2E8F0; white-space: nowrap; }
th:hover { background: #DBEAFE; color: #1E3A8A; }
th.no-sort { cursor: default; } th.no-sort:hover { background: #F1F5F9; color: #475569; }
th .sort-ind { color: #CBD5E1; margin-left: 0.25rem; font-size: 0.7rem; }
td { padding: 0.55rem 0.75rem; border-bottom: 1px solid #F1F5F9; vertical-align: middle; }
tbody tr:hover { background: #F8FAFC; }
.badge { display: inline-block; padding: 0.12rem 0.5rem; border-radius: 4px; font-size: 0.72rem; font-weight: 600; font-variant-numeric: tabular-nums; min-width: 1.8rem; text-align: center; }
.badge-crit { background: #FEE2E2; color: #991B1B; }
.badge-high { background: #FED7AA; color: #9A3412; }
.badge-med  { background: #FEF3C7; color: #92400E; }
.badge-low  { background: #E0F2FE; color: #075985; }
.badge-info { background: #F1F5F9; color: #475569; }
.badge-wx { display: inline-flex; align-items: center; gap: 0.35rem; padding: 0.12rem 0.6rem; border-radius: 999px; font-size: 0.72rem; font-weight: 600; background: #F1F5F9; color: #475569; }
.badge-wx.wx-storm    { background: #FEE2E2; color: #991B1B; }
.badge-wx.wx-rain     { background: #FED7AA; color: #9A3412; }
.badge-wx.wx-cloudy   { background: #FEF3C7; color: #92400E; }
.badge-wx.wx-partly   { background: #E0F2FE; color: #075985; }
.badge-wx.wx-clear    { background: #DBEAFE; color: #1E40AF; }
.badge-wx.wx-obsolete { background: #F1F5F9; color: #64748B; }
.badge-wx.wx-nodata   { background: #F8FAFC; color: #94A3B8; }
.num  { font-variant-numeric: tabular-nums; text-align: right; }
.zero { color: #CBD5E1; }
.muted { color: #94A3B8; font-size: 0.8rem; }
.chart-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; }
.chart-card h3 { color: #475569; font-size: 0.82rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.6rem; }
.heatmap td { text-align: center; font-variant-numeric: tabular-nums; font-weight: 600; padding: 0.45rem 0.55rem; }
.heatmap td:first-child, .heatmap th:first-child { text-align: left; font-weight: 700; }
.heatmap .hm-0 { background: #F8FAFC; color: #CBD5E1; }
.heatmap .hm-1 { background: #EFF6FF; color: #1E40AF; }
.heatmap .hm-2 { background: #DBEAFE; color: #1E3A8A; }
.heatmap .hm-3 { background: #FEF3C7; color: #92400E; }
.heatmap .hm-4 { background: #FED7AA; color: #9A3412; }
.heatmap .hm-5 { background: #FEE2E2; color: #991B1B; }
.forgotten-list li { padding: 0.4rem 0; color: #475569; border-bottom: 1px dashed #E2E8F0; display: flex; align-items: center; gap: 0.5rem; }
.forgotten-list li:last-child { border-bottom: none; }
footer { text-align: center; color: #94A3B8; font-size: 0.72rem; padding: 1.5rem 2rem 2rem; }
@media (max-width: 900px) {
  .chart-row { grid-template-columns: 1fr; }
  main { padding: 1rem; }
  header { padding: 1rem; }
}
@media print {
  .toolbar { display: none; }
  section { break-inside: avoid; box-shadow: none; }
}
'@
 
    # ---------- JS minimal (sort & filter sans dependances) ----------
    $js = @'
(function(){
  var search = document.getElementById('search');
  var filterWx = document.getElementById('filter-weather');
  var filterSI = document.getElementById('filter-si');
  var counter = document.getElementById('row-count');
  var tbody = document.querySelector('#postes-table tbody');
  if (!tbody) return;
  var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
 
  function apply() {
    var q  = (search.value || '').toLowerCase().trim();
    var wx = filterWx.value;
    var si = filterSI.value;
    var shown = 0;
    rows.forEach(function(r){
      var ok = true;
      if (q  && r.textContent.toLowerCase().indexOf(q) === -1) ok = false;
      if (ok && wx && r.dataset.weather !== wx) ok = false;
      if (ok && si && r.dataset.si !== si) ok = false;
      r.style.display = ok ? '' : 'none';
      if (ok) shown++;
    });
    if (counter) counter.textContent = shown + ' / ' + rows.length;
  }
  if (search)   search.addEventListener('input', apply);
  if (filterWx) filterWx.addEventListener('change', apply);
  if (filterSI) filterSI.addEventListener('change', apply);
 
  var dir = {};
  document.querySelectorAll('th[data-sort]').forEach(function(th){
    th.addEventListener('click', function(){
      var key = th.dataset.sort;
      var numeric = th.dataset.numeric === '1';
      dir[key] = (dir[key] || 1) * -1;
      var sign = dir[key];
      var visible = rows.filter(function(r){ return r.style.display !== 'none'; });
      var hidden  = rows.filter(function(r){ return r.style.display === 'none'; });
      visible.sort(function(a,b){
        var va = a.dataset[key]; var vb = b.dataset[key];
        if (numeric) { return ((parseFloat(va)||0) - (parseFloat(vb)||0)) * sign; }
        return ((va||'').localeCompare(vb||'')) * sign;
      });
      tbody.innerHTML = '';
      visible.concat(hidden).forEach(function(r){ tbody.appendChild(r); });
      document.querySelectorAll('th .sort-ind').forEach(function(s){ s.textContent = ''; });
      var ind = th.querySelector('.sort-ind');
      if (ind) { ind.textContent = sign === 1 ? '▲' : '▼'; ind.style.color = '#2563EB'; }
    });
  });
})();
'@
 
    # ---------- Bandeau KPI ----------
    $kpiHtml = @"
<div class="kpi-row">
  <div class="kpi"><div class="kpi-value">$($siGroups.Count)</div><div class="kpi-label">Systemes d'information</div></div>
  <div class="kpi"><div class="kpi-value">$totalPostes</div><div class="kpi-label">Postes suivis</div></div>
  <div class="kpi ok"><div class="kpi-value">$coverage%</div><div class="kpi-label">Couverture &lt; 90 j</div></div>
  <div class="kpi crit"><div class="kpi-value">$sumCrit</div><div class="kpi-label">Alertes critiques</div></div>
  <div class="kpi high"><div class="kpi-value">$sumHigh</div><div class="kpi-label">Alertes elevees</div></div>
  <div class="kpi warn"><div class="kpi-value">$($forgotten.Count)</div><div class="kpi-label">Postes oublies &gt; 90 j</div></div>
</div>
"@
 
    # ---------- Panel meteo SI ----------
    $siCards = New-Object System.Text.StringBuilder
    foreach ($g in $siGroups) {
        $siWx = Get-SiWeather -Postes @($g.Group)
        $siCrit = 0; $siHigh = 0; $siMed = 0
        foreach ($pp in $g.Group) { $siCrit += $pp.Summary.Crit; $siHigh += $pp.Summary.High; $siMed += $pp.Summary.Med }
        $siName = ConvertTo-HtmlSafe $g.Name
        $cssClass = $siWx.Class
        [void]$siCards.Append("<a class='si-card $cssClass' href='#si-$siName' style='text-decoration:none;color:inherit;'>")
        [void]$siCards.Append("<div class='si-head'><div><div class='si-name'>$siName</div><div class='si-label'>$($siWx.Label)</div></div><div class='si-icon'>$($siWx.Icon)</div></div>")
        [void]$siCards.Append("<div class='si-stats'>")
        [void]$siCards.Append("<span>$($g.Count) poste$(if ($g.Count -gt 1){'s'})</span>")
        if ($siCrit -gt 0) { [void]$siCards.Append("<span class='badge badge-crit'>$siCrit crit</span>") }
        if ($siHigh -gt 0) { [void]$siCards.Append("<span class='badge badge-high'>$siHigh hi</span>") }
        if ($siMed  -gt 0) { [void]$siCards.Append("<span class='badge badge-med'>$siMed me</span>") }
        if (($siCrit + $siHigh + $siMed) -eq 0) { [void]$siCards.Append("<span class='muted'>RAS</span>") }
        [void]$siCards.Append("</div></a>")
    }
 
    # ---------- Charts ----------
    $svgBars = New-SeverityBarSvg -Crit $sumCrit -High $sumHigh -Med $sumMed -Low $sumLow -Info $sumInfo
 
    # Heatmap SI x criticite
    $hmHeader = "<tr><th>SI</th><th>Crit</th><th>eleve</th><th>Moyen</th><th>Faible</th><th>Info</th><th>Total</th></tr>"
    $hmRows = New-Object System.Text.StringBuilder
    foreach ($g in $siGroups) {
        $cC = 0; $cH = 0; $cM = 0; $cL = 0; $cI = 0
        foreach ($pp in $g.Group) {
            $cC += $pp.Summary.Crit; $cH += $pp.Summary.High; $cM += $pp.Summary.Med
            $cL += $pp.Summary.Low;  $cI += $pp.Summary.Info
        }
        $tot = $cC + $cH + $cM + $cL + $cI
        $clsC = if ($cC -ge 1) { 'hm-5' } else { 'hm-0' }
        $clsH = if ($cH -ge 5) { 'hm-4' } elseif ($cH -ge 1) { 'hm-3' } else { 'hm-0' }
        $clsM = if ($cM -ge 10) { 'hm-3' } elseif ($cM -ge 1) { 'hm-2' } else { 'hm-0' }
        $clsL = if ($cL -ge 1) { 'hm-1' } else { 'hm-0' }
        $clsI = if ($cI -ge 1) { 'hm-1' } else { 'hm-0' }
        [void]$hmRows.Append("<tr><td>$(ConvertTo-HtmlSafe $g.Name)</td><td class='$clsC'>$cC</td><td class='$clsH'>$cH</td><td class='$clsM'>$cM</td><td class='$clsL'>$cL</td><td class='$clsI'>$cI</td><td>$tot</td></tr>")
    }
 
    # ---------- Selecteurs ----------
    $siOptions = ($siGroups | ForEach-Object { "<option value='$(ConvertTo-HtmlSafe $_.Name)'>$(ConvertTo-HtmlSafe $_.Name)</option>" }) -join ''
    $wxOptions = @(
        "<option value='storm'>Orage</option>"
        "<option value='rain'>Pluie</option>"
        "<option value='cloudy'>Nuageux</option>"
        "<option value='partly'>eclaircies</option>"
        "<option value='clear'>Clair</option>"
        "<option value='obsolete'>Obsolete</option>"
        "<option value='nodata'>Sans donnees</option>"
    ) -join ''
 
    # ---------- Tableau des postes ----------
    $rowsHtml = New-Object System.Text.StringBuilder
    $sortedPostes = $Postes | Sort-Object @{Expression={ -$_.Score }}, SI, Poste
    foreach ($p in $sortedPostes) {
        $wx = $p.Weather
        $siHtml    = ConvertTo-HtmlSafe $p.SI
        $posteHtml = ConvertTo-HtmlSafe $p.Poste
        $age = Format-Age -LastExport $p.LastExport
        $ageSort = if ($p.LastExport) { $p.LastExport.ToString('yyyyMMddHHmmss') } else { '00000000000000' }
        $lastEvt = if ($p.Summary.LastEventTime) { $p.Summary.LastEventTime.ToString('yyyy-MM-dd HH:mm') } else { '—' }
 
        $cellCrit = if ($p.Summary.Crit -gt 0) { "<span class='badge badge-crit'>$($p.Summary.Crit)</span>" } else { "<span class='zero'>0</span>" }
        $cellHigh = if ($p.Summary.High -gt 0) { "<span class='badge badge-high'>$($p.Summary.High)</span>" } else { "<span class='zero'>0</span>" }
        $cellMed  = if ($p.Summary.Med  -gt 0) { "<span class='badge badge-med'>$($p.Summary.Med)</span>"  } else { "<span class='zero'>0</span>" }
        $cellLow  = if ($p.Summary.Low  -gt 0) { "<span class='badge badge-low'>$($p.Summary.Low)</span>"  } else { "<span class='zero'>0</span>" }
        $cellInfo = if ($p.Summary.Info -gt 0) { "<span class='badge badge-info'>$($p.Summary.Info)</span>"} else { "<span class='zero'>0</span>" }
 
        $linkAnalyse = ''
        if ($p.AnalyseFile) {
            $relUri = ([Uri]$p.AnalyseFile).AbsoluteUri
            $linkAnalyse = "<a href='$relUri' title='Ouvrir l''analyse CSV'>CSV</a>"
        }
 
        [void]$rowsHtml.Append("<tr data-si='$siHtml' data-poste='$posteHtml' data-weather='$($wx.Code)' data-crit='$($p.Summary.Crit)' data-high='$($p.Summary.High)' data-med='$($p.Summary.Med)' data-low='$($p.Summary.Low)' data-score='$($p.Score)' data-age='$ageSort'>")
        [void]$rowsHtml.Append("<td>$siHtml</td>")
        [void]$rowsHtml.Append("<td><strong>$posteHtml</strong></td>")
        [void]$rowsHtml.Append("<td><span class='badge-wx $($wx.Class)'>$($wx.Icon) $($wx.Label)</span></td>")
        [void]$rowsHtml.Append("<td class='num'>$cellCrit</td>")
        [void]$rowsHtml.Append("<td class='num'>$cellHigh</td>")
        [void]$rowsHtml.Append("<td class='num'>$cellMed</td>")
        [void]$rowsHtml.Append("<td class='num'>$cellLow</td>")
        [void]$rowsHtml.Append("<td class='num'>$cellInfo</td>")
        [void]$rowsHtml.Append("<td class='num'>$($p.Score)</td>")
        [void]$rowsHtml.Append("<td>$age</td>")
        [void]$rowsHtml.Append("<td class='muted'>$lastEvt</td>")
        [void]$rowsHtml.Append("<td>$linkAnalyse</td>")
        [void]$rowsHtml.Append("</tr>")
    }
 
    # ---------- Top regles ----------
    $rulesHtml = New-Object System.Text.StringBuilder
    if ($topRules.Count -eq 0) {
        [void]$rulesHtml.Append("<tr><td colspan='4' class='muted'>Aucune regle declenchee.</td></tr>")
    } else {
        foreach ($r in $topRules) {
            $lvl = $r.Level
            $badge = switch -Regex ($lvl) {
                '^crit'  { "<span class='badge badge-crit'>crit</span>"; break }
                '^high$' { "<span class='badge badge-high'>high</span>"; break }
                '^med'   { "<span class='badge badge-med'>med</span>"; break }
                '^low$'  { "<span class='badge badge-low'>low</span>"; break }
                default  { "<span class='badge badge-info'>$lvl</span>" }
            }
            $postesList = ($r.Postes | Sort-Object | Select-Object -First 5) -join ', '
            if ($r.Postes.Count -gt 5) { $postesList += "<span class='muted'> +$($r.Postes.Count - 5)</span>" }
            [void]$rulesHtml.Append("<tr><td>$(ConvertTo-HtmlSafe $r.Rule)</td><td>$badge</td><td class='num'>$($r.Count)</td><td>$postesList</td></tr>")
        }
    }
 
    # ---------- Postes oublies ----------
    $forgottenHtml = New-Object System.Text.StringBuilder
    if ($forgotten.Count -eq 0) {
        [void]$forgottenHtml.Append("<p class='muted'>Aucun poste n'a ete oublie. Toutes les collectes ont moins de 90 jours.</p>")
    } else {
        [void]$forgottenHtml.Append("<ul class='forgotten-list'>")
        foreach ($p in ($forgotten | Sort-Object AgeDays -Descending)) {
            $ageTxt = if ($p.LastExport) { "$($p.AgeDays) j (derniere collecte : $($p.LastExport.ToString('yyyy-MM-dd')))" } else { 'jamais collecte' }
            [void]$forgottenHtml.Append("<li><strong>$(ConvertTo-HtmlSafe $p.SI) / $(ConvertTo-HtmlSafe $p.Poste)</strong> &mdash; <span class='muted'>$ageTxt</span></li>")
        }
        [void]$forgottenHtml.Append("</ul>")
    }
 
    $destSafe = ConvertTo-HtmlSafe $SaveDestination
    $generatedSafe = $GeneratedAt.ToString('dddd dd MMMM yyyy a HH:mm', [System.Globalization.CultureInfo]::GetCultureInfo('fr-FR'))
    $hostSafe = ConvertTo-HtmlSafe $env:COMPUTERNAME
    $userSafe = ConvertTo-HtmlSafe $env:USERNAME
 
    # ---------- HTML final ----------
    $html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard SSI - Meteo des postes isoles</title>
<style>
$css
</style>
</head>
<body>
<header>
  <div class="title-row">
    <h1>Meteo SSI &mdash; Postes isoles</h1>
    <span class="badge-version">$Script:AppName v$Script:AppVersion</span>
  </div>
  <div class="subtitle">Genere le $generatedSafe par $userSafe sur $hostSafe &nbsp;&middot;&nbsp; Source : <code>$destSafe</code></div>
</header>
<main>
 
<section>
  <h2>Vue d'ensemble <span class="meta">KPI temps reel</span></h2>
  $kpiHtml
</section>
 
<section id="weather-panel">
  <h2>Panel meteo par SI <span class="meta">cliquez pour filtrer le tableau</span></h2>
  <div class="si-grid">
    $($siCards.ToString())
  </div>
</section>
 
<section>
  <h2>Statistiques globales</h2>
  <div class="chart-row">
    <div class="chart-card">
      <h3>Distribution par criticite</h3>
      $svgBars
    </div>
    <div class="chart-card">
      <h3>Heatmap SI &times; criticite</h3>
      <table class="heatmap">
        <thead>$hmHeader</thead>
        <tbody>$($hmRows.ToString())</tbody>
      </table>
    </div>
  </div>
</section>
 
<section>
  <h2>Detail par poste <span class="meta">triable, filtrable</span></h2>
  <div class="toolbar">
    <input id="search" type="search" placeholder="Filtrer (SI, poste, meteo...)" autocomplete="off">
    <select id="filter-weather">
      <option value="">Toutes les meteos</option>
      $wxOptions
    </select>
    <select id="filter-si">
      <option value="">Tous les SI</option>
      $siOptions
    </select>
    <span class="count" id="row-count">$totalPostes / $totalPostes</span>
  </div>
  <table id="postes-table">
    <thead>
      <tr>
        <th data-sort="si">SI <span class="sort-ind"></span></th>
        <th data-sort="poste">Poste <span class="sort-ind"></span></th>
        <th data-sort="weather">Meteo <span class="sort-ind"></span></th>
        <th data-sort="crit" data-numeric="1">Crit <span class="sort-ind"></span></th>
        <th data-sort="high" data-numeric="1">eleve <span class="sort-ind"></span></th>
        <th data-sort="med"  data-numeric="1">Moyen <span class="sort-ind"></span></th>
        <th data-sort="low"  data-numeric="1">Faible <span class="sort-ind"></span></th>
        <th class="no-sort">Info</th>
        <th data-sort="score" data-numeric="1">Score <span class="sort-ind"></span></th>
        <th data-sort="age" data-numeric="1">Derniere collecte <span class="sort-ind"></span></th>
        <th class="no-sort">Dernier evenement</th>
        <th class="no-sort">Analyse</th>
      </tr>
    </thead>
    <tbody>
      $($rowsHtml.ToString())
    </tbody>
  </table>
</section>
 
<section>
  <h2>Top 20 regles declenchees <span class="meta">priorite criticite puis volume</span></h2>
  <table>
    <thead>
      <tr><th class="no-sort">Regle</th><th class="no-sort">Niveau</th><th class="no-sort">Occurrences</th><th class="no-sort">Postes affectes</th></tr>
    </thead>
    <tbody>
      $($rulesHtml.ToString())
    </tbody>
  </table>
</section>
 
<section>
  <h2>Postes oublies <span class="meta">collecte &gt; 90 jours</span></h2>
  $($forgottenHtml.ToString())
</section>
 
</main>
<footer>
  Score = critique &times; 100 + eleve &times; 20 + moyen &times; 5 + faible &times; 1 &nbsp;&middot;&nbsp;
  Dashboard auto-contenu, sans dependance externe.
</footer>
<script>
$js
</script>
</body>
</html>
"@
 
    return $html
}
 
function Invoke-WeatherDashboard {
    $dest = $Script:Config.SaveDestination
    if (-not $dest) {
        Write-Host "SaveDestination n'est pas configure dans standmanager.config.json." -ForegroundColor Red
        return
    }
    if (-not (Test-Path -LiteralPath $dest)) {
        Write-Host "Destination reseau inaccessible : $dest" -ForegroundColor Red
        Write-StandLog "Dashboard : $dest inaccessible." -Level 'ERROR'
        return
    }
 
    Write-Banner -Title 'GENERATION DU DASHBOARD METEO SSI'
    Write-Host "Lecture des artefacts depuis : $dest" -ForegroundColor Cyan
 
    $now = Get-Date
    $postes = New-Object System.Collections.Generic.List[object]
 
    $siDirs = @(Get-ChildItem -LiteralPath $dest -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '^_' })

    if ($siDirs.Count -eq 0) {
        Write-Host "Aucun SI trouve dans $dest." -ForegroundColor Yellow
        return
    }

    # On etablit d'abord la liste complete des postes a traiter, afin de calculer
    # un pourcentage de progression fiable quel que soit le nombre de postes par SI.
    $pairs = New-Object System.Collections.Generic.List[object]
    foreach ($siDir in $siDirs) {
        $posteDirs = @(Get-ChildItem -LiteralPath $siDir.FullName -Directory -ErrorAction SilentlyContinue)
        foreach ($posteDir in $posteDirs) {
            $pairs.Add([PSCustomObject]@{ SiDir = $siDir; PosteDir = $posteDir })
        }
    }

    $totalToScan = $pairs.Count
    if ($totalToScan -eq 0) {
        Write-Host "Aucun poste n'a ete trouve sous $dest." -ForegroundColor Yellow
        return
    }

    $scanned = 0
    foreach ($pair in $pairs) {
        $scanned++
        $siDir = $pair.SiDir
        $posteDir = $pair.PosteDir
        $pct = [math]::Min(100, [int](($scanned / $totalToScan) * 100))
        Write-Progress -Activity 'Agregation dashboard' `
            -Status "$($siDir.Name) / $($posteDir.Name) ($scanned/$totalToScan)" `
            -PercentComplete $pct

        $latestDir = Join-Path -Path $posteDir.FullName -ChildPath 'latest'
            $hayCsv    = Join-Path -Path $latestDir -ChildPath 'hayabusa.csv'
            $auditJson = Join-Path -Path $latestDir -ChildPath 'system_audit.json'
            $lastExp   = Join-Path -Path $latestDir -ChildPath 'last_export.txt'
 
            $hasAnalysis = Test-Path -LiteralPath $hayCsv
            $summary = if ($hasAnalysis) { Get-HayabusaSummary -CsvPath $hayCsv } else {
                [ordered]@{ Crit=0; High=0; Med=0; Low=0; Info=0; Total=0; Rules=@(); LastEventTime=$null }
            }
 
            $lastExport = $null
            if (Test-Path -LiteralPath $lastExp) {
                $txt = (Get-Content -LiteralPath $lastExp -ErrorAction SilentlyContinue | Select-Object -First 1)
                if ($txt) {
                    try { $lastExport = [DateTime]::ParseExact($txt.Trim(), 'yyyy-MM-dd HH:mm:ss', $null) } catch { }
                }
            }
 
            $audit = $null
            if (Test-Path -LiteralPath $auditJson) {
                try { $audit = Get-Content -LiteralPath $auditJson -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
            }
 
            $ageDays = if ($lastExport) { [int][math]::Floor(((Get-Date) - $lastExport).TotalDays) } else { 9999 }
            $weather = Get-PosteWeather -Crit $summary.Crit -High $summary.High -Med $summary.Med -AgeDays $ageDays -HasAnalysis $hasAnalysis
            $score = ($summary.Crit * 100) + ($summary.High * 20) + ($summary.Med * 5) + $summary.Low
 
            $postes.Add([PSCustomObject]@{
                SI           = $siDir.Name
                Poste        = $posteDir.Name
                Weather      = $weather
                Summary      = $summary
                LastExport   = $lastExport
                AgeDays      = $ageDays
                Score        = $score
                Audit        = $audit
                HasAnalysis  = $hasAnalysis
                AnalyseFile  = if ($hasAnalysis) { $hayCsv } else { $null }
            })
    }
    Write-Progress -Activity 'Agregation dashboard' -Completed
 
    if ($postes.Count -eq 0) {
        Write-Host "Aucun poste n'a ete trouve sous $dest." -ForegroundColor Yellow
        return
    }
 
    Write-Host "Postes agreges : $($postes.Count)" -ForegroundColor Cyan
    Write-Host "Generation du HTML..." -ForegroundColor Cyan
 
    $html = New-DashboardHtml -Postes $postes.ToArray() -GeneratedAt $now -SaveDestination $dest
 
    $dashDir = Join-Path -Path $dest -ChildPath '_Dashboard'
    Confirm-Directory -Path $dashDir
    $stamp = $now.ToString('yyyyMMdd-HHmmss')
    $outFile    = Join-Path -Path $dashDir -ChildPath "Dashboard_SSI_$stamp.html"
    $latestFile = Join-Path -Path $dashDir -ChildPath 'latest.html'
 
    # UTF-8 BOM pour assurer le rendu correct des emojis meteo dans tous les navigateurs
    $utf8Bom = [System.Text.UTF8Encoding]::new($true)
    [System.IO.File]::WriteAllText($outFile, $html, $utf8Bom)
    [System.IO.File]::WriteAllText($latestFile, $html, $utf8Bom)
 
    Write-Host ""
    Write-Host "Dashboard genere : $outFile" -ForegroundColor Green
    Write-Host "Raccourci stable : $latestFile" -ForegroundColor Green
    Write-StandLog "Dashboard meteo genere ($($postes.Count) postes) : $outFile" -Level 'OK'
 
    if (Read-YesNoChoice -Message 'Ouvrir le dashboard maintenant ?' -Default 'O') {
        try { Start-Process $latestFile } catch { Write-Host "Impossible d'ouvrir : $_" -ForegroundColor Yellow }
    }
}
 
# ============================================================================
# region Menu interactif
# ============================================================================
 
function Show-MainMenu {
    Clear-Host
    $bar = '=' * 70
    Write-Host $bar -ForegroundColor Cyan
    Write-Host (" $Script:AppName v$Script:AppVersion - Assistant collecte & durcissement").PadRight(70) -ForegroundColor Cyan
    Write-Host $bar -ForegroundColor Cyan
    $adminTag = if (Test-IsAdministrator) { '[ADMIN]' } else { '[USER]' }
    Write-Host (" Hote : $env:COMPUTERNAME    Utilisateur : $env:USERNAME    $adminTag")
    Write-Host (" Racine script : $Script:ScriptRoot")
    Write-Host $bar -ForegroundColor Cyan
    Write-Host ''
    Write-Host ' 1. Desactivation des services inutiles' -NoNewline
    Write-Host '   (admin requis)' -ForegroundColor Red
    Write-Host ' 2. Restauration des services desactives' -NoNewline
    Write-Host '   (admin requis)' -ForegroundColor Red
    Write-Host ' 3. Export EVTX + AV + Audit + Analyse differentielle' -NoNewline
    Write-Host '   (admin requis)' -ForegroundColor Red
    Write-Host ' 4. Analyse Hayabusa d''un poste (rattrapage)' -NoNewline
    Write-Host '   (aucun privilege requis)' -ForegroundColor DarkGray
    Write-Host ' 5. Sauvegarde des logs sur le reseau'
    Write-Host ' 6. Dashboard meteo SSI' -NoNewline
    Write-Host '   (lit le partage reseau, aucun privilege requis)' -ForegroundColor DarkGray
    Write-Host ' 7. Quitter'
    Write-Host $bar -ForegroundColor Yellow

    while ($true) {
        $choice = Read-Host 'Que voulez-vous faire ? (1-7)'
        if ($choice -in '1','2','3','4','5','6','7') { return $choice }
        Write-Host 'Choix invalide. Saisissez un nombre entre 1 et 7.' -ForegroundColor Yellow
    }
}
 
function Invoke-MenuChoice {
    param (
        [Parameter(Mandatory)][string]$Choice,
        [Parameter(Mandatory)][string]$BasePath
    )
 
    switch ($Choice) {
        '1' {
            Invoke-ServiceTriage -BasePath $BasePath
        }
        '2' {
            Restore-ServiceStartup
        }
        '3' {
            $ctx = Get-OperationContext -SIName $SIName -ComputerName $ComputerName
            Export-WindowsEventLogs -BasePath $BasePath -SIName $ctx.SIName -ComputerName $ctx.ComputerName | Out-Null
            Export-AVLogs       -BasePath $BasePath -SIName $ctx.SIName -ComputerName $ctx.ComputerName
            Invoke-SystemAudit       -BasePath $BasePath -SIName $ctx.SIName -ComputerName $ctx.ComputerName
            Invoke-DifferentialAnalysis -BasePath $BasePath -SIName $ctx.SIName -ComputerName $ctx.ComputerName
        }
        '4' {
            Invoke-StandaloneAnalysis -BasePath $BasePath
        }
        '5' {
            $ctx = Get-SaveOperationContext -SIName $SIName
            Invoke-NetworkBackup -SIName $ctx.SIName
        }
        '6' {
            Invoke-WeatherDashboard
        }
        '7' {
            Write-Host 'Au revoir.' -ForegroundColor Cyan
        }
        default {
            Write-Host 'Option non reconnue.' -ForegroundColor Yellow
        }
    }
}
 
function Get-ActionChoice {
    param ([string]$Action)
    switch ($Action) {
        'Triage'    { '1' }
        'Restore'   { '2' }
        'Export'    { '3' }
        'Hayabusa'  { '4' }
        'Save'      { '5' }
        'Dashboard' { '6' }
        'Quit'      { '7' }
        default     { $null }
    }
}
 
# ============================================================================
# region Point d'entree
# ============================================================================
 
try {
    Initialize-StandManager
    $basePath = Get-DriveRoot
 
    if ($Interactive -or -not $Action) {
        $running = $true
        while ($running) {
            $menu = Show-MainMenu
            try {
                Invoke-MenuChoice -Choice $menu -BasePath $basePath
            } catch {
                Write-StandLog "Erreur menu (choix $menu) : $_" -Level 'ERROR'
                Write-Host "Erreur : $_" -ForegroundColor Red
            }
 
            if ($menu -eq '7') {
                $running = $false
            } else {
                Write-Host ''
                Read-Host 'Appuyez sur Entree pour revenir au menu principal'
            }
        }
    } else {
        $menu = Get-ActionChoice -Action $Action
        if (-not $menu) {
            Write-Host "Action inconnue : $Action" -ForegroundColor Red
            exit 2
        }
        Invoke-MenuChoice -Choice $menu -BasePath $basePath
        Write-Host ''
        Write-Host 'Operation terminee.' -ForegroundColor Green
    }
} catch {
    Write-StandLog "Erreur fatale : $_" -Level 'ERROR'
    Write-Host "Erreur fatale : $_" -ForegroundColor Red
    exit 1
}