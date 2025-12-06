/**
 * Curated list of legitimate Windows processes for typosquatting detection
 *
 * This list includes:
 * - Core Windows system processes
 * - Common Windows services and utilities
 * - Popular third-party applications
 * - Security and antivirus processes
 *
 * Sources:
 * - Windows internals documentation
 * - Security research (SOCInvestigation, TryHackMe, Andrea Fortuna)
 * - Common application processes (browsers, office apps, etc.)
 *
 * Last updated: 2025
 */

export const LEGITIMATE_PROCESSES = [
  // Core System Processes (Critical)
  'system',
  'smss.exe',
  'csrss.exe',
  'wininit.exe',
  'services.exe',
  'lsass.exe',
  'lsaiso.exe',
  'winlogon.exe',
  'svchost.exe',

  // User Mode Processes
  'explorer.exe',
  'dwm.exe',
  'sihost.exe',
  'taskhostw.exe',
  'taskhost.exe',
  'ctfmon.exe',
  'conhost.exe',
  'fontdrvhost.exe',
  'dwm.exe',
  'runtimebroker.exe',
  'dllhost.exe',
  'rundll32.exe',
  'spoolsv.exe',

  // Windows Services
  'searchindexer.exe',
  'searchprotocolhost.exe',
  'searchfilterhost.exe',
  'wuauclt.exe',
  'trustedinstaller.exe',
  'tiworker.exe',
  'wudfhost.exe',
  'audiodg.exe',
  'winrshost.exe',
  'wmiprvse.exe',
  'msdtc.exe',
  'vssvc.exe',
  'msiexec.exe',

  // Windows Defender & Security
  'msmpeng.exe',
  'msmpsvc.exe',
  'nissrv.exe',
  'securityhealthservice.exe',
  'securityhealthsystray.exe',
  'smartscreen.exe',
  'antimalwareservice.exe',

  // Windows Update & Maintenance
  'usocoreworker.exe',
  'musnotification.exe',
  'musnotificationux.exe',
  'wuapp.exe',

  // Command Line & Scripting
  'cmd.exe',
  'powershell.exe',
  'powershell_ise.exe',
  'wscript.exe',
  'cscript.exe',
  'mshta.exe',
  'regsvr32.exe',
  'reg.exe',
  'regedit.exe',

  // System Utilities
  'notepad.exe',
  'mspaint.exe',
  'calc.exe',
  'taskmgr.exe',
  'perfmon.exe',
  'resmon.exe',
  'mmc.exe',
  'eventvwr.exe',
  'diskpart.exe',
  'cleanmgr.exe',
  'dism.exe',
  'chkdsk.exe',
  'sfc.exe',
  'defrag.exe',
  'certutil.exe',
  'bitsadmin.exe',
  'sc.exe',
  'net.exe',
  'net1.exe',
  'netsh.exe',
  'whoami.exe',
  'hostname.exe',
  'ipconfig.exe',
  'ping.exe',
  'tracert.exe',
  'nslookup.exe',

  // Microsoft Office & Productivity
  'outlook.exe',
  'winword.exe',
  'excel.exe',
  'powerpnt.exe',
  'onenote.exe',
  'mspub.exe',
  'msaccess.exe',
  'teams.exe',
  'lync.exe',
  'skype.exe',
  'onedrive.exe',
  'onedrivesetup.exe',

  // Common Applications
  'notepad++.exe',
  'discord.exe',
  'zoom.exe',
  'spotify.exe',
  'steam.exe',
  'vlc.exe',
  'acrobat.exe',
  'acrord32.exe',
  'winrar.exe',
  '7zg.exe',
  '7zfm.exe',

  // Drivers & Hardware
  'nvcontainer.exe',
  'nvdisplay.container.exe',
  'amdrsserv.exe',
  'atieclxx.exe',
  'igfxem.exe',
  'igfxtray.exe',
  'realtekaudiosrv.exe',

  // Virtual Machines & Containers
  'vmware.exe',
  'vmware-vmx.exe',
  'vmwareuser.exe',
  'vmtoolsd.exe',
  'vboxservice.exe',
  'vboxtray.exe',
  'docker.exe',
  'dockerd.exe',

  // Remote Access & Management
  'teamviewer.exe',
  'tvnserver.exe',
  'logmein.exe',
  'anydesk.exe',
  'rdpclip.exe',
  'mstsc.exe',

  // Backup & Sync
  'backupclient.exe',
  'dropbox.exe',
  'googledrivesync.exe',
  'box.exe',

  // Third-party Security
  'avgui.exe',
  'avastui.exe',
  'mbam.exe',
  'mbamservice.exe',
  'ccsvchst.exe',
  'nortonsecurity.exe',
  'mcuicnt.exe',
  'mcshield.exe',
  'eset.exe',
  'ekrn.exe',

  // Development Tools
  'git.exe',
  'java.exe',
  'javaw.exe',
  'devenv.exe',

  // Print & Scan
  'spoolsv.exe',
  'printfilterpipelinesvc.exe',

  // Windows Apps (UWP)
  'applicationframehost.exe',
  'systemsettings.exe',
  'calculator.exe',
  'windowsstore.exe',
  'yourphone.exe',
  'lockapp.exe',

];

/**
 * Normalizes a process name to lowercase for comparison
 */
export function normalizeProcessName(processName: string): string {
  return processName.toLowerCase().trim();
}

/**
 * Checks if a process name is in the legitimate process list
 */
export function isLegitimateProcess(processName: string): boolean {
  const normalized = normalizeProcessName(processName);
  return LEGITIMATE_PROCESSES.includes(normalized);
}
