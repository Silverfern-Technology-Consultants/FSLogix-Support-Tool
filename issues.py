"""Known FSLogix issue definitions with detection patterns and remediation steps."""

import re
from dataclasses import dataclass, field
from typing import List

@dataclass
class IssueDefinition:
    id: str
    name: str
    severity: str  # critical | high | medium | low
    patterns: List[re.Pattern]
    description: str
    causes: List[str]
    remediation_steps: List[str]
    links: List[str] = field(default_factory=list)


KNOWN_ISSUES: List[IssueDefinition] = [
    IssueDefinition(
        id="gp_client_access_denied",
        name="Group Policy Client Service — Access Denied",
        severity="critical",
        patterns=[
            re.compile(r"group policy client.*sign.in", re.IGNORECASE),
            re.compile(r"access is denied", re.IGNORECASE),
            re.compile(r"0x80070005", re.IGNORECASE),
        ],
        description=(
            "FSLogix failed to mount the profile container before Windows attempted to apply "
            "Group Policy. The Group Policy Client service then reported 'Access is denied' "
            "because the user's redirected profile folders were unavailable. This is almost "
            "always a symptom of a container attach failure, not a GP issue itself."
        ),
        causes=[
            "Profile VHD/VHDX failed to attach (network share unreachable, permissions, or locked file)",
            "Profile container already open in another session (concurrent access not configured)",
            "Insufficient NTFS or share permissions on the profile container or parent path",
            "FSLogix filter driver (frxdrv) not loaded before Group Policy processing began",
            "SMB signing mismatch between the AVD host and the file server",
            "Azure Files / NetApp authentication failure (Kerberos or NTLM token issue)",
            "Storage account firewall or NSG blocking port 445 from the AVD subnet",
        ],
        remediation_steps=[
            r"Review the FSLogix Profile log around the same timestamp for 'Failed to attach' or 'ERROR' lines — the root cause is almost always there",
            r"Verify the share is reachable from the AVD host:  Test-NetConnection -ComputerName <server> -Port 445",
            r"For Azure Files: confirm the AVD host's computer account or managed identity has the 'Storage File Data SMB Share Contributor' role",
            r"Check for a stale lock file on the share alongside the .vhdx (e.g. username.vhdx.lock) and delete it if the user has no active session",
            r"If users legitimately need multiple simultaneous sessions, enable:  reg add HKLM\SOFTWARE\FSLogix\Profiles /v ConcurrentUserSessions /t REG_DWORD /d 1",
            r"Confirm the FSLogix filter driver is running:  Get-Service frxdrv | Select-Object Status",
            r"Review Event Viewer → Application and Services Logs → Microsoft → Windows → User Profile Service for supplementary detail",
            r"Run  frx list-redirects  on the host to validate that FSLogix rule configuration is correct",
        ],
        links=[
            "https://learn.microsoft.com/en-us/fslogix/troubleshooting-events-logs-diagnostics",
            "https://learn.microsoft.com/en-us/azure/virtual-desktop/troubleshoot-fslogix",
            "https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-ad-ds-configure-permissions",
        ],
    ),
    IssueDefinition(
        id="vhd_attach_failure",
        name="VHD/VHDX Attach Failure",
        severity="critical",
        patterns=[
            re.compile(r"failed to attach", re.IGNORECASE),
            re.compile(r"failed to mount", re.IGNORECASE),
            re.compile(r"error attaching vhd", re.IGNORECASE),
            re.compile(r"could not attach", re.IGNORECASE),
            re.compile(r"attach.*failed", re.IGNORECASE),
        ],
        description=(
            "FSLogix was unable to attach the profile container VHD/VHDX file. "
            "This is one of the most common root causes in AVD environments and "
            "will cascade into multiple downstream errors including profile load failures "
            "and the Group Policy Client Access Denied event."
        ),
        causes=[
            "Network path to the profile share is unreachable from the AVD host",
            "VHD/VHDX is locked by another session (concurrent access not enabled)",
            "Profile container disk is full (MaximumSize reached)",
            "Corrupt VHD/VHDX file",
            "Virtual Disk service (vds) not running on the host",
            "Antivirus or EDR product blocking VHD attach operations",
        ],
        remediation_steps=[
            r"Test network path:  Test-Path \\<server>\<share>",
            r"Check for a lock file:  Get-ChildItem \\<server>\<share>\<username>*.lock",
            r"Attempt VHD repair:  Repair-VHD -Path '<path-to.vhdx>' -Mode Full",
            r"Verify Virtual Disk service:  Get-Service vds | Select-Object Status",
            r"Check antivirus exclusions — the FSLogix VHD paths and the frxdrv driver should be excluded",
            r"Review MaximumSize:  Get-ItemProperty HKLM:\SOFTWARE\FSLogix\Profiles -Name SizeInMBs",
        ],
        links=[
            "https://learn.microsoft.com/en-us/fslogix/troubleshooting-events-logs-diagnostics",
            "https://learn.microsoft.com/en-us/fslogix/reference-configuration-settings",
        ],
    ),
    IssueDefinition(
        id="profile_size_limit",
        name="Profile Container Size Limit Reached",
        severity="high",
        patterns=[
            re.compile(r"size limit", re.IGNORECASE),
            re.compile(r"disk.*full", re.IGNORECASE),
            re.compile(r"not enough.*space", re.IGNORECASE),
            re.compile(r"exceeded.*maximum.*size", re.IGNORECASE),
            re.compile(r"insufficient.*space", re.IGNORECASE),
        ],
        description=(
            "The user's profile container has reached its configured maximum size. "
            "New writes to the profile will fail, which can cause application crashes, "
            "profile corruption, and failed sign-ins."
        ),
        causes=[
            "SizeInMBs (MaximumSize) set too low for the user's actual profile data",
            "Browser or Teams cache accumulating inside the container",
            "Large files stored on the desktop or in Downloads inside the profile",
            "Outlook OST file growing without bound (Office container not configured)",
        ],
        remediation_steps=[
            r"Increase the limit:  reg add HKLM\SOFTWARE\FSLogix\Profiles /v SizeInMBs /t REG_DWORD /d <new_size_mb>",
            r"Configure an Office Container (ODFC) to offload Outlook OST and Teams cache from the profile container",
            r"Redirect Desktop, Downloads, and Documents to a separate DFS or SharePoint path via Group Policy folder redirection",
            r"Add browser cache and Teams cache paths to FSLogix exclusion rules (FRX redirections)",
            r"Run  frx copy-profile  to compact the existing VHD before resizing",
        ],
        links=[
            "https://learn.microsoft.com/en-us/fslogix/reference-configuration-settings",
            "https://learn.microsoft.com/en-us/fslogix/concepts-fslogix-for-microsoft-teams",
        ],
    ),
    IssueDefinition(
        id="network_share_unreachable",
        name="Network Share / Storage Unreachable",
        severity="critical",
        patterns=[
            re.compile(r"network.*unreachable", re.IGNORECASE),
            re.compile(r"network path.*not.*found", re.IGNORECASE),
            re.compile(r"0x80070035", re.IGNORECASE),   # ERROR_BAD_NETPATH
            re.compile(r"0x80070003", re.IGNORECASE),   # ERROR_PATH_NOT_FOUND
            re.compile(r"path.*not.*found", re.IGNORECASE),
            re.compile(r"failed to connect.*share", re.IGNORECASE),
        ],
        description=(
            "FSLogix could not reach the configured network share for profile containers. "
            "Every user sign-in will fail to load a profile until the share is accessible."
        ),
        causes=[
            "DNS resolution failure for the file server or Azure Storage account hostname",
            "Azure Files private endpoint not accessible (missing DNS zone or NSG rule)",
            "SMB port 445 blocked by NSG, host firewall, or ISP",
            "Kerberos ticket acquisition failure (time skew, KDC unreachable)",
            "Storage account key or SAS token expired",
        ],
        remediation_steps=[
            r"Test SMB connectivity:  Test-NetConnection -ComputerName <server> -Port 445",
            r"Resolve DNS:  Resolve-DnsName <storage-account>.file.core.windows.net",
            r"For Azure Files with private endpoint, verify the private DNS zone is linked to the AVD vNet",
            r"Check NSG outbound rules: port 445 must be allowed from the AVD subnet to the storage service tag",
            r"Verify Kerberos:  klist  in a user session to confirm tickets are present and not expired",
            r"Check time sync on AVD hosts:  w32tm /query /status  — Kerberos requires < 5 min skew",
        ],
        links=[
            "https://learn.microsoft.com/en-us/azure/storage/files/storage-troubleshoot-windows-file-connection-problems",
            "https://learn.microsoft.com/en-us/azure/storage/files/storage-files-networking-overview",
        ],
    ),
    IssueDefinition(
        id="frxsvc_not_running",
        name="FSLogix Service Not Running",
        severity="critical",
        patterns=[
            re.compile(r"frxsvc.*not.*running", re.IGNORECASE),
            re.compile(r"service.*not.*start", re.IGNORECASE),
            re.compile(r"failed to start.*frx", re.IGNORECASE),
            re.compile(r"frx.*service.*stopped", re.IGNORECASE),
        ],
        description=(
            "The FSLogix Agent service (frxsvc) was not running when a user signed in. "
            "Without this service, profile containers will not be mounted and all users "
            "on the host will receive temporary profiles."
        ),
        causes=[
            "FSLogix installation is incomplete or corrupt",
            "A pending Windows update or reboot has left the service in a failed state",
            "Security software or Group Policy preventing the service from starting",
            "The filter driver (frxdrv) failed to load, causing the service to abort",
        ],
        remediation_steps=[
            r"Check service state:  Get-Service frxsvc, frxdrv, frxccds | Select-Object Name, Status, StartType",
            r"Attempt manual start:  Start-Service frxsvc",
            r"Review System event log for Service Control Manager errors around the service failure time",
            r"Check driver load:  sc query frxdrv",
            r"If the service is missing, reinstall the FSLogix agent from:  https://aka.ms/fslogix-latest",
            r"After reinstall, reboot the host and verify:  Get-Service frxsvc | Select-Object Status",
        ],
        links=[
            "https://learn.microsoft.com/en-us/fslogix/how-to-install-fslogix",
            "https://aka.ms/fslogix-latest",
        ],
    ),
    IssueDefinition(
        id="concurrent_session_conflict",
        name="Concurrent Session / Profile Already in Use",
        severity="high",
        patterns=[
            re.compile(r"already.*in use", re.IGNORECASE),
            re.compile(r"profile.*locked", re.IGNORECASE),
            re.compile(r"concurrent.*session", re.IGNORECASE),
            re.compile(r"vhd.*already.*attached", re.IGNORECASE),
            re.compile(r"another.*session.*open", re.IGNORECASE),
        ],
        description=(
            "The user's profile container VHD/VHDX is already attached by another session. "
            "By default FSLogix is configured for single-session use. In multi-session AVD "
            "(pooled host pools) users may open sessions on different hosts, leaving orphaned "
            "VHD handles."
        ),
        causes=[
            "User has an active session on another AVD host in the pool",
            "Previous session terminated abnormally and left a VHD handle open",
            "ConcurrentUserSessions not enabled for a pooled (multi-session) host pool",
        ],
        remediation_steps=[
            r"Check for active sessions:  Query-User /server:<each-host>  across all hosts in the pool",
            r"If no active session exists, look for a lock file on the share and remove it",
            r"For pooled host pools, enable concurrent sessions:  reg add HKLM\SOFTWARE\FSLogix\Profiles /v ConcurrentUserSessions /t REG_DWORD /d 1",
            r"Ensure ProfileType is set correctly for your scenario (0=single, 3=read/write with CCDLocations for Cloud Cache)",
            r"If using Azure Files, check the share for open file handles:  Get-AzStorageFileHandle",
        ],
        links=[
            "https://learn.microsoft.com/en-us/fslogix/reference-configuration-settings",
        ],
    ),
]
