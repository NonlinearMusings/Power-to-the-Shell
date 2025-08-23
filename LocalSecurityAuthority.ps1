#region Script Header and Purpose
<#
.SYNOPSIS
    Local Security Authority (LSA) Privilege Management Script
    
.DESCRIPTION
    This script manages Windows user privileges by interacting with the Local Security Authority (LSA)
    through Windows API calls. It provides functionality to grant, revoke and verify user privileges such as
    "Log on as a service" rights.

.NOTES
    Requires: Administrator privileges
#>
#endregion

#region Type Definition Check and C# Class Declaration
# Check if the custom LsaWrapper type is already loaded in the current PowerShell session
# This prevents "type already exists" errors when running the script multiple times
if (-not ("LsaWrapper" -as [type])) {
    # Define the C# source code as a single-quoted here-string to avoid PowerShell variable expansion
    $source = @'
// Import required .NET namespaces for Windows API interop and security operations
using System;                          // Core system types and functionality
using System.Runtime.InteropServices;  // P/Invoke declarations and interop helpers
using System.Security.Principal;       // Windows security principals and SID handling

// Compatibility shim: some runtimes used by PowerShell Core do not expose System.ComponentModel.Win32Exception
// in a referenced assembly at compile time. Provide a minimal implementation so code can throw/inspect it.
namespace System.ComponentModel
{
    public class Win32Exception : Exception
    {
        public int NativeErrorCode { get; private set; }
        public Win32Exception() : base() { NativeErrorCode = 0; }
        public Win32Exception(string message) : base(message) { NativeErrorCode = 0; }
        public Win32Exception(int error) : base("Win32 error " + error) { NativeErrorCode = error; }
    }
}

// Main wrapper class for Local Security Authority (LSA) operations
// Provides managed .NET methods to interact with Windows LSA APIs
public class LsaWrapper
{
    #region Windows API Structures
    
    // LSA_OBJECT_ATTRIBUTES: Structure used when opening LSA policy handles
    // Defines attributes for LSA objects including security descriptors and access rights
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES
    {
        public int    Length;                    // Size of this structure in bytes
        public IntPtr RootDirectory;             // Handle to root directory (usually null for LSA)
        public IntPtr ObjectName;                // Pointer to object name (usually null for LSA)
        public uint   Attributes;                // Object attributes flags (usually 0)
        public IntPtr SecurityDescriptor;        // Security descriptor (usually null)
        public IntPtr SecurityQualityOfService;  // Quality of service settings (usually null)
    }

    // LSA_UNICODE_STRING: Structure for passing Unicode strings to LSA APIs
    // LSA APIs require strings in this specific format rather than standard .NET strings
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING
    {
        public ushort Length;        // Length of string in bytes (not characters)
        public ushort MaximumLength; // Maximum buffer size in bytes
        public IntPtr Buffer;        // Pointer to the actual Unicode string data
    }
    
    #endregion
    
    #region Windows API Function Imports

    // NOTE: LSA functions return NTSTATUS values (not Win32 GetLastError values).
    // When an LSA API returns a non-zero NTSTATUS, convert it with LsaNtStatusToWinError
    // before creating a Win32Exception or reporting a Win32 error code to the caller.

    // Opens a handle to the Local Security Authority (LSA) policy database
    // Required before performing any privilege operations
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int LsaOpenPolicy(
        ref LSA_UNICODE_STRING systemName,     // Target system name (null for local)
        ref LSA_OBJECT_ATTRIBUTES attributes,  // Object attributes structure
        uint access,                           // Desired access rights
        out IntPtr policyHandle);              // Receives the policy handle

    // Adds privileges/rights to a user account in the LSA database
    // This is the core function for granting user privileges
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int LsaAddAccountRights(
        IntPtr policyHandle,                   // LSA policy handle from LsaOpenPolicy
        byte[] sid,                            // User's Security Identifier (SID) as byte array
        LSA_UNICODE_STRING[] userRights,       // Array of privilege names to grant
        int count);                            // Number of privileges in the array

    // Retrieves the privileges/rights currently assigned to a user account
    // Used for verification and privilege enumeration
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int LsaEnumerateAccountRights(
        IntPtr policyHandle,                   // LSA policy handle from LsaOpenPolicy
        byte[] sid,                            // User's Security Identifier (SID) as byte array
        out IntPtr userRights,                 // Receives pointer to array of privileges
        out int count);                        // Receives count of privileges

    // Removes privileges/rights from a user account in the LSA database
    // Signature includes a BOOLEAN removeAll parameter; when TRUE all rights are removed.
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int LsaRemoveAccountRights(
        IntPtr policyHandle,                            // LSA policy handle from LsaOpenPolicy
        byte[] sid,                                     // User's Security Identifier (SID) as byte array
        [MarshalAs(UnmanagedType.U1)] bool removeAll,   // Whether to remove ALL rights (TRUE) or the provided rights array (FALSE)
        LSA_UNICODE_STRING[] userRights,                // Array of privilege names to remove
        int count);                                     // Number of privileges in the array

    // Closes an LSA policy handle and releases associated resources
    // Must be called to prevent resource leaks
    [DllImport("advapi32.dll")]
    private static extern int LsaClose(IntPtr policyHandle);

    // Converts LSA NTSTATUS codes to standard Win32 error codes
    // Useful for error handling and reporting
    [DllImport("advapi32.dll")]
    private static extern int LsaNtStatusToWinError(int status);

    // Frees memory allocated by LSA functions
    // Required to prevent memory leaks when working with LSA-allocated memory
    [DllImport("advapi32.dll")]
    private static extern int LsaFreeMemory(IntPtr buffer);
    
    #endregion
    
    #region Helper Methods

    // Converts a .NET string to LSA_UNICODE_STRING format
    // LSA APIs require strings in this specific structure format
    private static LSA_UNICODE_STRING InitLsaString(string s)
    {
        // Handle null or empty strings by returning an empty LSA_UNICODE_STRING
        if (string.IsNullOrEmpty(s))
        {
            return new LSA_UNICODE_STRING
            {
                Buffer = IntPtr.Zero,        // No buffer allocated
                Length = 0,                  // Zero length
                MaximumLength = 0            // Zero maximum length
            };
        }
        
        // Allocate unmanaged memory for the Unicode string
        // StringToHGlobalUni creates a null-terminated Unicode string in unmanaged memory
        IntPtr ptr = Marshal.StringToHGlobalUni(s);

        // Create and return the LSA_UNICODE_STRING structure
        // NOTE: The unmanaged buffer returned in LSA_UNICODE_STRING.Buffer must be freed by the caller
        // (for example via Marshal.FreeHGlobal) after the structure has been used by native APIs.
        return new LSA_UNICODE_STRING
        {
            Buffer = ptr,                                           // Pointer to the string data
            Length = (ushort)(s.Length * sizeof(char)),             // String length in bytes (Unicode = 2 bytes per char)
            MaximumLength = (ushort)((s.Length + 1) * sizeof(char)) // Buffer size including null terminator
        };
    }

    // Create exceptions that include both the raw NTSTATUS (hex) and the converted Win32 message.
    // This aids diagnostics when LSA returns NTSTATUS codes that are otherwise opaque.
    private static System.ComponentModel.Win32Exception MakeLsaException(int ntstatus)
    {
        int win32 = LsaNtStatusToWinError(ntstatus);
        string winMsg = new System.ComponentModel.Win32Exception(win32).Message;
        string msg = string.Format("LSA NTSTATUS 0x{0:X8} -> Win32 {1} ({2})", ntstatus, win32, winMsg);
        return new System.ComponentModel.Win32Exception(msg);
    }
    
    #endregion
    
    #region Public Methods

    // Grant a user account a specific privilege.
    public static bool GrantPrivilege(string accountName, string privilege, bool verbose = false, string errorAction = "Continue")
    {
        bool throwOnError = verbose || string.Equals(errorAction, "Stop", StringComparison.OrdinalIgnoreCase);

        // Initialize LSA_OBJECT_ATTRIBUTES structure with default values
        LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
        attributes.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES)); // Set structure size

        // Create empty system name structure (indicates local system)
        LSA_UNICODE_STRING systemName = new LSA_UNICODE_STRING
        {
            Buffer = IntPtr.Zero,
            Length = 0,
            MaximumLength = 0
        };

        // Define access rights for the LSA policy handle
        uint access = 0x000F0FFF; // POLICY_ALL_ACCESS constant

        IntPtr policyHandle;
        int result = LsaOpenPolicy(ref systemName, ref attributes, access, out policyHandle);

        // Surface or return based on throwOnError
        if (result != 0)
        {
            if (throwOnError)
                throw MakeLsaException(result);
            return false;
        }

        try
        {
            // Resolve account to SID
            NTAccount account = new NTAccount(accountName);
            SecurityIdentifier sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));

            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            // Prepare the privilege name for the LSA API call
            LSA_UNICODE_STRING[] userRights = new LSA_UNICODE_STRING[1];
            userRights[0] = InitLsaString(privilege);

            // Ensure unmanaged string is freed even if the API call fails
            try
            {
                result = LsaAddAccountRights(policyHandle, sidBytes, userRights, 1);

                if (result != 0)
                {
                    if (throwOnError)
                        throw MakeLsaException(result);
                    return false;
                }

                return true;
            }
            finally
            {
                if (userRights[0].Buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(userRights[0].Buffer);
            }
        }
        finally
        {
            // Always close the LSA policy handle to release system resources
            LsaClose(policyHandle);
        }
    }

    // Revoke a user account's specific privilege.
    public static bool RevokePrivilege(string accountName, string privilege, bool verbose = false, string errorAction = "Continue")
    {
        bool throwOnError = verbose || string.Equals(errorAction, "Stop", StringComparison.OrdinalIgnoreCase);

        // Initialize LSA_OBJECT_ATTRIBUTES structure for policy access
        LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
        attributes.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES)); // Set structure size

        // Create empty system name structure for local system access
        LSA_UNICODE_STRING systemName = new LSA_UNICODE_STRING
        {
            Buffer = IntPtr.Zero,
            Length = 0,
            MaximumLength = 0
        };

        // Define access rights for removal operations (use POLICY_ALL_ACCESS)
        uint access = 0x000F0FFF; // POLICY_ALL_ACCESS constant

        IntPtr policyHandle;
        int result = LsaOpenPolicy(ref systemName, ref attributes, access, out policyHandle);

        if (result != 0)
        {
            if (throwOnError)
                throw MakeLsaException(result);
            return false;
        }

        try
        {
            // Resolve account to SID
            NTAccount account = new NTAccount(accountName);
            SecurityIdentifier sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));

            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            LSA_UNICODE_STRING[] userRights = new LSA_UNICODE_STRING[1];
            userRights[0] = InitLsaString(privilege);

            try
            {
                // Pass 'false' for removeAll so we remove only the specified right(s)
                result = LsaRemoveAccountRights(policyHandle, sidBytes, false, userRights, 1);

                if (result != 0)
                {
                    // Map NTSTATUS -> Win32 and consider 'not found' (Win32 2) as success
                    int win32 = LsaNtStatusToWinError(result);
                    if (win32 == 2) // ERROR_FILE_NOT_FOUND -> privilege not present
                    {
                        return true;
                    }

                    if (throwOnError)
                        throw MakeLsaException(result);
                    return false;
                }

                return true;
            }
            finally
            {
                if (userRights[0].Buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(userRights[0].Buffer);
            }
        }
        finally
        {
            // Always close the LSA policy handle
            LsaClose(policyHandle);
        }
    }

    // Verify a user account's specific privilege.
    public static bool HasPrivilege(string accountName, string privilege, bool verbose = false, string errorAction = "Continue")
    {
        bool throwOnError = verbose || string.Equals(errorAction, "Stop", StringComparison.OrdinalIgnoreCase);

        // Initialize LSA_OBJECT_ATTRIBUTES structure for policy access
        LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
        attributes.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES)); // Set structure size

        // Create empty system name structure for local system access
        LSA_UNICODE_STRING systemName = new LSA_UNICODE_STRING
        {
            Buffer = IntPtr.Zero,    // Local system
            Length = 0,              // Zero length
            MaximumLength = 0        // Zero maximum length
        };

        // Define access rights for privilege enumeration
        uint access = 0x00000800; // POLICY_LOOKUP_NAMES constant

        IntPtr policyHandle;

        int result = LsaOpenPolicy(ref systemName, ref attributes, access, out policyHandle);

        if (result != 0)
        {
            if (throwOnError)
                throw MakeLsaException(result);
            return false;
        }

        try
        {
            // Convert the account name to a Security Identifier (SID)
            NTAccount account = new NTAccount(accountName);
            SecurityIdentifier sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));

            // Convert SID to byte array format for LSA API
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            IntPtr userRightsPtr = IntPtr.Zero;
            int count;

            result = LsaEnumerateAccountRights(policyHandle, sidBytes, out userRightsPtr, out count);

            try
            {
                if (result == 0 && userRightsPtr != IntPtr.Zero)
                {
                    IntPtr current = userRightsPtr;

                    for (int i = 0; i < count; i++)
                    {
                        LSA_UNICODE_STRING right = (LSA_UNICODE_STRING)Marshal.PtrToStructure(current, typeof(LSA_UNICODE_STRING));

                        if (right.Buffer != IntPtr.Zero)
                        {
                            string rightName = Marshal.PtrToStringUni(right.Buffer, right.Length / 2);
                            if (rightName == privilege)
                                return true;
                        }

                        current = IntPtr.Add(current, Marshal.SizeOf(typeof(LSA_UNICODE_STRING)));
                    }
                }

                return false;
            }
            finally
            {
                if (userRightsPtr != IntPtr.Zero)
                {
                    LsaFreeMemory(userRightsPtr);
                }
            }
        }
        finally
        {
            LsaClose(policyHandle);
        }
    }
    #endregion
}
'@

    # Compile the C# source code into the PowerShell session
    # Add-Type creates a .NET assembly from the source code and loads it into the current AppDomain
    # ReferencedAssemblies parameter specifies additional .NET assemblies required by the code
    try {
        Add-Type -TypeDefinition $source -ReferencedAssemblies "System.Security", "System.DirectoryServices", "System.Security.Principal.Windows" -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to compile LsaWrapper C# code: $($_.Exception.Message)"
        if ($_.Exception.InnerException) {
            Write-Error "Inner exception: $($_.Exception.InnerException.Message)"
        }
        throw
    }
}
#endregion

#region Script Configuration and Variables
# Define the target user account for privilege assignment
# $env:USERNAME contains the currently logged-in user's username
$user = $env:USERNAME

# Recommended Se* privileges for SQL Server service accounts
# Adjust this list as needed for your environment
$privileges = @(
    "SeServiceLogonRight",            # Log on as a service
    "SeImpersonatePrivilege",         # Impersonate a client after authentication
    "SeAssignPrimaryTokenPrivilege",  # Replace a process-level token
    "SeIncreaseQuotaPrivilege",       # Adjust memory quotas for a process
    "SeCreateGlobalPrivilege"         # Create global objects
)

# User Interface and Information Display
Clear-Host
Write-Host "Attempting to grant configured SQL Server privileges to user '$user'... (Verbose LSA errors: $($VerbosePreference -eq 'Continue'))"
Write-Host "Current computer: $env:COMPUTERNAME" -ForegroundColor Gray  # Show computer name
Write-Host "Current user: $(whoami)" -ForegroundColor Gray              # Show current user context
#endregion

#region Administrator Privilege Verification
# Compute per-call preferences using PowerShell defaults
# $callVerbose is driven by -Verbose.
# $callErrorAction will be passed to the C# methods; if set to 'Stop' those methods will throw on LSA failures.
$callVerbose = ($VerbosePreference -eq 'Continue')
$callErrorAction = $ErrorActionPreference.ToString()

# Examples:
# * Force verbose and treat LSA errors as terminating (useful for debugging):
#   $callVerbose = $true
#   $callErrorAction = 'Stop'
#
# * Show verbose details but do not throw (continue on errors):
#   $callVerbose = $true
#   $callErrorAction = 'SilentlyContinue'
#
# * Do not show verbose output but convert errors to terminating:
#   $callVerbose = $false
#   $callErrorAction = 'Stop'
#
# * Explicitly ignore errors (not recommended in production):
#   $callVerbose = $false
#   $callErrorAction = 'SilentlyContinue'

# Get the current user's Windows identity
# WindowsIdentity represents the Windows user account context
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()

# Create a WindowsPrincipal object to check role membership
# WindowsPrincipal allows checking if the user is in specific Windows roles/groups
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)

# Check if the current user is a member of the local Administrators group
# IsInRole returns true if the user has the specified role
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Verify administrator privileges are present before proceeding
# LSA privilege operations require administrator access
if (-not $isAdmin) {
    Write-Warning "This script requires administrator privileges. Please run as administrator."
    exit 1
}
#endregion

#region Main Privilege Grant Operation
# Execute the privilege grant operation within a try-catch block for error handling
try {
    #region User Account Validation
    # Validate that the specified user account exists and can be resolved
    # This prevents attempting to grant privileges to non-existent accounts
    try {
        # Create an NTAccount object from the username
        # NTAccount represents a Windows account by name (domain\user or user)
        $account = New-Object System.Security.Principal.NTAccount($user)
        
        # Translate the account name to a Security Identifier (SID)
        # This verifies the account exists and can be resolved by Windows
        # If the account doesn't exist, this will throw an exception
        $sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
        
        # Display the resolved SID for verification purposes
        # SIDs are unique identifiers that Windows uses internally for accounts
        Write-Host "User SID: $($sid.Value)"
    }
    catch {
        # If account resolution fails, display error and exit
        # This prevents attempting privilege operations on invalid accounts
        Write-Error "User '$user' cannot be resolved: $_"
        exit 1
    }
    #endregion
    
    #region Privilege Grant Execution
    # Call the LsaWrapper class method to grant each configured privilege
    foreach ($privilege in $privileges) {
        Write-Host "\nProcessing privilege: $privilege" -ForegroundColor Cyan

        $granted = [LsaWrapper]::GrantPrivilege($user, $privilege, $callVerbose, $callErrorAction)
        if ($granted) {
            Write-Host "Successfully granted privilege '$privilege' to user '$user'." -ForegroundColor Green
        } else {
            Write-Host "Failed to grant privilege '$privilege' to user '$user'." -ForegroundColor Yellow
        }

        # Verification
        Write-Host "Verifying privilege assignment for '$privilege'..." -ForegroundColor Cyan
        $has = [LsaWrapper]::HasPrivilege($user, $privilege, $callVerbose, $callErrorAction)
        if ($has) {
            Write-Host "User '$user' now has the privilege '$privilege'" -ForegroundColor Green
        } else {
            Write-Host "Could not verify privilege assignment for '$privilege'" -ForegroundColor Red
        }
    }
    #endregion

} 
catch {
    #region Error Handling
    # Catch any unexpected exceptions during the privilege grant process
    Write-Error "Failed to grant privilege: $($_.Exception.Message)"
    exit 1
    #endregion
}
#endregion

#region Demonstration: Revoke (optional)
# This demonstration will attempt to revoke the privileges that were just granted.
# It is intentionally opt-in and requires typing the exact string 'YES' to proceed.
$answer = Read-Host "Do you want to demonstrate revoking the privileges we just attempted? Type 'YES' to proceed"
if ($answer -eq 'YES') {
    # Demonstration revoke block uses the same per-call preferences
    foreach ($privilege in $privileges) {
        Write-Host "Attempting to revoke privilege '$privilege' from user '$user'..." -ForegroundColor Cyan

        $revoked = [LsaWrapper]::RevokePrivilege($user, $privilege, $callVerbose, $callErrorAction)
        if ($revoked) {
            Write-Host "Successfully revoked privilege '$privilege' from user '$user'." -ForegroundColor Green
        } else {
            Write-Host "Failed to revoke privilege '$privilege' from user '$user'." -ForegroundColor Yellow
        }

        # Verification
        Write-Host "Verifying removal of '$privilege'..." -ForegroundColor Cyan
        $stillHas = [LsaWrapper]::HasPrivilege($user, $privilege, $callVerbose, $callErrorAction)
        if (-not $stillHas) {
            Write-Host "Verified: user '$user' no longer has '$privilege'." -ForegroundColor Green
        } else {
            Write-Host "User '$user' still has '$privilege'." -ForegroundColor Red
        }
    }
} else {
    Write-Host "Skipping revoke demonstration." -ForegroundColor Gray
}
#endregion
