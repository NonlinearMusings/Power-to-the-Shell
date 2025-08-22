#region Script Header and Purpose
<#
.SYNOPSIS
    Local Security Authority (LSA) Privilege Management Script
    
.DESCRIPTION
    This script manages Windows user privileges by interacting with the Local Security Authority (LSA)
    through Windows API calls. It provides functionality to grant and verify user privileges such as
    "Log on as a service" rights.

.NOTES
    Requires: Administrator privileges
#>
#endregion

#region Type Definition Check and C# Class Declaration
# Check if the custom LsaWrapper type is already loaded in the current PowerShell session
# This prevents "type already exists" errors when running the script multiple times
if (-not ("LsaWrapper" -as [type])) {
    # Define the C# source code as a here-string for compilation into PowerShell
    $source = `
@"
// Import required .NET namespaces for Windows API interop and security operations
using System;                          // Core system types and functionality
using System.Runtime.InteropServices;  // Platform invoke (P/Invoke) for calling Windows APIs
using System.Security.Principal;       // Windows security principals and SID handling

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
        return new LSA_UNICODE_STRING
        {
            Buffer = ptr,                                           // Pointer to the string data
            Length = (ushort)(s.Length * sizeof(char)),            // String length in bytes (Unicode = 2 bytes per char)
            MaximumLength = (ushort)((s.Length + 1) * sizeof(char)) // Buffer size including null terminator
        };
    }
    
    #endregion
    
    #region Public Methods

    // Grants a specific privilege to a user account
    // Returns true if successful, false if failed
    public static bool GrantPrivilege(string accountName, string privilege)
    {
        // Initialize LSA_OBJECT_ATTRIBUTES structure with default values
        // This structure defines attributes for the LSA policy object
        LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
        attributes.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES)); // Set structure size
        
        // Create empty system name structure (indicates local system)
        // Non-null values would target remote systems
        LSA_UNICODE_STRING systemName = new LSA_UNICODE_STRING
        {
            Buffer = IntPtr.Zero,    // No system name = local system
            Length = 0,              // Zero length
            MaximumLength = 0        // Zero maximum length
        };

        // Define access rights for the LSA policy handle
        // POLICY_ALL_ACCESS (0x000F0FFF) provides full access to policy operations
        uint access = 0x000F0FFF; // POLICY_ALL_ACCESS constant
        
        // Declare variable to receive the policy handle
        IntPtr policyHandle;
        
        // Attempt to open the LSA policy database
        // This must succeed before any privilege operations can be performed
        int result = LsaOpenPolicy(ref systemName, ref attributes, access, out policyHandle);
        
        // Check if LsaOpenPolicy failed (non-zero return value indicates failure)
        if (result != 0)
            return false; // Return failure if we can't open the policy

        // Use try-finally to ensure proper cleanup of the policy handle
        try
        {
            // Nested try-catch for account resolution and privilege assignment
            try
            {
                // Convert the account name to a Security Identifier (SID)
                // Windows internally works with SIDs rather than account names
                NTAccount account = new NTAccount(accountName);                        // Create NTAccount object from name
                SecurityIdentifier sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier)); // Convert to SID
                
                // Convert SID to byte array format required by LSA APIs
                byte[] sidBytes = new byte[sid.BinaryLength];  // Allocate byte array of correct size
                sid.GetBinaryForm(sidBytes, 0);                // Copy SID binary data to array

                // Prepare the privilege name for the LSA API call
                // LSA APIs require an array of LSA_UNICODE_STRING structures
                LSA_UNICODE_STRING[] userRights = new LSA_UNICODE_STRING[1]; // Create array for one privilege
                userRights[0] = InitLsaString(privilege);                    // Convert privilege name to LSA format

                // Nested try-finally to ensure memory cleanup for the privilege string
                try
                    // Call the LSA API to add the privilege to the user account
                    // This is the core operation that actually grants the privilege
                    result = LsaAddAccountRights(policyHandle, sidBytes, userRights, 1);
                    
                    // Return success status: true if result is 0 (success), false otherwise
                    return result == 0;
                }
                finally
                {
                    // Critical cleanup: Free the allocated string memory to prevent memory leaks
                    // The InitLsaString method allocated unmanaged memory that must be freed
                    if (userRights[0].Buffer != IntPtr.Zero)
                        Marshal.FreeHGlobal(userRights[0].Buffer); // Free the Unicode string buffer
                }
            }
            catch
            {
                // If any exception occurs during the privilege grant operation, return failure
                // This catches issues like invalid account names, privilege names, or API failures
                return false;
            }
        }
        finally
        {
            // Always close the LSA policy handle to release system resources
            // This is critical to prevent resource leaks in the LSA subsystem
            LsaClose(policyHandle);
        }
    }

    // Checks if a user account has a specific privilege
    // Returns true if the privilege is assigned, false otherwise
    public static bool HasPrivilege(string accountName, string privilege)
    {
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
        // POLICY_LOOKUP_NAMES (0x00000800) allows querying account privileges
        uint access = 0x00000800; // POLICY_LOOKUP_NAMES constant
        
        // Declare variable to receive the policy handle
        IntPtr policyHandle;
        
        // Attempt to open the LSA policy with lookup access
        int result = LsaOpenPolicy(ref systemName, ref attributes, access, out policyHandle);
        
        // If policy open fails, throw an exception with the Windows error code
        if (result != 0)
            throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(result));

        // Use try-finally to ensure proper cleanup of the policy handle
        try
        {
            // Convert the account name to a Security Identifier (SID)
            NTAccount account = new NTAccount(accountName);                        // Create NTAccount from name
            SecurityIdentifier sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier)); // Convert to SID
            
            // Convert SID to byte array format for LSA API
            byte[] sidBytes = new byte[sid.BinaryLength];  // Allocate byte array
            sid.GetBinaryForm(sidBytes, 0);                // Copy SID binary data

            // Declare variables to receive privilege enumeration results
            IntPtr userRightsPtr = IntPtr.Zero; // Will receive pointer to privilege array
            int count;                          // Will receive count of privileges
            
            // Enumerate all privileges currently assigned to the user
            result = LsaEnumerateAccountRights(policyHandle, sidBytes, out userRightsPtr, out count);
            
            // Use try-finally to ensure cleanup of LSA-allocated memory
            try
            {
                // Check if enumeration succeeded and returned privilege data
                if (result == 0 && userRightsPtr != IntPtr.Zero)
                {
                    // Initialize pointer for iterating through the privilege array
                    IntPtr current = userRightsPtr;
                    
                    // Loop through each privilege in the returned array
                    for (int i = 0; i < count; i++)
                    {
                        // Marshal the current array element to LSA_UNICODE_STRING structure
                        LSA_UNICODE_STRING right = (LSA_UNICODE_STRING)Marshal.PtrToStructure(current, typeof(LSA_UNICODE_STRING));
                        
                        // Check if the privilege has valid string data
                        if (right.Buffer != IntPtr.Zero)
                        {
                            // Convert the LSA Unicode string to a .NET string
                            // Divide length by 2 because Length is in bytes, not characters
                            string rightName = Marshal.PtrToStringUni(right.Buffer, right.Length / 2);
                            
                            // Check if this privilege matches the one we're looking for
                            if (rightName == privilege)
                                return true; // Found the privilege
                        }
                        
                        // Move to the next privilege in the array
                        current = IntPtr.Add(current, Marshal.SizeOf(typeof(LSA_UNICODE_STRING)));
                    }
                }
                
                // If we reach here, the privilege was not found in the user's privilege list
                return false;
            }
            finally
            {
                // Critical cleanup: Free the memory allocated by LsaEnumerateAccountRights
                // This prevents memory leaks in the LSA subsystem
                if (userRightsPtr != IntPtr.Zero)
                {
                    LsaFreeMemory(userRightsPtr); // Free the privilege array memory
                }
            }
        }
        finally
        {
            // Always close the LSA policy handle to release system resources
            LsaClose(policyHandle);
        }
    }
    
    #endregion
}
"@

    # Compile the C# source code into the PowerShell session
    # Add-Type creates a .NET assembly from the source code and loads it into the current AppDomain
    # ReferencedAssemblies parameter specifies additional .NET assemblies required by the code
    Add-Type -TypeDefinition $source -ReferencedAssemblies "System.Security", "System.DirectoryServices"
}
#endregion

#region Script Configuration and Variables
# Define the target user account for privilege assignment
# $env:USERNAME contains the currently logged-in user's username
$user = $env:USERNAME

# Define the privilege to be granted
# SeServiceLogonRight = "Log on as a service" privilege
# Other common privileges: SeBackupPrivilege, SeRestorePrivilege, SeShutdownPrivilege, etc.
$privilege = "SeServiceLogonRight"
#endregion

#region User Interface and Information Display
Clear-Host
Write-Host "Attempting to grant privilege '$privilege' to user '$user'..."
Write-Host "Current computer: $env:COMPUTERNAME" -ForegroundColor Gray  # Show computer name
Write-Host "Current user: $(whoami)" -ForegroundColor Gray              # Show current user context
#endregion

#region Administrator Privilege Verification
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
    # Call the LsaWrapper class method to grant the privilege
    # GrantPrivilege returns true for success, false for failure
    $result = [LsaWrapper]::GrantPrivilege($user, $privilege)
    
    # Check the result and display appropriate success message
    if ($result) {
        Write-Host "Successfully granted privilege '$privilege' to user '$user'." -ForegroundColor Green
    }
    #endregion
    
    #region Privilege Verification
    Write-Host ""
    Write-Host "Verifying privilege assignment..." -ForegroundColor Cyan
    
    # Call the LsaWrapper class method to verify the privilege was granted
    # HasPrivilege returns true if the privilege is assigned, false otherwise
    $result = [LsaWrapper]::HasPrivilege($user, $privilege)
    
    # Display verification results with appropriate color coding
    if ($result) {
        Write-Host "User '$user' now has the privilege '$privilege'" -ForegroundColor Green
    } else {
        Write-Host "Could not verify privilege assignment" -ForegroundColor Red
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
