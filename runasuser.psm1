$script:source = @"
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Diagnostics; // Added for potential future logging
using System.ComponentModel; // Added for Win32Exception
using System.Xml; // Added for CLIXML parsing

namespace RunAsUser
{
    internal class NativeHelpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public int LowPart;
            public int HighPart;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public PrivilegeAttributes Attributes;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] // Added CharSet
        public struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] // Corrected size for initial struct definition
            public LUID_AND_ATTRIBUTES[] Privileges; // This will be handled dynamically later
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;
            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;
            public readonly WTS_CONNECTSTATE_CLASS State;
        }
        [StructLayout(LayoutKind.Sequential)] // Added StructLayout
        public struct SECURITY_ATTRIBUTES
        {
            public Int32 nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle; // Changed to int (0 or 1 often used)
        }
        // --- Added for Username Logging ---
        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_USER {
            public SID_AND_ATTRIBUTES User;
        }
        // --- End Added for Username Logging ---
        // --- Added for Username Logging ---
        public enum SID_NAME_USE {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }
        // --- End Added for Username Logging ---
    }
    internal class NativeMethods
    {
        [DllImport("kernel32", SetLastError = true)]
        public static extern uint WaitForSingleObject(
          IntPtr hHandle,
          uint dwMilliseconds); // Changed to uint

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(
            IntPtr hObject); // Changed name for clarity

        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(
            ref IntPtr lpEnvironment,
            SafeHandle hToken, // Use SafeHandle base class
            bool bInherit);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUserW(
            SafeHandle hToken, // Use SafeHandle
            String lpApplicationName,
            StringBuilder lpCommandLine, // Use StringBuilder for mutable string
            ref NativeHelpers.SECURITY_ATTRIBUTES lpProcessAttributes, // Pass struct by ref
            ref NativeHelpers.SECURITY_ATTRIBUTES lpThreadAttributes, // Pass struct by ref
            bool bInheritHandles, // Changed name for clarity
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref NativeHelpers.STARTUPINFO lpStartupInfo, // Pass struct by ref
            out NativeHelpers.PROCESS_INFORMATION lpProcessInformation); // Pass struct by out

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DestroyEnvironmentBlock(
            IntPtr lpEnvironment);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(
            SafeHandle ExistingTokenHandle, // Use SafeHandle
            uint dwDesiredAccess, // Typically uses constants like TOKEN_DUPLICATE | TOKEN_QUERY
            ref NativeHelpers.SECURITY_ATTRIBUTES lpTokenAttributes, // Pass struct by ref
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out SafeNativeHandle DuplicateTokenHandle); // Use SafeNativeHandle

        [DllImport("kernel32")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            SafeHandle TokenHandle, // Use SafeHandle
            uint TokenInformationClass, // TOKEN_INFORMATION_CLASS enum value
            SafeMemoryBuffer TokenInformation, // Use SafeMemoryBuffer
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupPrivilegeName(
            string lpSystemName,
            ref NativeHelpers.LUID lpLuid, // Pass LUID by ref
            StringBuilder lpName,
            ref Int32 cchName);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            TokenAccessLevels DesiredAccess, // Use TokenAccessLevels enum
            out SafeNativeHandle TokenHandle); // Use SafeNativeHandle

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved, // Should be 0
            int Version,  // Should be 1
            ref IntPtr ppSessionInfo,
            ref int pCount);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(
            IntPtr pMemory);

        [DllImport("kernel32.dll")]
        public static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSQueryUserToken(
            uint SessionId,
            out SafeNativeHandle phToken); // Use SafeNativeHandle

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreatePipe(
            ref IntPtr hReadPipe, // Changed to IntPtr for easier management
            ref IntPtr hWritePipe, // Changed to IntPtr
            ref NativeHelpers.SECURITY_ATTRIBUTES lpPipeAttributes, // Pass struct by ref
            Int32 nSize); // 0 for default buffer size

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetHandleInformation(
            IntPtr hObject, // Use IntPtr
            int dwMask, // HANDLE_FLAG constants (e.g., HANDLE_FLAG_INHERIT)
            int dwFlags); // Flags to set (0 to remove)

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(
            IntPtr hFile, // Use IntPtr
            [Out] byte[] lpBuffer, // Output buffer
            int nNumberOfBytesToRead,
            ref int lpNumberOfBytesRead, // Use ref for bytes read
            IntPtr lpOverlapped); // Typically IntPtr.Zero for synchronous operations


        // DuplicateHandle signature seems problematic. The ushort might be wrong.
        // Usually, source/target handles are IntPtr. Let's assume IntPtr for now.
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
           IntPtr hSourceHandle, // Changed ushort to IntPtr
           IntPtr hTargetProcessHandle,
           out IntPtr lpTargetHandle,
           uint dwDesiredAccess,
           [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
           uint dwOptions); // DUPLICATE_SAME_ACCESS, DUPLICATE_CLOSE_SOURCE
        // --- Added for Username Logging ---
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool LookupAccountSid(
            string lpSystemName, // null for local system
            IntPtr Sid,
            StringBuilder lpName,
            ref uint cchName,
            StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out NativeHelpers.SID_NAME_USE peUse);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertSidToStringSid(
            IntPtr pSID,
            out IntPtr ptrSid); // Use IntPtr for string pointer

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);
        // --- End Added for Username Logging ---
    }

    // SafeHandle wrapper for HGLOBAL memory allocated by Marshal.AllocHGlobal
    internal class SafeMemoryBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        // Constructor for allocating memory
        public SafeMemoryBuffer(int cb) : base(true)
        {
            base.SetHandle(Marshal.AllocHGlobal(cb));
            // Consider adding capacity property if needed
        }

        // Constructor for existing handle (use with caution, ensure ownership is transferred)
        public SafeMemoryBuffer(IntPtr handle) : base(true)
        {
            base.SetHandle(handle);
        }

        // Constructor needed for P/Invoke GetTokenInformation (size = 0 case)
        private SafeMemoryBuffer() : base(true) { }


        protected override bool ReleaseHandle()
        {
            if (handle != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(handle);
                handle = IntPtr.Zero; // Mark as freed
                return true;
            }
            return false; // Already freed or never allocated
        }
    }

    // SafeHandle wrapper for native handles closed with CloseHandle
    internal class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        // Private constructor for P/Invoke to use.
        private SafeNativeHandle() : base(true) { }

        // Public constructor if needed (e.g., wrapping an existing handle)
        public SafeNativeHandle(IntPtr handle) : base(true)
        {
            SetHandle(handle);
        }

        // Allows checking if the handle is valid (non-zero, non-invalid)
        public bool IsValid // Replaced expression body for C# 5 compatibility
        {
            get { return !IsInvalid && !IsClosed; }
        }


        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseHandle(handle);
        }
    }
    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3,
    }
    internal enum SW // ShowWindow Commands
    {
        SW_HIDE = 0,
        SW_SHOWNORMAL = 1,
        SW_NORMAL = 1,
        SW_SHOWMINIMIZED = 2,
        SW_SHOWMAXIMIZED = 3,
        SW_MAXIMIZE = 3,
        SW_SHOWNOACTIVATE = 4,
        SW_SHOW = 5,
        SW_MINIMIZE = 6,
        SW_SHOWMINNOACTIVE = 7,
        SW_SHOWNA = 8,
        SW_RESTORE = 9,
        SW_SHOWDEFAULT = 10,
        SW_MAX = 10 // Note: Some sources say SW_FORCEMINIMIZE is 11
    }

    // TOKEN_INFORMATION_CLASS subset needed
    internal enum TokenInformationClass
    {
         TokenUser = 1,
         TokenGroups = 2,
         TokenPrivileges = 3,
         // ... other values
         TokenElevationType = 18,
         TokenLinkedToken = 19,
         TokenSessionId = 12,
         // ... other values
    }


    internal enum TokenElevationType
    {
        TokenElevationTypeDefault = 1,
        TokenElevationTypeFull,
        TokenElevationTypeLimited,
    }
    internal enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation = 2
    }
    internal enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive,
        WTSConnected,
        WTSConnectQuery,
        WTSShadow,
        WTSDisconnected,
        WTSIdle,
        WTSListen,
        WTSReset,
        WTSDown,
        WTSInit
    }
    [Flags]
    public enum PrivilegeAttributes : uint
    {
        Disabled = 0x00000000,
        EnabledByDefault = 0x00000001,
        Enabled = 0x00000002,
        Removed = 0x00000004,
        UsedForAccess = 0x80000000,
    }

    [Flags]
    public enum TokenAccessLevels : uint
    {
        AssignPrimary = 0x0001,
        Duplicate = 0x0002,
        Impersonate = 0x0004,
        Query = 0x0008,
        QuerySource = 0x0010,
        AdjustPrivileges = 0x0020,
        AdjustGroups = 0x0040,
        AdjustDefault = 0x0080,
        AdjustSessionId = 0x0100,
        Read = 0x00020000 | Query, // STANDARD_RIGHTS_READ | Query
        Write = 0x00020000 | AdjustPrivileges | AdjustGroups | AdjustDefault, // STANDARD_RIGHTS_WRITE | AdjustPrivileges | AdjustGroups | AdjustDefault
        AllAccess = 0x000F0000 | AssignPrimary | Duplicate | Impersonate | Query | QuerySource | AdjustPrivileges | AdjustGroups | AdjustDefault | AdjustSessionId // STANDARD_RIGHTS_REQUIRED | ...
    }


    public static class ProcessExtensions
    {
        #region Win32 Constants
        // Creation Flags for CreateProcessAsUser
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint CREATE_NEW_CONSOLE = 0x00000010;
        private const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000; // Allows process to run outside the job object of the parent
        private const uint NORMAL_PRIORITY_CLASS = 0x00000020;


        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        // Handle Flags
        private const int HANDLE_FLAG_INHERIT = 0x00000001;
        private const int HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x00000002;

        // STARTUPINFO Flags
        private const uint STARTF_USESTDHANDLES = 0x00000100;

        // Token Access Rights
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_ADJUST_GROUPS = 0x0040;
        private const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private const uint TOKEN_ADJUST_SESSIONID = 0x0100;
        private const uint TOKEN_ALL_ACCESS = (uint)TokenAccessLevels.AllAccess; // Cast enum to uint for const
        private const uint TOKEN_READ = (uint)TokenAccessLevels.Read; // Cast enum to uint for const
        private const uint TOKEN_WRITE = (uint)TokenAccessLevels.Write; // Cast enum to uint for const

        // Other constants
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int ERROR_BAD_LENGTH = 24; // Sometimes returned instead of 122
        private const int BUFSIZE = 4096; // Buffer for pipe reads
        private const uint ERROR_BROKEN_PIPE = 109; // Expected error when pipe is closed


        #endregion

        // Gets the primary user token for the currently active user session.
        private static SafeNativeHandle GetSessionUserToken(bool getElevatedToken)
        {
            uint activeSessionId = INVALID_SESSION_ID;
            IntPtr pSessionInfo = IntPtr.Zero;
            int sessionCount = 0;

            // Try enumerating sessions to find the active one.
            if (NativeMethods.WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount))
            {
                try
                {
                    IntPtr current = pSessionInfo;
                    int dataSize = Marshal.SizeOf(typeof(NativeHelpers.WTS_SESSION_INFO));
                    for (int i = 0; i < sessionCount; i++)
                    {
                        NativeHelpers.WTS_SESSION_INFO si = (NativeHelpers.WTS_SESSION_INFO)Marshal.PtrToStructure(current, typeof(NativeHelpers.WTS_SESSION_INFO));
                        current = IntPtr.Add(current, dataSize); // Move pointer to next struct
                        if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                        {
                            activeSessionId = si.SessionID;
                            Console.WriteLine(string.Format("DEBUG: Found active session {0} via WTSEnumerateSessions.", activeSessionId)); // Replaced string interpolation for C# 5 compatibility
                            break;
                        }
                    }
                }
                finally
                {
                    NativeMethods.WTSFreeMemory(pSessionInfo);
                }
            }
            else
            {
                 int error = Marshal.GetLastWin32Error();
                 Console.WriteLine(string.Format("[WARNING] WTSEnumerateSessions failed with code: {0}. Falling back...", error));
            }


            // Fallback if enumeration failed or no active session was found
            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = NativeMethods.WTSGetActiveConsoleSessionId();
                if (activeSessionId == INVALID_SESSION_ID) // 0xFFFFFFFF
                {
                     // This can happen if no user is logged in or in certain service contexts.
                     throw new Win32Exception("Could not get active console session ID. No user might be logged on.");
                }
                Console.WriteLine(string.Format("DEBUG: Using active console session ID: {0} (fallback).", activeSessionId));
            }
            Console.WriteLine(string.Format("DEBUG_CS_SESSION: Target Session ID is {0}", activeSessionId));

            SafeNativeHandle hImpersonationToken;
            if (!NativeMethods.WTSQueryUserToken(activeSessionId, out hImpersonationToken))
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine(string.Format("[ERROR] WTSQueryUserToken failed for session {0}. Error Code: {1}", activeSessionId, error));
                throw new Win32Exception(error, string.Format("WTSQueryUserToken failed for session {0}", activeSessionId));
            }

            // WTSQueryUserToken returns an impersonation token. We need a primary token for CreateProcessAsUser.
            using (hImpersonationToken) // Ensure impersonation token is disposed
            {
                // Check if the user wants the elevated token and if UAC is involved
                 if (getElevatedToken)
                 {
                     try
                     {
                         TokenElevationType elevationType = GetTokenElevationType(hImpersonationToken);
                         if (elevationType == TokenElevationType.TokenElevationTypeLimited)
                         {
                             Console.WriteLine("DEBUG: Current token is limited, attempting to get linked elevated token.");
                             using (SafeNativeHandle linkedToken = GetTokenLinkedToken(hImpersonationToken))
                             {
                                 return DuplicateTokenAsPrimary(linkedToken); // Get primary token from the elevated linked token
                             }
                         }
                         else if (elevationType == TokenElevationType.TokenElevationTypeFull)
                         {
                             Console.WriteLine("DEBUG: Current token is already full (elevated or UAC off).");
                         }
                         else // TokenElevationTypeDefault
                         {
                             Console.WriteLine("DEBUG: Token elevation type is default (UAC likely off or not applicable).");
                         }
                     }
                     catch (Win32Exception ex)
                     {
                         if (ex.NativeErrorCode == 1312) // ERROR_NO_SUCH_LOGON_SESSION (often means no linked token)
                         {
                             Console.WriteLine("[WARNING] Could not get linked token (Error 1312). Proceeding with the limited token.");
                             // Fall through to duplicate the limited token if getting the elevated one failed.
                         }
                         else
                         {
                             throw; // Re-throw exception if condition not met
                         }
                     }
                     catch (Exception ex) // Added variable 'ex' back
                     {
                         Console.WriteLine(string.Format("[WARNING] Error checking/getting linked token: {0}. Proceeding with the current token.", ex.Message));
                         // Fall through if any other error occurs during elevation check/linked token retrieval.
                     }
                 }
                 else // getElevatedToken is false
                 {
                     Console.WriteLine("DEBUG: Elevated token not requested. Using the standard token.");
                 }


                 // Duplicate the (potentially limited) impersonation token as a primary token.
                 return DuplicateTokenAsPrimary(hImpersonationToken);
            }
        }


        public static string StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true, int wait = -1, bool elevated = true, bool redirectOutput = true, bool breakaway = false )
        {
            string result = string.Empty; // Initialize result
            // SafeNativeHandle hUserToken = null; // Commented out unused variable
            SafeNativeHandle primaryToken = null;
            IntPtr pEnv = IntPtr.Zero;
            NativeHelpers.PROCESS_INFORMATION procInfo = new NativeHelpers.PROCESS_INFORMATION();
            NativeHelpers.STARTUPINFO startInfo = new NativeHelpers.STARTUPINFO();
            IntPtr out_read_ptr = IntPtr.Zero, out_write_ptr = IntPtr.Zero; // Raw pipe handles
            IntPtr err_read_ptr = IntPtr.Zero, err_write_ptr = IntPtr.Zero; // Raw pipe handles


            SafeNativeHandle out_read = null, out_write = null; // Safe handle wrappers
            SafeNativeHandle err_read = null, err_write = null;

            try // Outer try for resource acquisition (token, env block, pipes)
            {
                 Console.WriteLine(string.Format("DEBUG: Entered StartProcessAsCurrentUser C#. App: '{0}', Elevated: {1}, Redirect: {2}", appPath, elevated, redirectOutput));


                 // 1. Get User Token
                 primaryToken = GetSessionUserToken(elevated); // This function now returns the desired primary token
                 // --- Added for Username Logging ---
                 try
                 {
                     int tokenInfoLength = 0;
                     // First call to get required buffer size for TokenUser
                     // Use primaryToken which should be valid here
                     NativeMethods.GetTokenInformation(primaryToken, (uint)TokenInformationClass.TokenUser, null, 0, out tokenInfoLength);
                     int error = Marshal.GetLastWin32Error();
                     if (error == ERROR_INSUFFICIENT_BUFFER || error == ERROR_BAD_LENGTH) // Allow ERROR_BAD_LENGTH too
                     {
                         using (SafeMemoryBuffer tokenInfo = new SafeMemoryBuffer(tokenInfoLength))
                         {
                             if (NativeMethods.GetTokenInformation(primaryToken, (uint)TokenInformationClass.TokenUser, tokenInfo, tokenInfoLength, out tokenInfoLength))
                             {
                                 NativeHelpers.TOKEN_USER tokenUser = (NativeHelpers.TOKEN_USER)Marshal.PtrToStructure(tokenInfo.DangerousGetHandle(), typeof(NativeHelpers.TOKEN_USER));

                                 uint nameSize = 0;
                                 uint domainNameSize = 0;
                                 NativeHelpers.SID_NAME_USE sidUse;
                                 // Get buffer sizes for LookupAccountSid
                                 NativeMethods.LookupAccountSid(null, tokenUser.User.Sid, null, ref nameSize, null, ref domainNameSize, out sidUse);
                                 error = Marshal.GetLastWin32Error();
                                 if (error == ERROR_INSUFFICIENT_BUFFER)
                                 {
                                     StringBuilder name = new StringBuilder((int)nameSize);
                                     StringBuilder domainName = new StringBuilder((int)domainNameSize);
                                     if (NativeMethods.LookupAccountSid(null, tokenUser.User.Sid, name, ref nameSize, domainName, ref domainNameSize, out sidUse))
                                     {
                                         Console.WriteLine(string.Format("DEBUG_CS_USER: Running under token for user: {0}\\{1} (SID Type: {2})", domainName.ToString(), name.ToString(), sidUse));
                                     }
                                     else
                                     {
                                         error = Marshal.GetLastWin32Error();
                                         Console.WriteLine(string.Format("DEBUG_CS_USER: LookupAccountSid (data retrieval) failed. Error Code: {0}", error));
                                     }
                                 }
                                 else
                                 {
                                     Console.WriteLine(string.Format("DEBUG_CS_USER: LookupAccountSid (size query) failed. Error Code: {0}", error));
                                 }
                             }
                             else
                             {
                                 error = Marshal.GetLastWin32Error();
                                 Console.WriteLine(string.Format("DEBUG_CS_USER: GetTokenInformation (TokenUser data retrieval) failed. Error Code: {0}", error));
                             }
                         }
                     }
                     else
                     {
                          Console.WriteLine(string.Format("DEBUG_CS_USER: GetTokenInformation (TokenUser size query) failed. Error Code: {0}", error));
                     }
                 }
                 catch (Exception ex)
                 {
                     Console.WriteLine(string.Format("DEBUG_CS_USER: Exception during username lookup: {0}", ex.Message));
                 }
                 // --- End Added for Username Logging ---


                 // 2. Prepare Environment Block
                 if (!NativeMethods.CreateEnvironmentBlock(ref pEnv, primaryToken, false))
                 {
                     int error = Marshal.GetLastWin32Error();
                     Console.WriteLine(string.Format("[ERROR] CreateEnvironmentBlock failed with code: {0}", error));
                     throw new Win32Exception(error, "CreateEnvironmentBlock failed.");
                 }
                 Console.WriteLine("DEBUG: Environment block created.");

                 // 3. Prepare Pipes and STARTUPINFO if redirecting
                 if (redirectOutput)
                 {
                     NativeHelpers.SECURITY_ATTRIBUTES saAttr = new NativeHelpers.SECURITY_ATTRIBUTES();
                     saAttr.nLength = Marshal.SizeOf(saAttr);
                     saAttr.bInheritHandle = 1; // TRUE - Pipe handles should be inheritable
                     saAttr.lpSecurityDescriptor = IntPtr.Zero; // NULL

                     // Create StdOut pipe
                     if (!NativeMethods.CreatePipe(ref out_read_ptr, ref out_write_ptr, ref saAttr, 0))
                         throw new Win32Exception(Marshal.GetLastWin32Error(), "CreatePipe (stdout) failed.");

                     // Create StdErr pipe
                     if (!NativeMethods.CreatePipe(ref err_read_ptr, ref err_write_ptr, ref saAttr, 0))
                         throw new Win32Exception(Marshal.GetLastWin32Error(), "CreatePipe (stderr) failed.");

                     // Wrap raw handles in SafeNativeHandles
                     out_read = new SafeNativeHandle(out_read_ptr);
                     out_write = new SafeNativeHandle(out_write_ptr);
                     err_read = new SafeNativeHandle(err_read_ptr);
                     err_write = new SafeNativeHandle(err_write_ptr);

                     // Ensure the read ends of the pipes are NOT inherited by the child process.
                     if (!NativeMethods.SetHandleInformation(out_read.DangerousGetHandle(), HANDLE_FLAG_INHERIT, 0)) // 0 = Remove inherit flag
                         throw new Win32Exception(Marshal.GetLastWin32Error(), "SetHandleInformation (stdout read) failed.");
                     if (!NativeMethods.SetHandleInformation(err_read.DangerousGetHandle(), HANDLE_FLAG_INHERIT, 0))
                         throw new Win32Exception(Marshal.GetLastWin32Error(), "SetHandleInformation (stderr read) failed.");

                     startInfo.dwFlags = STARTF_USESTDHANDLES;
                     startInfo.hStdOutput = out_write.DangerousGetHandle(); // Write end is inherited
                     startInfo.hStdError = err_write.DangerousGetHandle();  // Write end is inherited
                     startInfo.hStdInput = IntPtr.Zero; // No input redirection for now
                     Console.WriteLine("DEBUG: Pipes created and configured for redirection.");
                 }
                 else
                 {
                     Console.WriteLine("DEBUG: Output redirection disabled.");
                 }


                 // 4. Prepare STARTUPINFO essentials
                 startInfo.cb = Marshal.SizeOf(startInfo);
                 startInfo.lpDesktop = @"winsta0\default"; // Explicitly target interactive desktop
                 Console.WriteLine(string.Format("DEBUG_CS_DESKTOP: STARTUPINFO.lpDesktop set to: {0}", (startInfo.lpDesktop != null ? startInfo.lpDesktop : "null"))); // Added DEBUG log
                 // Control window state based on 'visible' parameter
                 if (visible) {
                     startInfo.wShowWindow = (short)SW.SW_SHOWNORMAL; // Value 1: Show normally
                 } else {
                     // Use SW_SHOWMINNOACTIVE (7) to launch minimized without stealing focus
                     startInfo.wShowWindow = (short)SW.SW_SHOWMINNOACTIVE; // Value 7: Show minimized, not active
                 }

                 // 5. Prepare Creation Flags
                 // Base creation flags: Unicode environment and normal priority.
                 // CREATE_NO_WINDOW is intentionally omitted to allow wShowWindow to control visibility.
                 uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS;

                 if (breakaway)
                 {
                     dwCreationFlags |= CREATE_BREAKAWAY_FROM_JOB;
                      Console.WriteLine("DEBUG: CREATE_BREAKAWAY_FROM_JOB flag set.");
                 }


                 // 6. Prepare Process and Thread Attributes (using default security)
                 NativeHelpers.SECURITY_ATTRIBUTES procSecAttrs = new NativeHelpers.SECURITY_ATTRIBUTES();
                 procSecAttrs.nLength = Marshal.SizeOf(procSecAttrs);
                 NativeHelpers.SECURITY_ATTRIBUTES threadSecAttrs = new NativeHelpers.SECURITY_ATTRIBUTES();
                 threadSecAttrs.nLength = Marshal.SizeOf(threadSecAttrs);

                 // 7. Determine Application and Command Line based on appPath extension
                 string applicationToLaunch = null;
                 StringBuilder finalCommandLine = null;

                 // The PowerShell wrapper now determines the correct executable ($appPath)
                 // and the full command line ($commandLineArgs) needed by CreateProcessAsUserW.
                 // The C# method simply passes them through.
                 Console.WriteLine("DEBUG: Using pre-determined executable and command line from PowerShell wrapper.");
                 applicationToLaunch = appPath; // This is now always the executable path (e.g., powershell.exe or myapp.exe)
                 finalCommandLine = new StringBuilder(cmdLine ?? ""); // This is now the full argument string

                 // Log the actual parameters being used
                 Console.WriteLine(string.Format("DEBUG: Calling CreateProcessAsUserW. App: '{0}', CmdLine: '{1}', Dir: '{2}', Flags: {3}",
                     applicationToLaunch,
                     finalCommandLine.ToString(),
                     (workDir != null ? workDir : "Default"), // Use TEMP if workDir is null? C# sets TEMP later.
                     dwCreationFlags));

                 // 8. Create the Process
                 Console.WriteLine(string.Format("DEBUG_CS_STARTINFO: lpDesktop='{0}', dwFlags={1}, wShowWindow={2}", startInfo.lpDesktop, startInfo.dwFlags, startInfo.wShowWindow));
                 bool processCreated = NativeMethods.CreateProcessAsUserW(
                      primaryToken,         // User token
                      applicationToLaunch,  // Determined application (.exe path or powershell.exe)
                      finalCommandLine,     // Constructed command line (args for .exe, or PS command for scripts)
                      ref procSecAttrs,     // Process attributes
                      ref threadSecAttrs,   // Thread attributes
                      redirectOutput,       // Inherit handles ONLY if redirecting
                      dwCreationFlags,      // Creation flags
                      pEnv,                 // Environment block
                      System.IO.Path.GetTempPath(), // Explicitly set Working directory to TEMP
                      ref startInfo,        // Startup info
                      out procInfo);        // Process information (out)


                 // 9. Handle Process Creation Result
                 if (!processCreated)
                 {
                     int error = Marshal.GetLastWin32Error();
                     // Use string.Format for C# 5 compatibility
                     Console.WriteLine(string.Format("[ERROR] CreateProcessAsUserW failed with code: {0}", error));
                     // Use string.Format for the exception message
                     throw new Win32Exception(error, string.Format("CreateProcessAsUserW failed for App: '{0}', Command: '{1}'", applicationToLaunch, finalCommandLine.ToString()));
                 }

                 Console.WriteLine(string.Format("DEBUG: Process created successfully. PID: {0}, TID: {1}", procInfo.dwProcessId, procInfo.dwThreadId));

                 // 10. Close unnecessary handles in the *parent* process immediately
                 // Close the write ends of the pipes in the parent. The child inherits them.
                 // The read ends must remain open in the parent to read the output.
                 if (redirectOutput)
                 {
                     if (out_write != null) { out_write.Close(); out_write = null; } // Replaced ?. for C# 5
                     if (err_write != null) { err_write.Close(); err_write = null; } // Replaced ?. for C# 5
                     Console.WriteLine("DEBUG: Closed write ends of pipes in parent.");
                 }

                 // Close the thread handle; we don't need it after process creation unless we plan to manipulate the main thread.
                 if (procInfo.hThread != IntPtr.Zero)
                 {
                     NativeMethods.CloseHandle(procInfo.hThread);
                     Console.WriteLine("DEBUG: Closed process's main thread handle.");
                     procInfo.hThread = IntPtr.Zero; // Mark as closed
                 }

                 // 11. Wait for process and read output (if applicable)
                 if (redirectOutput)
                 {
                     var outputBuilder = new StringBuilder();
                     var errorBuilder = new StringBuilder();
                     byte[] buffer = new byte[BUFSIZE];
                     int bytesRead = 0;

                      Console.WriteLine("DEBUG: Reading from StdOut pipe...");
                     // Read StdOut
                     while (out_read != null && !out_read.IsInvalid && !out_read.IsClosed) // Check safe handle state
                     {
                         bytesRead = 0;
                         bool readFileSuccess = NativeMethods.ReadFile(out_read.DangerousGetHandle(), buffer, BUFSIZE, ref bytesRead, IntPtr.Zero);

                         if (readFileSuccess && bytesRead > 0)
                         {
                             outputBuilder.Append(Encoding.UTF8.GetString(buffer, 0, bytesRead)); // Assuming UTF-8 output
                         }
                         else
                         {
                             int lastError = Marshal.GetLastWin32Error();
                              if (lastError == ERROR_BROKEN_PIPE || !readFileSuccess) // Pipe closed by child or other error
                              {
                                   Console.WriteLine(string.Format("DEBUG: StdOut pipe read finished or broken (Error: {0}). Breaking read loop.", lastError));
                                   break;
                              }
                             // If ReadFile returned true but bytesRead is 0, it's also EOF
                             Console.WriteLine("DEBUG: StdOut pipe read returned 0 bytes. Breaking read loop.");
                             break;
                         }
                     }
                     Console.WriteLine(string.Format("DEBUG: Finished reading StdOut pipe. Read {0} chars.", outputBuilder.Length));


                     Console.WriteLine("DEBUG: Reading from StdErr pipe...");
                     // Read StdErr
                     while (err_read != null && !err_read.IsInvalid && !err_read.IsClosed) // Check safe handle state
                     {
                         bytesRead = 0;
                         bool readFileSuccess = NativeMethods.ReadFile(err_read.DangerousGetHandle(), buffer, BUFSIZE, ref bytesRead, IntPtr.Zero);

                         if (readFileSuccess && bytesRead > 0)
                         {
                             errorBuilder.Append(Encoding.UTF8.GetString(buffer, 0, bytesRead)); // Assuming UTF-8 output
                         }
                         else
                         {
                              int lastError = Marshal.GetLastWin32Error();
                              if (lastError == ERROR_BROKEN_PIPE || !readFileSuccess) // Pipe closed by child or other error
                              {
                                   Console.WriteLine(string.Format("DEBUG: StdErr pipe read finished or broken (Error: {0}). Breaking read loop.", lastError));
                                   break;
                              }
                             Console.WriteLine("DEBUG: StdErr pipe read returned 0 bytes. Breaking read loop.");
                             break;
                         }
                     }
                     Console.WriteLine(string.Format("DEBUG: Finished reading StdErr pipe. Read {0} chars.", errorBuilder.Length));


                     // Combine results only after waiting (if required) or after confirming process ended if not waiting.
                     // Replace the existing wait block with this:
                     if (wait != 0) // wait = 0 means NoWait was specified in PowerShell
                     {
                          Console.WriteLine(string.Format("DEBUG: Waiting for process {0} to exit (timeout: {1} ms)...", procInfo.dwProcessId, wait));
                          uint waitResult = NativeMethods.WaitForSingleObject(procInfo.hProcess, (uint)wait);
                          Console.WriteLine(string.Format("DEBUG: Wait finished for process {0}.", procInfo.dwProcessId));
                     }

                     // Format the output
                     var finalResultBuilder = new StringBuilder();
                     string stdoutContent = outputBuilder.ToString().TrimEnd('\r', '\n');
                     string rawStderrContent = errorBuilder.ToString().TrimEnd('\r', '\n');
                     // Removed CLIXML processing for stderr

                     if (!string.IsNullOrEmpty(stdoutContent)) {
                         finalResultBuilder.AppendLine("[STDOUT]");
                         finalResultBuilder.AppendLine(stdoutContent);
                     }
                     if (!string.IsNullOrEmpty(rawStderrContent)) { // Use rawStderrContent directly
                         finalResultBuilder.AppendLine("[STDERR_XML]"); // Use XML marker as requested
                         // Simple XML escaping for CDATA resilience
                         string escapedStderr = rawStderrContent.Replace("]]>", "]]>]]><![CDATA[");
                         finalResultBuilder.AppendLine("<stderr><![CDATA[" + escapedStderr + "]]></stderr>"); // Wrap raw content in CDATA
                     }
                     result = finalResultBuilder.ToString();
                 }
                 else // Not redirecting output
                 {
                      if (wait != 0 && procInfo.hProcess != IntPtr.Zero)
                      {
                          Console.WriteLine(string.Format("DEBUG: Waiting for process {0} to exit (timeout: {1} ms)...", procInfo.dwProcessId, wait));
                          uint waitResult = NativeMethods.WaitForSingleObject(procInfo.hProcess, (uint)wait);
                          Console.WriteLine(string.Format("DEBUG: Wait finished for process {0}.", procInfo.dwProcessId));
                          result = string.Format("Process {0} completed.", procInfo.dwProcessId); // Or return exit code if needed
                      }
                      else
                      {
                          Console.WriteLine(string.Format("DEBUG: Process {0} started without waiting (wait=0).", procInfo.dwProcessId));
                          result = procInfo.dwProcessId.ToString(); // Return PID if not waiting
                      }
                 }
            }
            catch (Exception ex)
            {
                 Console.WriteLine(string.Format("[ERROR] Exception in StartProcessAsCurrentUser: {0} - {1}", ex.GetType().Name, ex.Message)); // C# 5 string format
                 if (ex is Win32Exception) // C# 5 type check
                 {
                     Win32Exception w32ex = (Win32Exception)ex; // C# 5 explicit cast
                     result = string.Format("[ERROR] Win32 Error {0}: {1}", w32ex.NativeErrorCode, w32ex.Message); // C# 5 string format
                 }
                 else
                 {
                     result = string.Format("[ERROR] {0}: {1}", ex.GetType().Name, ex.Message); // C# 5 string format
                 }
                 // Indicate failure in the result if an exception occurred
                 // Format the failure message correctly
                 result = string.Format("[FAILURE] {0}", result);
            }
            finally // Cleanup resources in reverse order of creation
            {
                Console.WriteLine("DEBUG: Entering final cleanup block...");
                // Close process handle (must be done after waiting and after reading pipes potentially)
                if (procInfo.hProcess != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(procInfo.hProcess);
                    Console.WriteLine(string.Format("DEBUG: Closed process handle for PID {0}.", procInfo.dwProcessId));
                    procInfo.hProcess = IntPtr.Zero;
                }
                 // Close thread handle if somehow still open (should be closed earlier)
                if (procInfo.hThread != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(procInfo.hThread);
                     Console.WriteLine("DEBUG: Closed process's main thread handle (in finally).");
                }


                // Close pipe handles (SafeHandles handle closing automatically via Dispose, but explicit Close is okay too)
                if (out_read != null) out_read.Close(); // Replaced ?. for C# 5
                if (out_write != null) out_write.Close(); // Replaced ?. for C# 5
                if (err_read != null) err_read.Close(); // Replaced ?. for C# 5
                if (err_write != null) err_write.Close(); // Replaced ?. for C# 5
                 if (redirectOutput) Console.WriteLine("DEBUG: Ensured pipe safe handles are closed.");

                // Destroy environment block
                if (pEnv != IntPtr.Zero)
                {
                    NativeMethods.DestroyEnvironmentBlock(pEnv);
                    Console.WriteLine("DEBUG: Destroyed environment block.");
                    pEnv = IntPtr.Zero;
                }

                // Close user token handle (SafeHandle handles closing automatically via Dispose)
                 if (primaryToken != null) primaryToken.Dispose(); // Replaced ?. for C# 5
                 if (primaryToken != null) Console.WriteLine("DEBUG: Disposed primary user token handle.");


                // hUserToken is disposed within its own scope in GetSessionUserToken

                 Console.WriteLine("DEBUG: Exiting final cleanup block.");
            }

            // *** The missing bracket was here ***
            //} // THIS WAS THE MISSING BRACKET closing the outer try block from line 368

            Console.WriteLine(string.Format("DEBUG: Returning result: {0}", (result.Length > 100 ? result.Substring(0,100) + "..." : result))); // Replaced invalid interpolation with string.Format
            return result; // Return the captured output, PID, or error string
        } // End StartProcessAsCurrentUser


        // Duplicates an impersonation or primary token into a primary token.
        private static SafeNativeHandle DuplicateTokenAsPrimary(SafeHandle hToken)
        {
            SafeNativeHandle primaryToken;
            NativeHelpers.SECURITY_ATTRIBUTES tokenAttrs = new NativeHelpers.SECURITY_ATTRIBUTES(); // Optional attributes
            tokenAttrs.nLength = Marshal.SizeOf(tokenAttrs);

            // Request necessary rights for CreateProcessAsUser
            uint desiredAccess = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;


            if (!NativeMethods.DuplicateTokenEx(
                    hToken,
                    desiredAccess, // Request necessary access rights
                    ref tokenAttrs, // Default security attributes
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, // Impersonation level (doesn't strictly matter for primary token)
                    TOKEN_TYPE.TokenPrimary, // We want a primary token
                    out primaryToken))
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine(string.Format("[ERROR] DuplicateTokenEx failed with code: {0}", error));
                throw new Win32Exception(error, "DuplicateTokenEx failed to create primary token.");
            }
            Console.WriteLine("DEBUG: Duplicated token as primary successfully.");
            return primaryToken;
        }

        // Gets the privileges associated with a token.
        public static Dictionary<String, PrivilegeAttributes> GetTokenPrivileges(SafeHandle hToken)
        {
            var privileges = new Dictionary<string, PrivilegeAttributes>();
            int bufferSize = 0;

            // First call to GetTokenInformation to get the required buffer size.
            // Pass IntPtr.Zero for the buffer. Error 122 (ERROR_INSUFFICIENT_BUFFER) is expected.
            NativeMethods.GetTokenInformation(hToken, (uint)TokenInformationClass.TokenPrivileges, null, 0, out bufferSize);
            int error = Marshal.GetLastWin32Error();
            if (error != ERROR_INSUFFICIENT_BUFFER)
            {
                 Console.WriteLine(string.Format("[ERROR] GetTokenInformation (size query) failed unexpectedly. Code: {0}", error));
                 throw new Win32Exception(error, "GetTokenInformation failed to query size for privileges.");
            }


            using (SafeMemoryBuffer tokenInfo = new SafeMemoryBuffer(bufferSize))
            {
                 // Second call to get the actual privilege information.
                 if (!NativeMethods.GetTokenInformation(hToken, (uint)TokenInformationClass.TokenPrivileges, tokenInfo, bufferSize, out bufferSize))
                 {
                     error = Marshal.GetLastWin32Error();
                      Console.WriteLine(string.Format("[ERROR] GetTokenInformation (data retrieval) failed. Code: {0}", error));
                     throw new Win32Exception(error, "GetTokenInformation failed to retrieve privileges.");
                 }


                 // Marshal the initial part of the structure (PrivilegeCount)
                 NativeHelpers.TOKEN_PRIVILEGES privilegeInfo = (NativeHelpers.TOKEN_PRIVILEGES)Marshal.PtrToStructure(
                     tokenInfo.DangerousGetHandle(),
                     typeof(NativeHelpers.TOKEN_PRIVILEGES));

                 // Calculate the starting point of the LUID_AND_ATTRIBUTES array.
                 // The array starts right after the PrivilegeCount field (which is an int = 4 bytes).
                 IntPtr arrayPtr = IntPtr.Add(tokenInfo.DangerousGetHandle(), sizeof(int)); // Offset past PrivilegeCount
                 int luidaSize = Marshal.SizeOf(typeof(NativeHelpers.LUID_AND_ATTRIBUTES));

                 for (int i = 0; i < privilegeInfo.PrivilegeCount; i++)
                 {
                     // Marshal each LUID_AND_ATTRIBUTES structure from the array.
                     NativeHelpers.LUID_AND_ATTRIBUTES laa = (NativeHelpers.LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                         IntPtr.Add(arrayPtr, i * luidaSize), // Calculate pointer for current element
                         typeof(NativeHelpers.LUID_AND_ATTRIBUTES));

                     NativeHelpers.LUID privLuid = laa.Luid; // Local copy for LookupPrivilegeName
                     int nameLen = 0;

                     // First call to LookupPrivilegeName to get the required name buffer size.
                     NativeMethods.LookupPrivilegeName(null, ref privLuid, null, ref nameLen);
                     error = Marshal.GetLastWin32Error();
                      if (error != ERROR_INSUFFICIENT_BUFFER)
                      {
                         Console.WriteLine(string.Format("[ERROR] LookupPrivilegeName (size query) failed. Code: {0}", error));
                         // Continue to next privilege or throw? Let's log and continue.
                         continue;
                      }


                     StringBuilder name = new StringBuilder(nameLen + 1); // Allocate buffer
                     // Second call to get the actual privilege name.
                     if (!NativeMethods.LookupPrivilegeName(null, ref privLuid, name, ref nameLen))
                     {
                         error = Marshal.GetLastWin32Error();
                         Console.WriteLine(string.Format("[ERROR] LookupPrivilegeName (data retrieval) failed. Code: {0}", error));
                         // Log and continue
                         continue;
                     }

                     privileges[name.ToString()] = laa.Attributes;
                 }
            }

            return privileges;
        }

        // Wrapper for GetTokenPrivileges using the current process token.
         public static Dictionary<String, PrivilegeAttributes> GetCurrentProcessTokenPrivileges()
         {
              Console.WriteLine("DEBUG: Getting current process token privileges.");
              using (SafeNativeHandle hToken = OpenProcessToken(NativeMethods.GetCurrentProcess(), TokenAccessLevels.Query))
              {
                  return GetTokenPrivileges(hToken);
              }
         }


        // Gets the elevation type of a token (Limited, Full, Default).
        private static TokenElevationType GetTokenElevationType(SafeHandle hToken)
        {
             int returnLength;
             // Size of the output buffer for TokenElevationType is just sizeof(int)
             int elevationTypeSize = sizeof(int);

             using(SafeMemoryBuffer tokenInfo = new SafeMemoryBuffer(elevationTypeSize))
             {
                if (!NativeMethods.GetTokenInformation(hToken, (uint)TokenInformationClass.TokenElevationType, tokenInfo, elevationTypeSize, out returnLength))
                {
                     int error = Marshal.GetLastWin32Error();
                     // Handle specific errors if needed, e.g., ERROR_INVALID_PARAMETER if the OS doesn't support it
                     Console.WriteLine("[ERROR] GetTokenInformation (TokenElevationType) failed. Code: {error}");
                     throw new Win32Exception(error, "Failed to get token elevation type.");
                }

                // Read the integer value from the buffer
                return (TokenElevationType)Marshal.ReadInt32(tokenInfo.DangerousGetHandle());
             }
        }

        // Gets the linked token (typically the elevated token if the current one is limited by UAC).
        private static SafeNativeHandle GetTokenLinkedToken(SafeHandle hToken)
        {
             int returnLength;
             // Size of the output buffer for TokenLinkedToken is sizeof(IntPtr) (it's a handle)
             int linkedTokenInfoSize = IntPtr.Size;

            using(SafeMemoryBuffer tokenInfo = new SafeMemoryBuffer(linkedTokenInfoSize))
            {
                if (!NativeMethods.GetTokenInformation(hToken, (uint)TokenInformationClass.TokenLinkedToken, tokenInfo, linkedTokenInfoSize, out returnLength))
                {
                    int error = Marshal.GetLastWin32Error();
                     // ERROR_NO_SUCH_LOGON_SESSION (1312) can occur if there's no linked token.
                     if (error == 1312)
                     {
                         Console.WriteLine("[INFO] No linked token found (Error 1312). This is expected if not running under split-token UAC.");
                         throw new Win32Exception(error, "No linked token available.");
                     }
                     Console.WriteLine(string.Format("[ERROR] GetTokenInformation (TokenLinkedToken) failed. Code: {0}", error));
                    throw new Win32Exception(error, "Failed to get linked token.");
                }

                // Read the IntPtr (handle) value from the buffer
                IntPtr linkedTokenPtr = Marshal.ReadIntPtr(tokenInfo.DangerousGetHandle());
                 if (linkedTokenPtr == IntPtr.Zero)
                 {
                      // Should not happen if GetTokenInformation succeeded, but check anyway.
                      throw new InvalidOperationException("GetTokenInformation succeeded but returned a null linked token handle.");
                 }
                // Wrap the raw handle in our SafeNativeHandle for proper cleanup.
                // The ownership of this handle is transferred to the SafeNativeHandle.
                return new SafeNativeHandle(linkedTokenPtr);
            }
        }

        // Helper to get specific token information classes that return simple value types (like int/uint).
        private static T GetTokenInformationSimpleValue<T>(SafeHandle hToken, TokenInformationClass infoClass) where T : struct
        {
            int returnLength;
            int dataSize = Marshal.SizeOf(typeof(T));

            using (SafeMemoryBuffer tokenInfo = new SafeMemoryBuffer(dataSize))
            {
                if (!NativeMethods.GetTokenInformation(hToken, (uint)infoClass, tokenInfo, dataSize, out returnLength))
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine(string.Format("[ERROR] GetTokenInformation ({0}) failed. Code: {1}", infoClass, error));
                    throw new Win32Exception(error, string.Format("Failed to get token information for {0}.", infoClass));
                }

                // Marshal the structure or value type from the buffer
                return (T)Marshal.PtrToStructure(tokenInfo.DangerousGetHandle(), typeof(T));
            }
        }


        // Opens the access token associated with a process.
        private static SafeNativeHandle OpenProcessToken(IntPtr processHandle, TokenAccessLevels desiredAccess)
        {
            SafeNativeHandle hToken;
            if (!NativeMethods.OpenProcessToken(processHandle, desiredAccess, out hToken))
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine(string.Format("[ERROR] OpenProcessToken failed. Code: {0}", error));
                throw new Win32Exception(error, "OpenProcessToken failed.");
            }
             Console.WriteLine(string.Format("DEBUG: Opened process token with access: {0}.", desiredAccess));
            return hToken;
        }

        // Helper method to extract plain text error message from CLIXML
        private static string ExtractErrorMessageFromCliXml(string cliXml)
        {
            if (string.IsNullOrWhiteSpace(cliXml) || !cliXml.TrimStart().StartsWith("<Objs", StringComparison.OrdinalIgnoreCase))
            {
                // Not CLIXML or empty, return as is
                return cliXml;
            }

            try
            {
                XmlDocument xmlDoc = new XmlDocument();
                // Need a namespace manager for the default PowerShell namespace
                XmlNamespaceManager nsMgr = new XmlNamespaceManager(xmlDoc.NameTable);
                nsMgr.AddNamespace("ps", "http://schemas.microsoft.com/powershell/2004/04");

                // Load the XML content
                xmlDoc.LoadXml(cliXml);

                // Find the <S N="Message"> element using XPath with the namespace
                // It might be nested within an <Obj><MS> structure for ErrorRecords
                XmlNode messageNode = xmlDoc.SelectSingleNode("//ps:S[@N='Message']", nsMgr);

                if (messageNode != null && !string.IsNullOrEmpty(messageNode.InnerText))
                {
                    // Return the inner text of the message node
                    return messageNode.InnerText.Trim();
                }
                else
                {
                    // Fallback: If specific message node not found, try getting the first <S> node's content
                    XmlNode firstSNode = xmlDoc.SelectSingleNode("//ps:S", nsMgr);
                    if (firstSNode != null && !string.IsNullOrEmpty(firstSNode.InnerText))
                    {
                        return firstSNode.InnerText.Trim();
                    }
                }
            }
            catch (XmlException ex)
            {
                // XML parsing failed, likely not valid CLIXML or malformed
                Console.WriteLine(string.Format("DEBUG: CLIXML parsing failed: {0}. Returning raw content.", ex.Message));
                return cliXml; // Return original string if parsing fails
            }
            catch (Exception ex)
            {
                // Catch other potential exceptions during processing
                Console.WriteLine(string.Format("DEBUG: Error processing potential CLIXML: {0}. Returning raw content.", ex.Message));
                return cliXml;
            }

            // If parsing succeeded but no message found, return original
            return cliXml;
        }
    }
}
"@

# Compile the C# code if the type doesn't already exist
if (-not ([System.Management.Automation.PSTypeName]'RunAsUser.ProcessExtensions').Type) {
    # Define Log Path before try block
    $addTypeLogPath = Join-Path $PSScriptRoot "runasuser_addtype_debug.log"; if (Test-Path $addTypeLogPath) { Remove-Item $addTypeLogPath -Force }
    try {
        Write-Host "DEBUG: Attempting Add-Type. Logging details to $addTypeLogPath"
        # Add -PassThru and redirect all streams to log file
                Add-Type -TypeDefinition $script:source -Language CSharp -ReferencedAssemblies 'System.dll', 'System.Core.dll', 'System.Management.Automation.dll', 'System.Xml.dll' -ErrorAction Stop -Verbose
        Write-Host "DEBUG: Add-Type command finished (check $addTypeLogPath for details)."
        # Check if the type exists
        # Attempt to get the type using reflection
        $typeName = "RunAsUser.ProcessExtensions"
        $foundType = $null
        try {
            # Try finding in currently loaded assemblies
            $foundType = [System.AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType($typeName) } | Where-Object { $null -ne $_ } | Select-Object -First 1

            if ($null -eq $foundType) {
                 # If not found, try getting it directly from the dynamic assembly created by Add-Type
                 $dynamicAssembly = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.FullName -like 'Microsoft.PowerShell.Commands.NewCompiler*,*' } | Select-Object -First 1
                 if ($null -ne $dynamicAssembly) {
                     Write-Host "DEBUG: Found dynamic assembly: $($dynamicAssembly.FullName)" -ForegroundColor Gray
                     $foundType = $dynamicAssembly.GetType($typeName)
                 } else {
                     Write-Host "DEBUG: Dynamic assembly from Add-Type not found." -ForegroundColor Gray
                 }
            }
        } catch {
            Write-Warning "DEBUG: Exception during reflection check for type '$typeName': $($_.Exception.Message)"
        }

        if ($null -ne $foundType) {
             Write-Host "DEBUG: Type [$($foundType.FullName)] successfully found via reflection." -ForegroundColor Green
        } else {
             Write-Warning "DEBUG: Type [$typeName] NOT found after Add-Type (checked via reflection)."
        }
    } catch {
        Write-Error "DEBUG: Add-Type failed (see $addTypeLogPath for details): $($_.Exception.Message)"
        # Append error details to the log file
        "DEBUG: Add-Type failed: $($_.Exception.Message)" | Out-File -FilePath $addTypeLogPath -Append
        "Stack Trace: $($_.ScriptStackTrace)" | Out-File -FilePath $addTypeLogPath -Append
    }
}

# Define the PowerShell wrapper function
function Invoke-AsCurrentUser {
    [CmdletBinding(DefaultParameterSetName='ScriptBlock')] # Added DefaultParameterSetName
    param(
        [Parameter(Mandatory=$true, ParameterSetName='ScriptBlock')]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory=$true, ParameterSetName='FilePath')]
        [string]$FilePath,

        [Parameter()] # Arguments can be used with FilePath
        [string]$Arguments, # Optional arguments for the executable

        [Parameter()]
        [Switch]$NoWait,

        [Parameter()]
        [Switch]$CaptureOutput,

        [Parameter()]
        [Switch]$CacheToDisk, # Note: Not fully implemented in C# helper

        [Parameter()]
        [Switch]$UseWindowsPowerShell, # Note: Affects powershell.exe path

        [Parameter()]
        [Switch]$NonElevatedSession, # Maps to inverted 'elevated' in C#

        [Parameter()]
        [Switch]$Breakaway, # Maps to 'breakaway' in C#

        [Parameter()]
        [Switch]$Visible # Maps to 'visible' in C#
    )

    # Determine PowerShell executable path
    # Removed logic for determining PowerShell path and constructing command line from ScriptBlock

        # Determine appPath and commandLineArgs based on ParameterSet
        $appPath = $null
        $commandLineArgs = $null

        if ($PSCmdlet.ParameterSetName -eq 'ScriptBlock') {
            # Prepare for PowerShell execution
            $powerShellExe = if ($UseWindowsPowerShell) { Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' } else { Get-Command powershell.exe | Select-Object -ExpandProperty Source }
            if (-not (Test-Path -Path $powerShellExe -PathType Leaf)) { throw "Could not find PowerShell executable at '$powerShellExe'." }
            $appPath = $powerShellExe

            $scriptBlockContent = $ScriptBlock.ToString()
            # Using Base64 encoding is safer for complex script blocks passed via -Command
            $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($scriptBlockContent))
            $commandLineArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
            # Arguments are generally not passed separately when using -EncodedCommand with a script block
            if ($Arguments) { Write-Warning "The -Arguments parameter is typically ignored when using -ScriptBlock." }

        } elseif ($PSCmdlet.ParameterSetName -eq 'FilePath') {
            # Prepare for direct executable execution
            if (-not (Test-Path -Path $FilePath -PathType Leaf)) { throw "File not found: $FilePath" }
            $appPath = $FilePath
            $commandLineArgs = $Arguments # Pass arguments directly

        } else {
            # Should not happen with Mandatory parameters in sets, but good practice
            throw "Internal error: Could not determine parameter set. Either -ScriptBlock or -FilePath must be specified."
        }

    # Map PowerShell parameters to C# method parameters
    $csVisible = $Visible.IsPresent
    # $csWait = if ($NoWait.IsPresent) { 0 } else { -1 } # Original: 0 for no wait, -1 for infinite wait
    $csWait = if ($NoWait.IsPresent) { 0 } else { 30000 } # Use 30-second timeout (30000 ms) instead of infinite
    $csElevated = -not $NonElevatedSession.IsPresent # Inverted logic
    $csRedirectOutput = $CaptureOutput.IsPresent
    $csBreakaway = $Breakaway.IsPresent
    $csWorkDir = $null # Use null for working directory, C# default handles it

    # Call the C# static method
    try {
        # --- Log parameters being passed to C# ---
        Write-Host "DEBUG (Invoke-AsCurrentUser): Calling StartProcessAsCurrentUser with:" -ForegroundColor Yellow
        Write-Host "  appPath = '$FilePath'" -ForegroundColor Yellow
        Write-Host "  cmdLine = '$Arguments'" -ForegroundColor Yellow
        Write-Host "  workDir = '$csWorkDir'" -ForegroundColor Yellow
        Write-Host "  visible = $csVisible" -ForegroundColor Yellow
        Write-Host "  wait = $csWait" -ForegroundColor Yellow
        Write-Host "  elevated = $csElevated" -ForegroundColor Yellow
        Write-Host "  redirectOutput = $csRedirectOutput" -ForegroundColor Yellow
        Write-Host "  breakaway = $csBreakaway" -ForegroundColor Yellow
        # --- End Log ---

        Write-Host "DEBUG: About to call C# StartProcessAsCurrentUser..." # Added diagnostic log
        $result = [RunAsUser.ProcessExtensions]::StartProcessAsCurrentUser(
            $appPath,         # Use determined application path
            $commandLineArgs, # Use determined command line arguments
            $csWorkDir,       # Passed as null from PS, C# method handles null/empty check
            $csVisible,
            $csWait,
            $csElevated,
            $csRedirectOutput,
            $csBreakaway
        )

        # Handle return value based on parameters and potential C# error string
        if ($result -like '[ERROR]*') {
             Write-Error "StartProcessAsCurrentUser reported an error: $result"
             return $null # Or handle error differently
        } elseif ($csRedirectOutput) {
            return $result # Return captured output string
        } elseif ($NoWait.IsPresent) {
            # If NoWait and not redirecting, C# returns PID string
            return $result
        } else {
            # If waiting and not capturing output, C# returns PID string, but PS function returns null
            return $null
        }
    } catch {
        Write-Error "Failed to invoke process as current user (PowerShell wrapper): $_"
        # Consider returning specific error codes or objects if needed
        return $null
    } finally {
        # Clean up temp script file if it was created
        if ($tempScriptPath -and (Test-Path -LiteralPath $tempScriptPath -PathType Leaf)) {
            Write-Host "DEBUG: Removing temp script file: $tempScriptPath" -ForegroundColor Gray
            Remove-Item -LiteralPath $tempScriptPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# Export the function explicitly (good practice for modules)
Export-ModuleMember -Function Invoke-AsCurrentUser

# Removed the loop that tried to import from .\Public
