using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace RunAsSystemNew
{
    internal class Structs
    {
        const Int32 ANYSIZE_ARRAY = 1;

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_ATTRIBUTES
        {
            internal int nLength;
            internal IntPtr lpSecurityDescriptor;
            internal bool bInheritHandles;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            internal ushort Length;
            internal ushort MaximumLength;
            internal IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_OBJECT_ATTRIBUTES
        {
            internal int Length;
            internal IntPtr RootDirectory;
            internal LSA_UNICODE_STRING ObjectName;
            internal UInt32 Attributes;
            internal IntPtr SecurityDescriptor;
            internal IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            internal IntPtr hProcess;
            internal IntPtr hThread;
            internal int dwProcessId;
            internal int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct STARTUPINFO
        {
            internal Int32 cb;
            internal IntPtr lpReserved;
            internal string lpDesktop;
            internal IntPtr lpTitle;
            internal uint dwX;
            internal uint dwY;
            internal uint dwXSize;
            internal uint dwYSize;
            internal uint dwXCountChars;
            internal uint dwYCountChars;
            internal uint dwFillAttributes;
            internal uint dwFlags;
            internal ushort wShowWindow;
            internal ushort cbReserved;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct TOKEN_PRIVILEGES
        {
            internal UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = ANYSIZE_ARRAY)]
            internal LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID_AND_ATTRIBUTES
        {
            internal LUID Luid;
            internal UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID
        {
            internal UInt32 LowPart;
            internal int HighPart;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct LSA_UNICODE_STRING
        {
            internal ushort Length;
            internal ushort MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string Buffer;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct SYSTEM_HANDLE_INFORMATION
        {
            internal UInt32 OwnerPID;
            internal Byte ObjectType;
            internal Byte HandleFlags;
            internal UInt16 HandleValue;
            internal UIntPtr ObjectPointer;
            internal IntPtr AccessMask;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct OBJECT_BASIC_INFORMATION
        {
            internal UInt32 Attributes;
            internal UInt32 GrantedAccess;
            internal UInt32 HandleCount;
            internal UInt32 PointerCount;
            internal UInt32 PagedPoolUsage;
            internal UInt32 NonPagedPoolUsage;
            internal UInt32 Reserved1;
            internal UInt32 Reserved2;
            internal UInt32 Reserved3;
            internal UInt32 NameInformationLength;
            internal UInt32 TypeInformationLength;
            internal UInt32 SecurityDescriptorLength;
            internal System.Runtime.InteropServices.ComTypes.FILETIME CreateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct OBJECT_TYPE_INFORMATION
        { // Information Class 2
            internal UNICODE_STRING Name;
            internal int ObjectCount;
            internal int HandleCount;
            internal int Reserved1;
            internal int Reserved2;
            internal int Reserved3;
            internal int Reserved4;
            internal int PeakObjectCount;
            internal int PeakHandleCount;
            internal int Reserved5;
            internal int Reserved6;
            internal int Reserved7;
            internal int Reserved8;
            internal int InvalidAttributes;
            internal GENERIC_MAPPING GenericMapping;
            internal int ValidAccess;
            internal byte Unknown;
            internal byte MaintainHandleDatabase;
            internal int PoolType;
            internal int PagedPoolUsage;
            internal int NonPagedPoolUsage;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct GENERIC_MAPPING
        {
            internal int GenericRead;
            internal int GenericWrite;
            internal int GenericExecute;
            internal int GenericAll;
        }
    }

    internal class Sid
    {
        public IntPtr pSid = IntPtr.Zero;
        public SecurityIdentifier sid = null;

        internal Sid(string account)
        {
            sid = (SecurityIdentifier)(new NTAccount(account)).Translate(typeof(SecurityIdentifier));
            byte[] buffer = new byte[sid.BinaryLength];
            sid.GetBinaryForm(buffer, 0);

            pSid = Marshal.AllocHGlobal(sid.BinaryLength);
            Marshal.Copy(buffer, 0, pSid, sid.BinaryLength);
        }
    }

    internal static class Helpers
    {
        internal static Structs.LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe)
            {
                throw new ArgumentException("String too long");
            }
            Structs.LSA_UNICODE_STRING lus = new Structs.LSA_UNICODE_STRING
            {
                Buffer = s,
                Length = (ushort)(s.Length * sizeof(char))
            };
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }

        internal static bool ExistsOnPath(string fileName)
        {
            return GetFullPath(fileName) != null;
        }

        internal static string GetFullPath(string fileName)
        {
            if (File.Exists(fileName))
            {
                return Path.GetFullPath(fileName);
            }
            var values = Environment.GetEnvironmentVariable("PATH");
            foreach (var path in values.Split(Path.PathSeparator))
            {
                var fullPath = Path.Combine(path, fileName);
                if (File.Exists(fullPath))
                {
                    return fullPath;
                }
            }
            return null;
        }
    }

    internal class Constants
    {
        internal static readonly string[] privileges = { "SeDebugPrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege" };
        internal static readonly string winlogon = "winlogon";
        internal static readonly UInt32 SE_PRIVILEGE_ENABLED = 0x2;
    }
}
