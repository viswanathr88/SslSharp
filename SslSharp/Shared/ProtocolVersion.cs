using System;
using System.Text;

namespace SslSharp.Shared
{
    public class ProtocolVersion
    {
        byte major;
        byte minor;

        public ProtocolVersion()
        {
            this.major = 3;
            this.minor = 1;
        }

        public ProtocolVersion(int major, int minor)
        {
            this.major = (byte)(major & 0xff);
            this.minor = (byte)(minor & 0xff);
        }

        public ProtocolVersion(byte[] data, int index)
        {
            major = data[index];
            minor = data[index + 1];
        }

        public byte[] GetBytes()
        {
            byte[] result = new byte[2];
            result[0] = major;
            result[1] = minor;
            
            return result;
        }

        /* property */
        public ushort Length
        {
            get { return 2; }
        }

        public byte Major
        {
            get { return major; }
            set { major = value; }
        }

        public byte Minor
        {
            get { return minor; }
            set { minor = value; }
        }

        internal void Print()
        {
            Console.WriteLine("Version = " + (int)Major + "." + (int)Minor);
        }

        public static ProtocolVersion ClientVersion
        {
            get { return new ProtocolVersion(); }
        }
    }   
}
