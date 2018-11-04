using System;
using System.Security.Cryptography;
using System.Text;

namespace SslSharp.ProtocolLayer
{
    class RandomUnit
    {
        uint GmtUnixTime;
        byte[] RandomBytes;

        public RandomUnit()
        {
            GmtUnixTime = (uint)((DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds);
            RandomBytes = new byte[28];
            Random random = new Random(DateTime.UtcNow.Millisecond);
            random.NextBytes(RandomBytes);
        }

        /* convert to bytes */
        public byte[] GetBytes()
        {
            byte[] time = BitConverter.GetBytes(GmtUnixTime);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(time);
            byte[] result = new byte[32];
            System.Buffer.BlockCopy(time, 0, result, 0, time.Length);
            System.Buffer.BlockCopy(RandomBytes, 0, result, time.Length, RandomBytes.Length);
            return result;
        }

        /* property */
        public static ushort Length
        {
            get { return 32; }
        }
    }
}
