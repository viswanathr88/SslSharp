using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SslSharp.Collections
{
    static class CompressionList
    {
        private static TlsCompressionMethod[] m_SupportedCompressionMethods = new TlsCompressionMethod[] {
            TlsCompressionMethod.NULL
        };

        /* property */
        public static ushort Length
        {
            get { return (ushort)m_SupportedCompressionMethods.Length; }
        }

        public static byte[] ToBytes()
        {
            byte[] result = new byte[1 + Length];
            int offset = 0;
            result[offset++] = (byte)(Length & 0xff);
            foreach (TlsCompressionMethod method in m_SupportedCompressionMethods)
            {
                byte[] r = new byte[1];
                r[0] = (byte)((ushort)(method) & 0xff);
                System.Buffer.BlockCopy(r, 0, result, offset++ , r.Length);
            }
            return result;
        }

        internal static bool IsPresent(TlsCompressionMethod cMethod)
        {
            foreach (TlsCompressionMethod method in m_SupportedCompressionMethods)
            {
                if (method == cMethod)
                    return true;
            }
            return false;
        }
    }
}
