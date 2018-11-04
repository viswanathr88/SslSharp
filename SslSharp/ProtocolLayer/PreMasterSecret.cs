using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

using SslSharp.Shared;

namespace SslSharp.ProtocolLayer
{
    class PreMasterSecret : IDisposable
    {
        byte[] m_RandomBytes;
        bool m_Disposed = false;

        public PreMasterSecret()
        {
            m_RandomBytes = new byte[46];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(m_RandomBytes);
        }

        public byte[] GetBytes()
        {
            byte[] result = new byte[48];
            ProtocolVersion version = new ProtocolVersion();
            System.Buffer.BlockCopy(version.GetBytes(), 0, result, 0, version.Length);
            System.Buffer.BlockCopy(m_RandomBytes, 0, result, 2, m_RandomBytes.Length);

            return result;
        }

        public void Dispose()
        {
            if (!m_Disposed)
            {
                m_Disposed = true;
                Array.Clear(m_RandomBytes, 0, m_RandomBytes.Length);
            }
        }
        ~PreMasterSecret()
        {
            Dispose();
        }
    }
}
