using System;
using System.Security.Cryptography;
using SslSharp.Security.Cryptography;
using SslSharp.Collections;

namespace SslSharp.Shared
{
    internal sealed class CipherSuite
    {
        private readonly ICryptoTransform m_Encryptor;
        private readonly ICryptoTransform m_Decryptor;
        private readonly KeyedHashAlgorithm m_ClientHasher;
        private readonly KeyedHashAlgorithm m_ServerHasher;

        public CipherSuite(TlsCipherSuite suite, byte[] master,
            byte[] clientRandom, byte[] serverRandom)
        {
            if (master == null)
                throw new ArgumentNullException();
            if (clientRandom == null)
                throw new ArgumentNullException();
            if (serverRandom == null)
                throw new ArgumentNullException();

            CipherDefinition cipherDef = CipherSuites.GetCipherDefinition(suite);

            int size = cipherDef.HashSize * 2 + cipherDef.BulkKeySize * 2;

            if (cipherDef.BulkIVSize != 0)
                size += cipherDef.BulkIVSize * 2;

            PrfDeriveBytes prf = new PrfDeriveBytes(master,
                "key expansion", ByteArray.Concat(serverRandom, clientRandom));

            byte[] keyBlock = prf.GetBytes(size);

            prf.Dispose();

            int offset = 0;

            byte[] client_write_mac = new byte[cipherDef.HashSize];
            System.Buffer.BlockCopy(keyBlock, offset, client_write_mac, 0, cipherDef.HashSize);
            offset += cipherDef.HashSize;

            byte[] server_write_mac = new byte[cipherDef.HashSize];
            System.Buffer.BlockCopy(keyBlock, offset, server_write_mac, 0, cipherDef.HashSize);
            offset += cipherDef.HashSize;

            byte[] client_write_key = new byte[cipherDef.BulkKeySize];
            System.Buffer.BlockCopy(keyBlock, offset, client_write_key, 0, cipherDef.BulkKeySize);
            offset += cipherDef.BulkKeySize;

            byte[] server_write_key = new byte[cipherDef.BulkKeySize];
            System.Buffer.BlockCopy(keyBlock, offset, server_write_key, 0, cipherDef.BulkKeySize);
            offset += cipherDef.BulkKeySize;

            byte[] client_write_iv = null;
            byte[] server_write_iv = null;

            if (cipherDef.BulkIVSize != 0)
            {
                client_write_iv = new byte[cipherDef.BulkIVSize];
                System.Buffer.BlockCopy(keyBlock, offset, client_write_iv, 0, cipherDef.BulkIVSize);
                offset += cipherDef.BulkIVSize;

                server_write_iv = new byte[cipherDef.BulkIVSize];
                System.Buffer.BlockCopy(keyBlock, offset, server_write_iv, 0, cipherDef.BulkIVSize);
                offset += cipherDef.BulkIVSize;
            }

            prf.Dispose();

            SymmetricAlgorithm sAlg = (SymmetricAlgorithm)Activator.CreateInstance(cipherDef.BulkCipherAlgorithm);
            sAlg.BlockSize = cipherDef.BulkIVSize * 8;

            if (cipherDef.Exportable)
            {
                //TODO: Make amends to support export cipher suites
            }

            m_Encryptor = sAlg.CreateEncryptor(client_write_key, client_write_iv);
            m_Decryptor = sAlg.CreateDecryptor(server_write_key, server_write_iv);
            m_ClientHasher = (KeyedHashAlgorithm)Activator.CreateInstance(cipherDef.HashAlgorithm, client_write_mac);
            m_ServerHasher = (KeyedHashAlgorithm)Activator.CreateInstance(cipherDef.HashAlgorithm, server_write_mac);

            /* clear up */
            Array.Clear(client_write_mac, 0, client_write_mac.Length);
            Array.Clear(server_write_mac, 0, server_write_mac.Length);
            Array.Clear(client_write_key, 0, client_write_key.Length);
            Array.Clear(server_write_key, 0, server_write_key.Length);

            if (client_write_iv != null && server_write_iv != null)
            {
                Array.Clear(client_write_iv, 0, client_write_iv.Length);
                Array.Clear(server_write_iv, 0, server_write_iv.Length);
            }
        }

        public ICryptoTransform Encryptor
        {
            get { return m_Encryptor; }
        }

        public ICryptoTransform Decryptor
        {
            get { return m_Decryptor; }
        }

        public KeyedHashAlgorithm ClientHasher
        {
            get { return m_ClientHasher; }
        }

        public KeyedHashAlgorithm ServerHasher
        {
            get { return m_ServerHasher; }
        }
    }
}
