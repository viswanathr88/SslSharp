using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.Collections;
namespace SslSharp.Shared
{
    public class SecurityParameters
    {
        private ConnectionEntity m_Entity = ConnectionEntity.Client;
        private TlsCipherSuite m_CipherSuite;
        private TlsCompressionMethod m_CompressionMethod;
        private byte[] m_MasterSecret;
        private byte[] m_ClientRandom;
        private byte[] m_ServerRandom;

        private ProtocolVersion chosenVersion = null;

        internal ConnectionEntity ConnectionEntity
        {
            get { return m_Entity; }
            set { m_Entity = value; }
        }
        
        internal TlsCompressionMethod CompressionMethod
        {
            get { return m_CompressionMethod; }
            set { m_CompressionMethod = value; }
        }
        
        public byte[] MasterSecret
        {
            get { return m_MasterSecret; }
            set { m_MasterSecret = value; }
        }
        
        public byte[] ClientRandom
        {
            get { return m_ClientRandom; }
            set { m_ClientRandom = value; }
        }
        
        public byte[] ServerRandom
        {
            get { return m_ServerRandom; }
            set { m_ServerRandom = value; }
        }

        public ProtocolVersion ChosenVersion
        {
            get { return chosenVersion; }
            set { this.chosenVersion = value; }
        }

        public TlsCipherSuite CipherSuite
        {
            get { return this.m_CipherSuite; }
            set { this.m_CipherSuite = value; }
        }

        public bool Validate()
        {
            bool result = true;
            if (m_ServerRandom == null)
            {
                Console.WriteLine("Server Random is null");
                result = false;
            }
            if (m_ClientRandom == null)
            {
                Console.WriteLine("Client Random is null");
                return false;
            }
            if (m_MasterSecret == null)
            {
                Console.WriteLine("Master Secret is null");
                return false;
            }

            return result;

        }
    }
}
