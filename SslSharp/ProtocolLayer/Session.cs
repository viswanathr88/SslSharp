using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using SslSharp.Collections;

namespace SslSharp.ProtocolLayer
{
    class Session
    {
        private SessionID sessionId;
        private X509Certificate cert = null;
        private TlsCompressionMethod chosenCompressionMethod;
        private TlsCipherSuite chosenCipherSpec;
        private byte[] masterSecret = null;
        private bool isResumable = false;

        internal SessionID Id
        {
            get { return sessionId; }
            set { this.sessionId = value; }
        }

        internal X509Certificate Certificate
        {
            get { return this.cert; }
            set { this.cert = value; }
        }

        internal TlsCompressionMethod CompressionMethod 
        {
            get { return chosenCompressionMethod; }
            set { this.chosenCompressionMethod = value; }
        }

        internal TlsCipherSuite CipherSuite
        {
            get { return chosenCipherSpec; }
            set { this.chosenCipherSpec = value; }
        }

        internal byte[] MasterSecret
        {
            get { return masterSecret; }
            set { this.masterSecret = value; }
        }

        internal bool IsResumable
        {
            get { return this.isResumable; }
            set { this.isResumable = value; }
        }
    }
}
