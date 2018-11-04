using System.Security.Cryptography;
using SslSharp.Shared;

namespace SslSharp.RecordLayer
{
    public class State
    {
        private TlsCompressionMethod m_CompressionMethod;
        private ICryptoTransform m_CryptoTransform;
        private KeyedHashAlgorithm m_Hasher;
        private ulong m_SequenceNumber;
        private ProtocolVersion m_ChosenVersion;

        public State()
        {
            m_SequenceNumber = 0;
        }

        internal TlsCompressionMethod CompressionMethod
        {
            get { return m_CompressionMethod; }
            set { this.m_CompressionMethod = value; }
        }

        internal ICryptoTransform CryptoTransform
        {
            get { return m_CryptoTransform; }
            set { this.m_CryptoTransform = value; }
        }

        internal KeyedHashAlgorithm Hasher
        {
            get { return m_Hasher; }
            set { this.m_Hasher = value; }
        }

        internal ProtocolVersion ChosenVersion
        {
            get { return m_ChosenVersion; }
            set { this.m_ChosenVersion = value; }
        }

        internal ulong SequenceNumber
        {
            get { return this.m_SequenceNumber; }
            set { this.m_SequenceNumber = value; }
        }

        internal void ResetSequenceNumber()
        {
            m_SequenceNumber = 0;
        }

        internal static void Copy(State activeState, State pendingState)
        {
            activeState.CryptoTransform = pendingState.CryptoTransform;
            activeState.CompressionMethod = pendingState.CompressionMethod;
            activeState.Hasher = pendingState.Hasher;
            activeState.ChosenVersion = pendingState.ChosenVersion;
        }
    }
}
