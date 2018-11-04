using System.Security.Cryptography;
using SslSharp.Shared;

namespace SslSharp.RecordLayer
{
    internal class States
    {
        State m_ActiveReadState;
        State m_ActiveWriteState;

        State m_PendingReadState;
        State m_PendingWriteState;

        public States()
        {
            m_ActiveReadState = new State();
            m_ActiveWriteState = new State();

            m_PendingReadState = new State();
            m_PendingWriteState = new State();
        }

        public void FillPendingStates(ProtocolVersion chosenVersion, TlsCompressionMethod compMethod, ICryptoTransform encryptor, ICryptoTransform decryptor,
            KeyedHashAlgorithm clientHasher, KeyedHashAlgorithm serverHasher)
        {
            m_PendingReadState.ChosenVersion = chosenVersion;
            m_PendingWriteState.ChosenVersion = chosenVersion;

            m_PendingReadState.CryptoTransform = decryptor;
            m_PendingWriteState.CryptoTransform = encryptor;

            m_PendingReadState.Hasher = serverHasher;
            m_PendingWriteState.Hasher = clientHasher;

            m_PendingReadState.CompressionMethod = m_PendingWriteState.CompressionMethod = compMethod;
        }

        public State ActiveReadState
        {
            get { return m_ActiveReadState; }
        }

        public State ActiveWriteState
        {
            get { return m_ActiveWriteState; }
        }

        public void MakePendingReadStateActive()
        {
            State.Copy(m_ActiveReadState, m_PendingReadState);
            m_ActiveReadState.ResetSequenceNumber();
        }

        public void MakePendingWriteStateActive()
        {
            State.Copy(m_ActiveWriteState, m_PendingWriteState);
            m_ActiveWriteState.ResetSequenceNumber();
        } 
    }
}
