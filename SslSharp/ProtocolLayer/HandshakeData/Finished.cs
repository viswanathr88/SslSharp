using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.Collections;
using SslSharp.RecordLayer;

namespace SslSharp.ProtocolLayer
{
    class Finished : IHandshakeData
    {
        byte[] finishedData = null;

        public Finished(byte[] data)
        {
            this.finishedData = data;
        }

        public byte[] GetBytes()
        {
            return finishedData;
        }

        public uint GetLength()
        {
            return (uint)finishedData.Length;
        }

        public new HandshakeDataType GetType()
        {
            return HandshakeDataType.Finished;
        }

        public void Process(IProtocolHandler pHandler)
        {
            pHandler.ProcessFinished(finishedData);
        }
    }
}
