using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SslSharp.ProtocolLayer
{
    public class SessionID
    {
        uint sessionId = 0;
        byte length;

        public SessionID(uint id, ushort len) 
        {
            sessionId = id;
            length = (byte)(len & 255);
        }

        public SessionID(byte[] data, int offset, ushort length)
        {
            this.length = (byte)(length);
            byte[] sess = new byte[length];
            System.Buffer.BlockCopy(data, offset, sess, 0, length);
            sessionId = BitConverter.ToUInt32(sess, 0);
        }

        /* property */
        public ushort Id
        {
            get { return (ushort)sessionId; }
        }
        public ushort Length
        {
            get { return (ushort)this.length; }
        }

        /* utility methods */
        public byte[] ToBytes()
        {
            byte[] result = null;
            if (length == 0)
            {
                result = new byte[1];
                result[0] = length;
                return result;
            }
            //TODO: Handle case when length is not zero
            return result;
        }
    }
}
