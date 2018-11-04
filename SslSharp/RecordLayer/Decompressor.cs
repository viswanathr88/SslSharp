using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.Exceptions;

namespace SslSharp.RecordLayer
{
    class Decompressor
    {
        internal static byte[] DecompressData(byte[] buffer, State state)
        {
            if (state.CompressionMethod == TlsCompressionMethod.NULL)
                return buffer;
            else
                throw new SslAlertException(ProtocolLayer.AlertLevel.Fatal, ProtocolLayer.AlertDescription.IllegalParameter);
        }
    }
}
