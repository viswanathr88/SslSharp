using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.Collections;
using SslSharp.Exceptions;

namespace SslSharp.RecordLayer
{
    static class Compressor
    {
        public static List<Record> CompressData(List<Record> lRecords, State state) 
        {
            if (state.CompressionMethod == TlsCompressionMethod.NULL)
                return lRecords;
            else
            {
                throw new SslAlertException(ProtocolLayer.AlertLevel.Fatal, ProtocolLayer.AlertDescription.IllegalParameter);
            }
        }
    }
}
