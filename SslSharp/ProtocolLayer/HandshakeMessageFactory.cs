using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SslSharp.ProtocolLayer
{
    class HandshakeMessageFactory
    {
        private static HandshakeTypeDefinition[] Definitions = new HandshakeTypeDefinition[] {
            new HandshakeTypeDefinition(HandshakeDataType.Certificate, typeof(Certificate)),
            new HandshakeTypeDefinition(HandshakeDataType.ClientHello, typeof(ClientHello)),
            new HandshakeTypeDefinition(HandshakeDataType.ClientKeyExchange, typeof(ClientKeyExchange)),
            new HandshakeTypeDefinition(HandshakeDataType.Finished, typeof(Finished)),
            new HandshakeTypeDefinition(HandshakeDataType.HelloRequest, typeof(HelloRequest)),
            new HandshakeTypeDefinition(HandshakeDataType.ServerHello, typeof(ServerHello)),
            new HandshakeTypeDefinition(HandshakeDataType.ServerHelloDone, typeof(ServerHelloDone))
        };

        private static Type GetObjectType(HandshakeDataType type) 
        {
            foreach (HandshakeTypeDefinition def in Definitions) 
            {
                if (def.type == type)
                    return def.HandshakeMessageObjectType;
            }
            return null;
        }

        public static IHandshakeData FromBytes(HandshakeDataType type, byte[] buffer)
        {
            IHandshakeData hData = (IHandshakeData)Activator.CreateInstance(GetObjectType(type), buffer);
            return hData;
        }
    }

    public class HandshakeTypeDefinition
    {
        public HandshakeDataType type;
        public Type HandshakeMessageObjectType;

        public HandshakeTypeDefinition(HandshakeDataType type, Type HandshakeMessageObjType) 
        {
            this.type = type;
            this.HandshakeMessageObjectType = HandshakeMessageObjType;
        }
    }
}
