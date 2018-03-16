import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.TransportMapping;
import org.snmp4j.asn1.BERInputStream;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.*;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * a debug class we could parse the raw message for snmpv3:
 *
 *    1) the input message bytes is in the output of the message:
 *          With the following output when the snmp4j log is enabled:
 *              Received message from /10.10.10.10/161 with length 156: 30:81:99:.....XXXX
 *    2) the related username and password must be correct set
 */
public class ParseMessage {
    public static void main(String[] args) throws Exception {
        System.setProperty(LogFactory.SNMP4J_LOG_FACTORY_SYSTEM_PROPERTY, DebuggerLogFactory.class.getCanonicalName());
        MPv3 mpv3 = new MPv3();
        MessageDispatcherImpl messageDispatcher = new MessageDispatcherImpl();
        messageDispatcher.addMessageProcessingModel(mpv3);

        USM usm = new USM();

        UsmUser usmUser = new UsmUser(new OctetString("logicmonitor"), AuthSHA.ID, new OctetString("logicmonitor"), PrivAES128.ID, new OctetString("logicmonitor"));
        usm.addUser(usmUser);
        SecurityModels.getInstance().addSecurityModel(usm);

        // packet address
        UdpAddress addr =  new UdpAddress(InetAddress.getByName("127.0.0.1"), 161);


        String message = "30:81:99:02:01:03:30:10:02:03:00:c4:20:02:03:00:ff:e3:04:01:03:02:01:03:04:43:30:41:04:11:80:00:1f:88:80:74:7a:d8:50:ad:42:f4:58:00:00:00:00:02:01:03:02:03:11:8d:ac:04:0c:6c:6f:67:69:63:6d:6f:6e:69:74:6f:72:04:0c:2f:ce:b2:2f:8e:ab:c6:d3:8b:b9:36:70:04:08:ab:7b:11:4a:95:77:13:69:04:3d:d6:03:a7:ab:b9:08:bc:32:f6:55:76:2f:78:57:1a:00:7e:48:d6:7d:55:f0:4f:5f:d1:3f:33:e0:83:da:b5:68:d4:59:fd:0b:99:19:31:e1:19:26:27:68:15:d9:cc:24:7d:8d:d9:b4:60:53:ff:36:56:7b:a6:ea:97";
        byte [] bytes = OctetString.fromHexString(message, ':').getValue();
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        BERInputStream in = new BERInputStream(byteBuffer);

        TransportMapping transportMapping = new DefaultUdpTransportMapping();
        messageDispatcher.processMessage(transportMapping, addr, in, null);

    }
}
