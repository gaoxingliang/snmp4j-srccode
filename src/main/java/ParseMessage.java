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
 * a debug class we could parse the raw packet message for snmp v3:
 *
 *    1) the input message bytes is in the output of the message:
 *          Option 1: With the following output when the snmp4j log is enabled:
 *              Received message from /10.10.10.10/161 with length 156: 30:81:99:.....XXXX
 *          Option 2: We can copy the hex stream from wireshark in:
 *                  Simple Network Management Protocol -> right click Copy -> ... as a Hex Stream
 *
 *
 *    2) the related username and password must be correct set if it's snmp v3
 *
 * //todo: add support for v2 message parsing
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

        // Option1: from snmp4j log:
        String message = "30:81:99:02:01:03:30:10:02:03:00:b3:94:02:03:00:ff:e3:04:01:03:02:01:03:04:43:30:41:04:11:80:00:1f:88:80:74:7a:d8:50:ad:42:f4:58:00:00:00:00:02:01:03:02:03:12:78:64:04:0c:6c:6f:67:69:63:6d:6f:6e:69:74:6f:72:04:0c:ba:93:35:3b:14:bb:ec:22:9a:b2:07:e9:04:08:ab:7b:11:4a:95:77:e5:54:04:3d:56:8d:55:58:6b:8a:09:17:88:e7:d7:18:89:42:4a:76:45:15:e2:ed:39:94:26:ce:8f:73:be:03:bf:e7:f3:6a:f6:61:96:9f:55:0a:52:0c:82:2f:d4:5b:30:49:aa:8c:b4:4b:a1:c2:d4:45:0c:8e:0b:b3:00:62:df";

        // Option2: from wireshark
        String message4Pcap = "3081990201033010020300b394020300ffe304010302010304433041041180001f8880747ad850ad42f458000000000201030203127864040c6c6f6769636d6f6e69746f72040cba93353b14bbec229ab207e90408ab7b114a9577e554043d568d55586b8a091788e7d71889424a764515e2ed399426ce8f73be03bfe7f36af661969f550a520c822fd45b3049aa8cb44ba1c2d4450c8e0bb30062df";
        StringBuffer stringBuffer = new StringBuffer();
        char [] chars = message4Pcap.toCharArray();
        for (int i = 0; i < chars.length / 2; i = i+2) {
            stringBuffer.append(chars[i]).append(chars[i+1]).append(":");
        }
        stringBuffer.deleteCharAt(stringBuffer.length() - 1);
        System.out.println("From wireshark:" + stringBuffer);


        byte [] bytes = OctetString.fromHexString(message, ':').getValue();
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        BERInputStream in = new BERInputStream(byteBuffer);

        TransportMapping transportMapping = new DefaultUdpTransportMapping();
        messageDispatcher.processMessage(transportMapping, addr, in, null);

    }
}
