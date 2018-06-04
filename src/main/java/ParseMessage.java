import org.snmp4j.*;
import org.snmp4j.asn1.BERInputStream;
import org.snmp4j.event.CounterEvent;
import org.snmp4j.event.CounterListener;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.CounterSupport;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.*;
import org.snmp4j.smi.AbstractVariable;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * a debug class we could parse the raw packet message for snmp v3/v2c/v1:
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
 *    3) we registered the CounterSupport to check whether any exception occured
 *       we registered the response handler if vb successfully parsed.
 */
public class ParseMessage {
    public static void main(String[] args) throws Exception {

        System.setProperty(LogFactory.SNMP4J_LOG_FACTORY_SYSTEM_PROPERTY, DebuggerLogFactory.class.getCanonicalName());

        /**
         * register a special integer 32 parser to avoid the length check
         */
        SNMP4JSettings.setExtensibilityEnabled(true);
        System.setProperty(AbstractVariable.SMISYNTAXES_PROPERTIES, "customizedsmisyntaxes.properties");

        // ~~~~

        MPv3 mpv3 = new MPv3();
        MessageDispatcherImpl messageDispatcher = new MessageDispatcherImpl();
        MPv2c mpv2c = new MPv2c();
        MPv1 mpv1 = new MPv1();
        messageDispatcher.addMessageProcessingModel(mpv3);
        messageDispatcher.addMessageProcessingModel(mpv2c);
        messageDispatcher.addMessageProcessingModel(mpv1);
        messageDispatcher.addCommandResponder(new CommandResponder() {
            @Override
            public void processPdu(CommandResponderEvent event) {
                System.out.println("Receive event:" + event);
            }
        });

        CounterSupport.getInstance().addCounterListener(new CounterListener() {
            @Override
            public void incrementCounter(CounterEvent event) {
                System.out.println("Receive counter event:" + event);
            }
        });



        USM usm = new USM();

        UsmUser usmUser = new UsmUser(new OctetString("logicmonitor"), AuthSHA.ID, new OctetString("logicmonitor"), PrivAES128.ID, new OctetString("logicmonitor"));
        usm.addUser(usmUser);
        SecurityModels.getInstance().addSecurityModel(usm);

        // packet address
        UdpAddress addr =  new UdpAddress(InetAddress.getByName("127.0.0.1"), 161);

        // Option1: from snmp4j log:
        String messageV3FromSnmp4jLog = "30:81:99:02:01:03:30:10:02:03:00:b3:94:02:03:00:ff:e3:04:01:03:02:01:03:04:43:30:41:04:11:80:00:1f:88:80:74:7a:d8:50:ad:42:f4:58:00:00:00:00:02:01:03:02:03:12:78:64:04:0c:6c:6f:67:69:63:6d:6f:6e:69:74:6f:72:04:0c:ba:93:35:3b:14:bb:ec:22:9a:b2:07:e9:04:08:ab:7b:11:4a:95:77:e5:54:04:3d:56:8d:55:58:6b:8a:09:17:88:e7:d7:18:89:42:4a:76:45:15:e2:ed:39:94:26:ce:8f:73:be:03:bf:e7:f3:6a:f6:61:96:9f:55:0a:52:0c:82:2f:d4:5b:30:49:aa:8c:b4:4b:a1:c2:d4:45:0c:8e:0b:b3:00:62:df";
        // Option2: from wireshark
        String messageV3FromWireshark = "3081990201033010020300b394020300ffe304010302010304433041041180001f8880747ad850ad42f458000000000201030203127864040c6c6f6769636d6f6e69746f72040cba93353b14bbec229ab207e90408ab7b114a9577e554043d568d55586b8a091788e7d71889424a764515e2ed399426ce8f73be03bfe7f36af661969f550a520c822fd45b3049aa8cb44ba1c2d4450c8e0bb30062df";
        String messageV3FromSnmp4jLogTransed = _wiresharkHexStreamToSplitString(messageV3FromWireshark);
        System.out.println("From wireshark:" + messageV3FromSnmp4jLogTransed + " Equals?" + messageV3FromSnmp4jLogTransed.equalsIgnoreCase(messageV3FromSnmp4jLog));

        String messageV2 = "3037020101040c6c6f6769636d6f6e69746f72a22402044a0b703002010002010030163014060b2b0601020119020301053a020500ae7ad900";
        String messageV2FromSnmp4jLog = "30:82:00:43:02:01:01:04:10:79:65:36:52:4e:34:50:6a:63:77:38:7a:57:39:52:51:a2:82:00:2a:02:04:2e:f9:4d:ce:02:01:00:02:01:00:30:82:00:1a:30:82:00:16:06:0d:2b:06:01:04:01:81:a4:4b:02:01:02:07:00:46:82:00:03:01:fe:0c";

        String [] testMessages = new String[]{messageV3FromSnmp4jLog, _wiresharkHexStreamToSplitString(messageV2), messageV2FromSnmp4jLog};

        for (String testMessage : testMessages) {
            System.out.println("Test..............................");
            try {
                byte[] bytes = OctetString.fromHexString(testMessage, ':').getValue();
                ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
                BERInputStream in = new BERInputStream(byteBuffer);
                TransportMapping transportMapping = new DefaultUdpTransportMapping();
                messageDispatcher.processMessage(transportMapping, addr, in, null);
            } catch (Exception e) {
                StringWriter sw = new StringWriter();
                e.printStackTrace(new PrintWriter(sw));
                System.out.println("Error \n" + sw.getBuffer().toString());
            }
            System.out.println("TestEnd ..............................\n\n");

        }

    }


    private static String _wiresharkHexStreamToSplitString(String hexStream) {
        StringBuffer stringBuffer = new StringBuffer();
        char [] chars = hexStream.toCharArray();
        for (int i = 0; i < chars.length; i = i+2) {
            stringBuffer.append(chars[i]).append(chars[i+1]).append(":");
        }
        stringBuffer.deleteCharAt(stringBuffer.length() - 1);
        return stringBuffer.toString();
    }
}
