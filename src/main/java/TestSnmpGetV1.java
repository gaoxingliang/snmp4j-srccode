import org.snmp4j.CommunityTarget;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.Snmp;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * test a snmp get request
 * Created by edward.gao on 07/09/2017.
 */
public class TestSnmpGetV1 {

    /**
     * Send a snmp get v1 request to request the remote device host name and uptime
     *
     * @param args [remote device Ip, remote device port, community, oid1, oid2, oid.....]
     *             <p>
     *             Example: 192.168.170.149 161 public
     */
    public static void main(String[] args) throws Exception {
        System.setProperty(LogFactory.SNMP4J_LOG_FACTORY_SYSTEM_PROPERTY, DebuggerLogFactory.class.getCanonicalName());


        if (args.length < 3) {
            _printUsage();
            return;
        }

        boolean onebyone = Boolean.parseBoolean(System.getProperty("onebyone", "false"));

        String ip = args[0];
        int port = Integer.valueOf(args[1]);
        String community = args[2];
        System.out.println(String.format("Send message version 1 to %s:%d with community - %s", ip, port, community));
        MessageDispatcherImpl messageDispatcher = new MessageDispatcherImpl();
        Snmp snmp = new Snmp(messageDispatcher, new DefaultUdpTransportMapping());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
        snmp.listen();

        CommunityTarget target = new CommunityTarget();
        Address address = new UdpAddress(String.format("%s/%d", ip, port));
        target.setAddress(address);
        target.setCommunity(new OctetString(community));
        target.setRetries(1); // if possible, retry this request
        target.setTimeout(5000); // the timeout in mills for one pdu
        target.setVersion(SnmpConstants.version1);

        List<OID> requestOIDs = new ArrayList<OID>();

        //we can send more than one oid in a signle pdu request
        if (args.length > 3) {
            for (int i = 3; i < args.length; i++) {
                requestOIDs.add(new OID(args[i]));
            }
        }
        else {
            requestOIDs.add(new OID(Constants.OID_HOSTNAME));
            requestOIDs.add(new OID(Constants.OID_UPTIME));
        }
        if (onebyone) {
            System.out.println("Request one by one....");
            for (OID oid : requestOIDs) {
                TestUtil.sendRequest(snmp, target, Arrays.asList(oid));
            }
        }
        else {
            TestUtil.sendRequest(snmp, target, requestOIDs);
        }

    }

    private static void _printUsage() {
        System.out.println("Arguments error. " + TestSnmpGetV1.class.getName() + " [ip] [port] [community] ([oid1] [oid2] .... )");
    }
}
