import org.snmp4j.CommunityTarget;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * test a snmp get request
 * Created by edward.gao on 07/09/2017.
 */
public class TestSnmpGetV2Async {

    /**
     * Send a snmp get v2 request to request the remote device host name and uptime (you can set other oids)
     *
     * Support -Dasync=true|false  to  send async or sync
     *
     *         This will request at most 60 times and one request in one sencond
     *         Use -Dstart and -Dend to set the start and end in seconds.
     *                  eg : -Dstart=10 -Dend=30. will send request in 10 -30 seconds.
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

        String ip = args[0];
        int port = Integer.valueOf(args[1]);
        String community = args[2];
        System.out.println(String.format("Send message version 1 to %s:%d with community - %s", ip, port, community));
        MessageDispatcherImpl messageDispatcher = new MessageDispatcherImpl();
        Snmp snmp = new Snmp(messageDispatcher, new DefaultUdpTransportMapping());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
        snmp.listen();

        CommunityTarget target = new CommunityTarget();
        Address address = new UdpAddress(String.format("%s/%d", ip, port));
        target.setAddress(address);
        target.setCommunity(new OctetString(community));
        target.setRetries(1); // if possible, retry this request
        target.setTimeout(Integer.getInteger("pdu", 5) * 1000); // the timeout in mills for one pdu
        target.setVersion(SnmpConstants.version2c);

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

        boolean async = Boolean.getBoolean("async");
        int startSec = Integer.getInteger("start", 0);
        int endSec = Integer.getInteger("end", 59);
        final CountDownLatch latch = new CountDownLatch(endSec - startSec + 1);
        final StringBuffer res = new StringBuffer();
        for (int i = 0; i < 59; i++) {
            final int j = i;
            final Date d = new Date();
            d.setMinutes(d.getMinutes() + 1);
            d.setSeconds(i);
            if (d.getSeconds() < startSec || d.getSeconds() > endSec) {
                continue;
            }

            PDU pdu = new PDU();
            for (OID o : requestOIDs) {
                pdu.add(new VariableBinding(o));
            }

            snmp.get(pdu, target, null, new ResponseListener() {
                @Override
                public void onResponse(ResponseEvent event) {
                    Object src = event.getSource();
                    if (src != null && src instanceof Snmp) {
                        ((Snmp) src).cancel(event.getRequest(), this);
                    }
                    res.append(String.format("\ndate=%s, req=%s,event=%s, src=%s\n", d, event.getRequest(), event.getResponse(), src));
                    latch.countDown();
                }
            });

        }

        latch.await(2, TimeUnit.MINUTES);
        System.out.println(res);
        return;
    }



    private static void _printUsage() {
        System.out.println("Arguments error. " + TestSnmpGetV2Async.class.getName() + " [ip] [port] [community] ([oid1] [oid2] .... )");
    }
}
