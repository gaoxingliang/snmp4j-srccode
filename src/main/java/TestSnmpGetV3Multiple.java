import org.snmp4j.*;
import org.snmp4j.event.*;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.MessageProcessingModel;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.util.ArrayList;
import java.util.List;

/**
 * test a snmp get request by using snmp v2c (community version)
 * Created by edward.gao on 07/09/2017.
 */
public class TestSnmpGetV3Multiple {

    /**
     * Send a snmp get v3 request to request the remote device host name and uptime
     *
     * @param args [remote device Ip, remote device port, security, authProtocol, authToken, privProtocol, privToken]
     *             <p>
     *             Example: 192.168.170.149 161 testUser md5 testAuth des privPass
     */
    public static void main(String[] args) throws Exception {

        System.setProperty(LogFactory.SNMP4J_LOG_FACTORY_SYSTEM_PROPERTY, DebuggerLogFactory.class.getCanonicalName());

        if (args.length < 7) {
            _printUsage();
            return;
        }

        String ip = args[0];
        int port = Integer.valueOf(args[1]);
        String security = args[2];
        String authProtocol = args[3];
        String authToken = args[4];
        String privProtocol = args[5];
        String privToken = args[6];
        if (security.isEmpty()) {
            System.out.println("Security is empty, this is required");
            return;
        }

        System.out.println(String.format("Send message version 3 to %s:%d with security=%s,authProtol=%s,authToken=%s,privProtocol=%s," +
                        "privToken=%s",
                ip, port, security, authProtocol, authToken, privProtocol, privToken));

        Snmp snmp = new Snmp(new DefaultUdpTransportMapping());
        OID authProtocolOID = SnmpV3Util.getAuthProtocol(authProtocol);
        OID privacyProtocolOID = SnmpV3Util.getPrivacyProtocol(privProtocol);

        int securityLevel = 0;
        if (authProtocolOID == null) {
            System.out.println("No authentication protocol set, related privacy will be disabled");
            securityLevel = SecurityLevel.NOAUTH_NOPRIV;
        }
        else {
            if (privacyProtocolOID == null) {
                securityLevel = SecurityLevel.AUTH_NOPRIV;
                System.out.println("No privacy protocol set");
            }
            else {
                securityLevel = SecurityLevel.AUTH_PRIV;
                System.out.println("Privacy protocol set");
            }
        }

        OctetString localEngineID = new OctetString(
                MPv3.createLocalEngineID());

        SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());
        USM usm = new USM(SecurityProtocols.getInstance(), localEngineID, 0);
        //Enable the usm to discover the engineId automatically
        usm.setEngineDiscoveryEnabled(true);
        MPv3 mPv3 = new MPv3(usm);
        usm.addUsmUserListener(new UsmUserListener() {
            @Override
            public void usmUserChange(UsmUserEvent event) {
                System.out.println("Receive event - " + event);
            }
        });
        mPv3.addSnmpEngineListener(new SnmpEngineListener() {
            @Override
            public void engineChanged(SnmpEngineEvent engineEvent) {
                System.out.println("Receive snmp enegine event - " + engineEvent);
            }
        });

        SecurityModels.getInstance().addSecurityModel(usm);
        snmp.getMessageDispatcher().addMessageProcessingModel(mPv3);



        snmp.listen();

        String [] securities = new String[] {security, "wrongSecu"};

        List<UsmUser> users = new ArrayList<UsmUser>();
        for (int i = 0; i< securities.length; i++) {
            String sec = securities[i];
            System.out.println("Use user -----------" + sec);
            UsmUser user = new UsmUser(new OctetString(sec), authProtocolOID, new OctetString(authToken), privacyProtocolOID, new
                    OctetString(privToken));
            users.add(user);
            ScopedPDU pdu = _composePDU();
            UserTarget target = _composeTarget(ip, port, sec);
            _addUser2Usm(snmp, target, user, i == 0 ? null : users.get(i-1));
            ResponseEvent responseEvent = snmp.get(pdu, target);
            PDU responsePDU = responseEvent.getResponse();
            readPdu(responsePDU);
        }


    }

    static void readPdu(PDU responsePDU) {
        if (responsePDU == null) {
            System.out.println("!!!!!!!!!!!!!!!!!!!!!!No response found, maybe snmp v3 related args found wrong");
        }
        else {
            if (responsePDU.getErrorIndex() != 0) {
                System.out.println("!!!!!!!!!!!!!!!!!!!!!!Error found " + responsePDU);
            }
            else if (responsePDU.getType() == PDU.RESPONSE) {
                System.out.println("!!!!!!!!!!!!!!!!!!!!!!Host name is - " + responsePDU.get(0).getVariable());
                System.out.println("!!!!!!!!!!!!!!!!!!!!!!Uptime is - " + responsePDU.get(1).getVariable());
            }
            else {
                System.out.println("!!!!!!!!!!!!!!!!!!!!!!Unknown pdu " + responsePDU);
            }
        }
    }
    static UserTarget _composeTarget(String ip, int port, String sec) {
        UserTarget target = new UserTarget();
        Address address = new UdpAddress(String.format("%s/%d", ip, port));
        target.setAddress(address);
        target.setRetries(1); // if possible, retry this request
        target.setTimeout(Integer.getInteger("pdu", 5) * 1000); // the timeout in mills for one pdu
        target.setVersion(SnmpConstants.version3);
        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityName(new OctetString(sec));
        return target;
    }

    static ScopedPDU _composePDU() {
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.GET);
        //we can send more than one oid in a signle pdu request
        pdu.addOID(new VariableBinding(Constants.OID_HOSTNAME));
        pdu.addOID(new VariableBinding(Constants.OID_UPTIME));

        return pdu;
    }


    static void _addUser2Usm(Snmp snmp, Target target, UsmUser user, UsmUser previousUser) {
        System.out.println("$$$$$$$$$$$$$$$Adding user start........");
        USM usm = snmp.getUSM();
        MPv3 mpv3 = (MPv3) snmp.getMessageProcessingModel(MessageProcessingModel.MPv3);
        OctetString engineID = mpv3.removeEngineID(target.getAddress());
        if (engineID != null) {
            usm.removeEngineTime(engineID);
            List n = usm.removeAllUsers(user.getSecurityName(), engineID);
            System.out.println("$$$$$$$$$$$$$$$Remove new users count = " + n.size());
            if (previousUser != null) {
                List l = usm.removeAllUsers(previousUser.getSecurityName(), engineID);
                System.out.println("$$$$$$$$$$$$$$$Remove previous users count = " + l.size());
            }
        }
        //Disable clean the engine ID;
        usm.addUser(user);
        System.out.println("$$$$$$$$$$$$$$$Adding user end........");
    }


    private static void _printUsage() {
        System.out.println("Arguments error. " + TestSnmpGetV3Multiple.class.getName() + " [remote device Ip, remote device port, " +
                "security, authProtocol, authToken, privProtocol, privToken]");
        System.out.println("security is the user name");
        System.out.println("authProtocol is the authentication protocol, now support MD5 and SHA");
        System.out.println("authToken is the authentication passphrase");
        System.out.println("privProtocol is the privacy protocol, now support DES/AES/AES128/3DES/AES256/AES384 (some may be restricted " +
                "by jdk)");
        System.out.println("privToken is the privacy passpharse");
    }
}
