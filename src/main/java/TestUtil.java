import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.VariableBinding;

import java.io.IOException;
import java.util.List;

public class TestUtil {
    public static void sendRequest(Snmp snmp, CommunityTarget target, List<OID> oids) throws IOException {
        PDU pdu = new PDU();
        for (OID oid : oids) {
            pdu.addOID(new VariableBinding(oid));
        }

        ResponseEvent responseEvent = snmp.get(pdu, target);
        PDU responsePDU = responseEvent.getResponse();
        if (responsePDU == null) {
            System.out.println("No response found, maybe community wrong");
        }
        else {
            if (responsePDU.getErrorIndex() != 0) {
                System.out.println("Error found " + responsePDU);
            }
            else {
                System.out.println("List response ----");
                for (int i = 0; i < responsePDU.size(); i++) {
                    System.out.println(String.format("oid=%s, index=%d, value=%s", oids.get(i), i, responsePDU.get(i).getVariable()));
                }
            }
        }
    }
}
