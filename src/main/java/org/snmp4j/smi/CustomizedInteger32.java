package org.snmp4j.smi;

import org.snmp4j.asn1.BER;
import org.snmp4j.asn1.BERInputStream;

import java.io.IOException;

/**
 * the main logic is same with Integer32. but we don't limit the length now
 */
public class CustomizedInteger32 extends Integer32
        implements AssignableFromInteger, AssignableFromString {

    @Override
    public void decodeBER(BERInputStream is) throws java.io.IOException {
        BER.MutableByte type = new BER.MutableByte();

        int length;
        int value = 0;

        type.setValue((byte)is.read());

        if ((type.getValue() != 0x02) && (type.getValue() != 0x43) &&
                (type.getValue() != 0x41)) {
            throw new IOException("Wrong ASN.1 type. Not an integer: "+type.getValue()+
                    getPositionMessage(is));
        }
        length = BER.decodeLength(is);
//        if (length > 4) {
//            throw new IOException("Length greater than 32bit are not supported "+
//                    " for integers: "+getPositionMessage(is));
//        }

        int b = is.read() & 0xFF;
        if ((b & 0x80) > 0) {
            value = -1; /* integer is negative */
        }
        while (length-- > 0) {
            value = (value << 8) | b;
            if (length > 0) {
                b = is.read();
            }
        }
        setValue(value);

    }


    private static String getPositionMessage(BERInputStream is) {
        return " at position "+is.getPosition();
    }

}

