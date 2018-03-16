package org.snmp4j.smi;

import org.snmp4j.asn1.BER;
import org.snmp4j.asn1.BERInputStream;

import java.io.IOException;
import java.io.OutputStream;

public class CustomizedInteger64 extends AbstractVariable
        implements AssignableFromInteger, AssignableFromString {

    private long value = 0;

    private static final long serialVersionUID = 5046132399890132416L;


    /**
     * Creates an <code>Integer32</code> with a zero value.
     */
    public CustomizedInteger64() {
    }

    /**
     * Creates an <code>Integer32</code> variable with the supplied value.
     * @param value
     *    an integer value.
     */
    public CustomizedInteger64(long value) {
        setValue(value);
    }

    public void encodeBER(OutputStream outputStream) throws java.io.IOException {
        BER.encodeInteger(outputStream, BER.INTEGER, (int)value);
    }

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
        if (length > 4) {
            is.reset();
            long longValue = BER.decodeUnsignedInteger(is, type);
            setValue(longValue);
        }
        else {
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
    }

    public int getSyntax() {
        return SMIConstants.SYNTAX_INTEGER;
    }

    public int hashCode() {
        return (int)value;
    }

    public int getBERLength() {
        if ((value <   0x80) &&
                (value >= -0x80)) {
            return 3;
        }
        else if ((value <   0x8000) &&
                (value >= -0x8000)) {
            return 4;
        }
        else if ((value <   0x800000) &&
                (value >= -0x800000)) {
            return 5;
        }
        return 6;
    }

    public boolean equals(Object o) {
        return (o instanceof CustomizedInteger64) && (((CustomizedInteger64) o).value == value);
    }

    public int compareTo(Variable o) {
        return (int)(value - ((CustomizedInteger64)o).value);
    }

    public String toString() {
        return Long.toString(value);
    }

    public final void setValue(String value) {
        this.value = Long.parseLong(value);
    }

    /**
     * Sets the value of this integer.
     * @param value
     *    an integer value.
     */
    public final void setValue(long value) {
        this.value = value;
    }

    /**
     * Gets the value.
     * @return
     *    an integer.
     */
    public final long getValue() {
        return value;
    }

    public Object clone() {
        return new CustomizedInteger64(value);
    }

    @Override
    public void setValue(int value) {
        this.value = value;
    }

    public final int toInt() {
        return (int)getValue();
    }

    public final long toLong() {
        return getValue();
    }

    public OID toSubIndex(boolean impliedLength) {
        return new OID(new int[] { (int)value });
    }

    public void fromSubIndex(OID subIndex, boolean impliedLength) {
        setValue(subIndex.get(0));
    }

    private static String getPositionMessage(BERInputStream is) {
        return " at position "+is.getPosition();
    }
}
