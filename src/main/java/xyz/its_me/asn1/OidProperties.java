package xyz.its_me.asn1;

import java.io.IOException;
import java.util.Properties;

public class OidProperties {
    private static final Properties OID_PROPERTIES = new Properties();

    private OidProperties() {
        throw new UnsupportedOperationException("OidProperties is an utility class.");
    }

    public static String resolveOid(String oid) {
        return OID_PROPERTIES.getProperty("oid." + oid, "unknown OID");
    }

    static {
        try {
            OID_PROPERTIES.load(OidProperties.class.getResourceAsStream("oid.properties"));
        } catch (IOException e) {
            throw new RuntimeException("cannot read oid.properties", e);
        }
    }
}
