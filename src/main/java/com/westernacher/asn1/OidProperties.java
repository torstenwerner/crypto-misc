package com.westernacher.asn1;

import java.io.IOException;
import java.util.Properties;

public class OidProperties {
    private static Properties oidProperties;

    public static String resolveOid(String oid) {
        return oidProperties.getProperty("oid." + oid, "unknown OID");
    }

    static {
        oidProperties = new Properties();
        try {
            oidProperties.load(OidProperties.class.getResourceAsStream("oid.properties"));
        } catch (IOException e) {
            throw new RuntimeException("cannot read oid.properties", e);
        }
    }
}
