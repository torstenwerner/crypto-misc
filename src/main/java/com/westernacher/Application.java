package com.westernacher;

import com.westernacher.asn1.Asn1Parser;
import com.westernacher.asn1.EvidenceRecordParser;

import java.io.IOException;

public class Application {
    public static void main(String[] args) throws IOException {
        if (args.length == 2 && "asn1".equalsIgnoreCase(args[0])) {
            Asn1Parser.parse(args[1]);
            return;
        }
        if (args.length == 4 && "er".equalsIgnoreCase(args[0])) {
            EvidenceRecordParser.parse(args[1], args[2],args[3]);
            return;
        }
        System.out.println("usage:\n" +
                "    java -jar crypto-misc.jar asn1 <fileName>\n" +
                "    java -jar crypto-misc.jar er <erName> <certName> <dataName>");
    }
}
