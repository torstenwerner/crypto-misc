package com.westernacher;

import com.westernacher.asn1.Asn1Parser;
import com.westernacher.asn1.EvidenceRecordParser;
import com.westernacher.cri.CertReqInfoGenerator;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class Application {
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        if (args.length == 2 && "asn1".equalsIgnoreCase(args[0])) {
            Asn1Parser.parse(args[1]);
            return;
        }
        if (args.length == 4 && "er".equalsIgnoreCase(args[0])) {
            EvidenceRecordParser.parse(args[1], args[2], args[3]);
            return;
        }
        if (args.length == 4 && "cri".equalsIgnoreCase(args[0])) {
            CertReqInfoGenerator.generate(args[1], args[2], args[3]);
            return;
        }
        System.out.println("usage:\n" +
                "    java -jar crypto-misc.jar asn1 <fileName>\n" +
                "    java -jar crypto-misc.jar er <erName> <certName> <dataName>\n" +
                "    java -jar crypto-misc.jar cri <pubKeyFile> <x500Name> <outputFile>");
    }
}
