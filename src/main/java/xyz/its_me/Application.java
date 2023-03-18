package xyz.its_me;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import xyz.its_me.asn1.Asn1Parser;
import xyz.its_me.asn1.BeaTimestampVerifier;
import xyz.its_me.asn1.EvidenceRecordParser;
import xyz.its_me.cri.CertReqInfoGenerator;

import java.security.Security;
import java.util.List;

@SpringBootApplication
public class Application implements ApplicationRunner {

    private final Logger logger = LoggerFactory.getLogger(Application.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        final List<String> nonOptionArgs = args.getNonOptionArgs();
        if (nonOptionArgs.size() == 2 && "asn1".equalsIgnoreCase(nonOptionArgs.get(0))) {
            Asn1Parser.parse(nonOptionArgs.get(1));
            return;
        }
        if (nonOptionArgs.size() == 4 && "er".equalsIgnoreCase(nonOptionArgs.get(0))) {
            EvidenceRecordParser.parse(nonOptionArgs.get(1), nonOptionArgs.get(2), nonOptionArgs.get(3));
            return;
        }
        if (nonOptionArgs.size() == 4 && "cri".equalsIgnoreCase(nonOptionArgs.get(0))) {
            CertReqInfoGenerator.generate(nonOptionArgs.get(1), nonOptionArgs.get(2), nonOptionArgs.get(3));
            return;
        }
        if (nonOptionArgs.size() == 3 && "beatsverify".equalsIgnoreCase(nonOptionArgs.get(0))) {
            BeaTimestampVerifier.verify(nonOptionArgs.get(1), nonOptionArgs.get(2));
            return;
        }
        logger.error("""
                usage:
                    java -jar crypto-misc.jar asn1 <fileName>
                    java -jar crypto-misc.jar er <erName> <certName> <dataName>
                    java -jar crypto-misc.jar cri <pubKeyFile> <x500Name> <outputFile>
                    java -jar crypto-misc.jar beatsverify <zipFile> <signatureFile>""");
    }
}
