# Various crypto stuff

- ASN.1 parser
- timestamp verifier
- evidence record parser
- evidence record verifier

Everything is pretty low level. Sorry for that.

## Searching a (e.g. timestamp) certificate by issuer DN and serial number

ldapsearch -h ldap.nrca-ds.de -b 'dc=ldap,dc=nrca-ds,dc=de' -x '(&(x509issuer=CN=14R-CA 1:PN,o=Bundesnetzagentur,c=de)(x509serialNumber=960))'
