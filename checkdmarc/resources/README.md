# About resources

Currently, there only two Mark Verifying Athorities that issue Verified Mark Certificates (VMCs) for use with [BIMI standard](https://bimigroup.org/implementation-guide/): [DigiCert](https://www.digicert.com/tls-ssl/verified-mark-certificates) and [Entrust](https://store.entrust.com/default/vmc.html).
They provide their customers with certificate chains containing the intermedate certificate and VMC. The root certificates for these certificates are different than the root certificates used fpr browsers.

- [DigiCert root Certificates download page](https://www.digicert.com/kb/digicert-root-certificates.htm)
- [EnTrust root Certificates download page](https://www.entrust.com/knowledgebase/ssl/entrust-root-certificates)

## Root certificates

DigiCert Verified Mark Root CA

```text
Expires: 2024-09-23
Seral number:  06:C1:67:CF:EB:F4:8D:35:D6:24:10:18:5E:11:C5:EB
SHA1 fingerprint: 74:E1:6E:32:AF:75:C6:CF:51:0A:26:FF:1F:C1:15:80:68:EA:92:3E
SHA256 fingerprint: 50:43:86:C9:EE:89:32:FE:CC:95:FA:DE:42:7F:69:C3:E2:53:4B:73:10:48:9E:30:0F:EE:44:8E:33:C4:6B:42
```

[Download link](http://cacerts.digicert.com/DigiCertVerifiedMarkRootCA.crt.pem)

Entrust Verified Mark Root Certification Authority – VMCR1

```text
Expires: 2040-12-30
Seral number: 743900bd5b07fc63d7e9150452c89bb701680463
SHA1 fingerprint: 4A:04:D5:A6:28:0E:98:E6:5C:D4:7F:87:E8:EC:A6:4C:8B:4A:9A:43
SHA256 fingerprint: 78:31:D9:5A:47:D4:25:08:CD:5C:9E:62:64:F9:09:6B:AC:19:F0:4E:B9:B7:C8:BD:D3:5F:FF:C7:1C:18:96:17
```

[Download link](https://web.entrust.com/root-certificates/VMRC1.cer)

`VMACAs.pem` contains both of these certificates in order to verify VMCs.
