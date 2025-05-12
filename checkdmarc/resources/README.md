# About resources

The resources package contains non-Python files used by `checkdmarc`.

## Root certificates

- [DigiCert root certificates download page](https://www.digicert.com/kb/digicert-root-certificates.htm)
- [EnTrust root certificates download page](https://www.entrust.com/knowledgebase/ssl/entrust-root-certificates)
- [SSL.com root certificates download page](https://www.ssl.com/repository/)

`VMACAs.pem` contains all of these VMC CA certificates in order to verify VMCs.

### DigiCert Verified Mark Root CA

```text
Expires: 2024-09-23
Seral number:  06:C1:67:CF:EB:F4:8D:35:D6:24:10:18:5E:11:C5:EB
SHA1 fingerprint: 74:E1:6E:32:AF:75:C6:CF:51:0A:26:FF:1F:C1:15:80:68:EA:92:3E
SHA256 fingerprint: 50:43:86:C9:EE:89:32:FE:CC:95:FA:DE:42:7F:69:C3:E2:53:4B:73:10:48:9E:30:0F:EE:44:8E:33:C4:6B:42
```

[Download link](http://cacerts.digicert.com/DigiCertVerifiedMarkRootCA.crt.pem)

### Entrust Verified Mark Root Certification Authority – VMCR1

```text
Expires: 2040-12-30
Seral number: 743900bd5b07fc63d7e9150452c89bb701680463
SHA1 fingerprint: 4A:04:D5:A6:28:0E:98:E6:5C:D4:7F:87:E8:EC:A6:4C:8B:4A:9A:43
SHA256 fingerprint: 78:31:D9:5A:47:D4:25:08:CD:5C:9E:62:64:F9:09:6B:AC:19:F0:4E:B9:B7:C8:BD:D3:5F:FF:C7:1C:18:96:17
```

[Download link](https://web.entrust.com/root-certificates/VMRC1.cer)

### SSL.com VMC ECC Root CA 2024

```text
Expires: 2048-02-13
Serial Number: 11:47:C1:6A:2D:3F:4A:F7:67:5D:65:E5:C1:AC:AD:8E
SHA1 fingerprint: 2C:8F:C6:88:3D:06:F1:6C:1E:DA:1A:20:65:A6:79:CB:EF:75:FC:E6
```

[Download link](https://ssl.com/repo/certs/SSL.com-VMC-Root-2024-ECC.pem)

### SSL.com VMC RSA Root CA 2024

```text
Expires: 2048-02-13
Serial Number: 70:94:6F:AE:BE:B3:CC:E0:D8:6F:B8:76:77:80:61:CB
SHA1 fingerprint: BB:AD:CB:97:B9:6A:78:E2:24:11:EA:2C:7E:2A:F4:5A:97:46:57:C5
```

[Download link](https://ssl.com/repo/certs/SSL.com-VMC-Root-2024-RSA.pem)
