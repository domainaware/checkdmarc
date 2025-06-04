# About resources

The resources package contains non-Python files used by `checkdmarc`.

## Root certificates

- [DigiCert root certificates download page](https://www.digicert.com/kb/digicert-root-certificates.htm)
- [GlobslSign root certificates download page](https://support.globalsign.com/ca-certificates/root-certificates/globalsign-root-certificates)
- [SSL.com root certificates download page](https://www.ssl.com/repository/)

`VMACAs.pem` contains all of these VMC CA certificates in order to verify VMCs.

More information about VMC Certificate Authorities can be found on the [VMC Issuers](https://bimigroup.org/vmc-issuers/) page of the BIMI Group website.

### DigiCert Verified Mark Root CA

```text
Expires: 2024-09-23
Seral number:  06:C1:67:CF:EB:F4:8D:35:D6:24:10:18:5E:11:C5:EB
SHA1 fingerprint: 74:E1:6E:32:AF:75:C6:CF:51:0A:26:FF:1F:C1:15:80:68:EA:92:3E
SHA256 fingerprint: 50:43:86:C9:EE:89:32:FE:CC:95:FA:DE:42:7F:69:C3:E2:53:4B:73:10:48:9E:30:0F:EE:44:8E:33:C4:6B:42
```

[Download link](http://cacerts.digicert.com/DigiCertVerifiedMarkRootCA.crt.pem)

## GlobalSign Verified Mark Root R42

```text
Expires: 2042-12-15
Serial number: 7f:e5:30:03:81:98:a7:5f:7d:17:c0:0f:24:2c:ab:f3
SHA1 fingerprint: 37:eb:5e:fe:12:99:47:7c:f8:c4:e8:94:64:4e:56:d1:da:d7:69:96
```

[Download link](https://secure.globalsign.com/cacert/gsverifiedmarkrootr42.crt)

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
