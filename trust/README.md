# Trusted TSA roots

`custody-verify --tsa-ca trust/` trusts exactly these certificates as roots for RFC 3161
timestamp chains. Choose your own bundle for real cases; the verifier never trusts
certificates supplied by the case database or the TSA token itself.

| File | Root | SHA-256 fingerprint | Source |
|---|---|---|---|
| `freetsa-cacert.pem` | Free TSA Root CA | `a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc` | https://freetsa.org/files/cacert.pem |
| `digicert-trusted-root-g4.pem` | DigiCert Trusted Root G4 | `552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988` | macOS system roots |
| `usertrust-rsa-ca.pem` | USERTrust RSA Certification Authority (Sectigo TSA) | `e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2` | macOS system roots |
| `globalsign-root-r6.pem` | GlobalSign Root CA - R6 | `2cabeafe37d06ca22aba7391c0033d25982952c453647349763a3ab5ad6ccf69` | macOS system roots |
| `sslcom-root-rsa.pem` | SSL.com Root Certification Authority RSA | `85666a562ee0be5ce925c1d8890a6f76a87ec16d4d7d5f29ea7419cf20123b69` | macOS system roots |

Check a fingerprint: `openssl x509 -in trust/freetsa-cacert.pem -noout -fingerprint -sha256`
