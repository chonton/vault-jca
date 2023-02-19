# JCA for VAULT

[Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html)
provides a way to plug a cryptography provider without modifying the client code. The client will
need to configure for its use.

This repository has security providers that
leverage [Vault's transit secrets](https://developer.hashicorp.com/vault/docs/v1.11.x/secrets/transit)
for implementing the following algorithms.

## [KeyPairGenerator Algorithms](https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keypairgenerator-algorithms)

| Algorithm Name | Description                                     |
|----------------|-------------------------------------------------|
| RSA            | keypairs for the RSA algorithm                  |
| RSASSA-PSS	    | keypairs for the RSASSA-PSS signature algorithm |
| EC	            | keypairs for the Elliptic Curve algorithm       |

## KeyStore Algorithms

| Algorithm Name | Description              |
|----------------|--------------------------|
| Vault          | keypairs stored in Vault |

## [Signature Algorithms](https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#signature-algorithms)

| Algorithm Name    | Description                            |
|-------------------|----------------------------------------|
| *Deterministic*   | RSA signatures using RSASSA-PKCS1-v1_5 |
| SHA256withRSA     | RSA_2048                               |
| SHA384withRSA     | RSA_3072                               |
| SHA512withRSA     | RSA_4096                               |
| *Randomized*      | RSA signatures using RSASSA-PSS        |
| RSASSA-PSS/SHA256 | RSA_2048                               |
| RSASSA-PSS/SHA384 | RSA_3072                               |
| RSASSA-PSS/SHA512 | RSA_4096                               |
| *Eliptic Curve*   |                                        |
| SHA256withECDSA   | ECDSA_P256                             |
| SHA384withECDSA   | ECDSA_P384                             |
| SHA512withECDSA   | ECDSA_P521                             |

# Keys Security

All private keys remain in Vault. The public key is available through the KeyStore interface. A new
KeyPair is generated using the KeyPairGenerator interface.
