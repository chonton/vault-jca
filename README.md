# JCA for VAULT

[Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html)
provides a way to plug a cryptography provider without modifying the client code. The client will
need to configure for its use.

This security provider leverages
[Vault's transit secrets](https://developer.hashicorp.com/vault/docs/v1.11.x/secrets/transit)
for implementing KeyStore, KeyPairGenerator, and Signature algorithms.

# Use Cases

## Register Provider

```java
  // Explicity specify vault address and token
  VaultApi.setVaultInstance(vaultAddress, vaultToken);
  private static final String providerName = VaultProvider.register().getName();

  // Otherwise, use VAULT_ADDR and VAULT_TOKEN environment variables
  private static final String NAME = VaultProvider.register().getName();
```

## KeyStore

The KeyStore can fetch exiting PublicKey from Vault.

```java
    // initialize KeyStore
    KeyStore keyStore = KeyStore.getInstance(NAME, NAME);
    keyStore.load(null, null);

    // get an existing Vault public key
    PublicKey publicKey = (PublicKey) keyStore.getKey(keyName, null);

    // list keys
    Collections.list(keyStore.aliases());
```

## KeyPairGenerator

The KeyPairGenerator will create a new KeyPair in Vault with the name given in the VaultParameterSpec

```java

    // keyAlgorithmName is from KeyPairGenerator Algorithms table below
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithmName, NAME);

    VaultParameterSpec keySpec;
    if ("EC".equals(keyAlgorithmName)) {
      // use appropriate VaultRsaKeyType
      keySpec = new VaultRsaParameterSpec(keyName, VaultRsaKeyType.RSA_3072);
    } else {
        // use appropriate VaultEcdsaKeyAlgorithm
      keySpec = new VaultEcdsaParameterSpec(keyName, VaultEcdsaKeyAlgorithm.ECDSA_P521);
    }

    keyPairGenerator.initialize(keySpec);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    // PublicKey is exported from vault and can be transfered out of process
    PublicKey publicKey = keyPair.getPublic();
    // PrivateKey remains in vault. This is a reference that can be used by signature,initSign
    PrivateKey privateKey = keyPair.getPrivate();
```

## Signature

```java
    // algorithm is from Signature Algorithms table below
    Signature signature = Signature.getInstance(signatureAlgorithmName, NAME);

    // sign
    signature.initSign(keyPair.getPrivate());
    signature.update(MESSAGE);
    byte[] signatureBytes = signature.sign();

    // verify
    signature.initVerify(publicKey);
    signature.update(MESSAGE);
    if (!signature.verify(signatureBytes)) {
      throw new VerificationException("");
    }
```

The security provider leverages
[Vault's transit secrets](https://developer.hashicorp.com/vault/docs/v1.11.x/secrets/transit)
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

| Algorithm Name       | Description                            |
|----------------------|----------------------------------------|
| *Deterministic*      | RSA signatures using RSASSA-PKCS1-v1_5 |
| SHA256withRSA        | 2048 bit RSA                           |
| SHA384withRSA        | 3072 bit RSA                           |
| SHA512withRSA        | 4096 bit RSA                           |
| *Randomized*         | RSA signatures using RSASSA-PSS        |
| SHA256withRSAandMGF1 | 2048 bit RSA, MGF1 salt 256 bits       |
| SHA384withRSAandMGF1 | 3072 bit RSA, MGF1 salt 384 bits       |
| SHA512withRSAandMGF1 | 4096 bit RSA, MGF1 salt 512 bits       |
| *Eliptic Curve*      |                                        |
| SHA256withECDSA      | 256 bit EC                             |
| SHA384withECDSA      | 384 bit EC                             |
| SHA512withECDSA      | 512 bit EC                             |

# Keys Security

All private keys remain in Vault. The public key is available through the KeyStore interface. A new
KeyPair is generated using the KeyPairGenerator interface.
