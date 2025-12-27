package com.xiaotong.keydetector;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.util.Base64;
import android.util.Log;
import android.content.res.Resources;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.lsposed.hiddenapibypass.HiddenApiBypass;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class PoCDetector {
    private byte[] mCurrentChallenge;
    private final Context mAppContext;
    private static final String TAG = "PoCDetector";
    private static final String KEY_ALIAS = "PoC_Attest_Key";
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final int RESULT_TRUSTED = 1;
    private static final int RESULT_PATCH_MODE = 512;
    private static final int ROOT_UNKNOWN = 0;
    private static final int ROOT_AOSP = 1;
    private static final int ROOT_GOOGLE_F = 2;
    private static final int ROOT_GOOGLE_I = 3;
    private static final int ROOT_VENDOR_REQUIRED = 4;

    private static final byte[] GOOGLE_ROOT_F = Base64.decode(
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==", 0);
    private static final byte[] GOOGLE_ROOT_G = Base64.decode(
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA==", 0);
    private static final byte[] GOOGLE_ROOT_H = Base64.decode(
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMfd5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmgMdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm+Vfkl5YLCazOkjWFmwIDAQAB", 0);
    private static final byte[] GOOGLE_ROOT_I = Base64.decode(
            "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhbGuLrpql5I2WJmrE5kEVZOo+dgA46mKrVJf/sgzfzs2u7M9c1Y9ZkCEiiYkhTFE9vPbasmUfXybwgZ2EM30A1ABPd124n3JbEDfsB/wnMH1AcgsJyJFPbETZiy42Fhwi+2BCA5bcHe7SrdkRIYSsdBRaKBoZsapxB0gAOs0jSPRX5M=", 0);

    private static final Set<String> VENDOR_REQUIRED_ROOT_PUBLIC_KEYS_B64 = new HashSet<>();
    static {
        try {
            Resources resources = Resources.getSystem();
            int id = resources.getIdentifier("vendor_required_attestation_certificates", "array", "android");
            if (id != 0) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                for (String raw : resources.getStringArray(id)) {
                    String normalized = raw
                            .replaceAll("\\s+", "\n")
                            .replaceAll("-BEGIN\\nCERTIFICATE-", "-BEGIN CERTIFICATE-")
                            .replaceAll("-END\\nCERTIFICATE-", "-END CERTIFICATE-");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(
                            new ByteArrayInputStream(normalized.getBytes(StandardCharsets.UTF_8)));
                    VENDOR_REQUIRED_ROOT_PUBLIC_KEYS_B64.add(
                            Base64.encodeToString(cert.getPublicKey().getEncoded(), Base64.NO_WRAP));
                }
            }
        } catch (Throwable ignored) {
        }
    }

    public PoCDetector(Context context) {
        this.mAppContext = context != null ? context.getApplicationContext() : null;
    }

    public PoCDetector() {
        this(null);
    }

    public int runDetection() {
        int resultCode = 0;

        Security.removeProvider("BC");
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                HiddenApiBypass.addHiddenApiExemptions("");
            }
        } catch (Throwable t) {
            Log.w(TAG, "HiddenApiBypass failed", t);
        }

        boolean hookInstalled = BinderHookHandler.installHook();
        if (!hookInstalled) {
            resultCode |= 4;
            Log.e(TAG, "Binder hook install failed; binder-based consistency checks may be unreliable.");
        }

        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            try {
                if (keyStore.containsAlias(KEY_ALIAS)) {
                    keyStore.deleteEntry(KEY_ALIAS);
                }
            } catch (Exception ignored) {
            }

            mCurrentChallenge = java.util.UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);

            Date now = new Date();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setCertificateNotBefore(now)
                    .setAttestationChallenge(mCurrentChallenge);

            if (Build.VERSION.SDK_INT >= 31) {
                builder.setAttestKeyAlias(null);
            }

            keyPairGenerator.initialize(builder.build());
            keyPairGenerator.generateKeyPair();

            keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            Certificate[] rawChain = keyStore.getCertificateChain(KEY_ALIAS);

            if (rawChain == null || rawChain.length < 2) {
                Log.e(TAG, "KeyStore.getCertificateChain returned invalid chain: " + (rawChain == null ? "null" : rawChain.length));
                return resultCode | 2;
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> sanitizedChain = new ArrayList<>();
            for (Certificate c : rawChain) {
                sanitizedChain.add((X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(c.getEncoded())));
            }

            X509Certificate leafCert = sanitizedChain.get(0);
            X509Certificate rootCert = sanitizedChain.get(sanitizedChain.size() - 1);
            int rootType = classifyRootType(rootCert);
            if (rootType == ROOT_UNKNOWN) {
                resultCode |= 16;
                Log.e(TAG, "Unknown attestation root key detected.");
                logCert("Root", rootCert);
            }
            if (rootType == ROOT_AOSP) {
                resultCode |= 8;
                Log.e(TAG, "AOSP/software attestation root key detected.");
                logCert("Root", rootCert);
            }

            resultCode |= checkBinderConsistency(KEY_ALIAS, hookInstalled, sanitizedChain);

            if (!verifyChainWithBouncyCastle(sanitizedChain)) {
                Log.e(TAG, "Certificate Chain Signature Verification Failed (BC Check)!");
                resultCode |= 64;
            }

            if (checkRevokedKeys(sanitizedChain)) {
                resultCode |= 256;
            }

            resultCode |= checkKeyConsistency(keyStore, leafCert);

            AttestationParseResult attestation = parseAndCheckASN1(leafCert);
            resultCode |= attestation.mask;

            resultCode |= runObfuscateStyleDeleteKeyProbe(hookInstalled);

            boolean rootTrusted = rootType == ROOT_GOOGLE_F || rootType == ROOT_GOOGLE_I || rootType == ROOT_VENDOR_REQUIRED;
            boolean locked = Boolean.TRUE.equals(attestation.deviceLocked);
            boolean bootVerified = Integer.valueOf(0).equals(attestation.verifiedBootState);
            boolean attestationOk = (resultCode & (2 | 32 | 64 | 128 | 256 | RESULT_PATCH_MODE)) == 0;
            boolean trustedBoot = rootTrusted && locked && bootVerified && attestationOk;
            if (trustedBoot) {
                resultCode |= RESULT_TRUSTED;
            }

            boolean abnormal = (resultCode & RESULT_TRUSTED) == 0 || (resultCode & ~RESULT_TRUSTED) != 0;
            if (abnormal) {
                Log.e(TAG, "=== Abnormal detection === code=" + resultCode + " (0x" + Integer.toHexString(resultCode) + ")");
                Log.e(TAG, "TrustedBoot=" + trustedBoot
                        + " rootTrusted=" + rootTrusted
                        + " rootType=" + rootTypeToString(rootType)
                        + " deviceLocked=" + attestation.deviceLocked
                        + " verifiedBootState=" + attestation.verifiedBootState
                        + " (" + verifiedBootStateToString(attestation.verifiedBootState) + ")"
                        + " attestationOk=" + attestationOk);
                if (attestation.verifiedBootHash != null) {
                    Log.e(TAG, "VerifiedBootHash=" + bytesToHex(attestation.verifiedBootHash));
                }
                logResultBits(resultCode);
                logChain("CertificateChain", sanitizedChain);
            }

            keyStore.deleteEntry(KEY_ALIAS);

        } catch (Exception e) {
            Log.e(TAG, "Detection crashed", e);
            resultCode |= 2;
        }

        Log.i(TAG, "=== Detection Finished. Code: " + resultCode + " ===");
        return resultCode;
    }

    private boolean verifyChainWithBouncyCastle(List<X509Certificate> chain) {
        try {
            java.security.Provider bcProvider = Security.getProvider("BC");
            if (bcProvider == null) {
                bcProvider = new BouncyCastleProvider();
            }

            X509Certificate root = chain.get(chain.size() - 1);
            try {
                root.checkValidity();
                root.verify(root.getPublicKey(), bcProvider);
            } catch (Exception e) {
                Log.e(TAG, "BC: Root verify failed", e);
                logCert("BC Root", root);
                return false;
            }

            PublicKey parentKey = root.getPublicKey();
            for (int i = chain.size() - 2; i >= 0; i--) {
                X509Certificate current = chain.get(i);
                try {
                    current.checkValidity();
                    current.verify(parentKey, bcProvider);
                } catch (GeneralSecurityException e) {
                    Log.e(TAG, "BC: Signature verification failed at index " + i, e);
                    logCert("BC Chain[" + i + "]", current);
                    return false;
                }
                parentKey = current.getPublicKey();
            }
            return true;
        } catch (Exception e) {
            Log.e(TAG, "BC: Chain verification error", e);
            return false;
        }
    }

    private boolean checkRootCertificate(X509Certificate rootCert) {
        return classifyRootType(rootCert) != ROOT_UNKNOWN;
    }

    private int classifyRootType(X509Certificate rootCert) {
        if (rootCert == null) return ROOT_UNKNOWN;
        byte[] key = rootCert.getPublicKey().getEncoded();
        if (Arrays.equals(key, GOOGLE_ROOT_F)) return ROOT_GOOGLE_F;
        if (Arrays.equals(key, GOOGLE_ROOT_G) || Arrays.equals(key, GOOGLE_ROOT_H)) return ROOT_AOSP;
        if (Arrays.equals(key, GOOGLE_ROOT_I)) return ROOT_GOOGLE_I;
        String keyB64 = Base64.encodeToString(key, Base64.NO_WRAP);
        return VENDOR_REQUIRED_ROOT_PUBLIC_KEYS_B64.contains(keyB64) ? ROOT_VENDOR_REQUIRED : ROOT_UNKNOWN;
    }

    private boolean checkRevokedKeys(List<X509Certificate> chain) {
        for (X509Certificate cert : chain) {
            String serialHex = cert.getSerialNumber().toString(16).toLowerCase(Locale.US);
            KeyboxRevocationList.RevocationEntry entry = KeyboxRevocationList.getEntry(mAppContext, serialHex);
            if (entry != null && entry.isRevoked()) {
                Log.e(TAG, "Revoked key detected: serial=" + serialHex + " reason=" + entry.reason);
                return true;
            }
        }
        return false;
    }

    private int checkKeyConsistency(KeyStore keyStore, X509Certificate leafCert) {
        try {
            KeyStore.Entry entry = keyStore.getEntry(KEY_ALIAS, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) return 2;
            PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            PublicKey publicKey = leafCert.getPublicKey();

            byte[] data = "ConsistencyCheck".getBytes(StandardCharsets.UTF_8);

            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(privateKey);
            signer.update(data);
            byte[] signature = signer.sign();

            java.security.Provider bcProvider = Security.getProvider("BC");
            if (bcProvider == null) bcProvider = new BouncyCastleProvider();

            Signature verifier = Signature.getInstance("SHA256withECDSA", bcProvider);
            verifier.initVerify(publicKey);
            verifier.update(data);
            boolean ok = verifier.verify(signature);
            if (!ok) {
                Log.e(TAG, "Key consistency failed: certificate public key cannot verify keystore private-key signature.");
                logCert("Leaf", leafCert);
            }
            return ok ? 0 : 128;
        } catch (KeyPermanentlyInvalidatedException e) {
            Log.e(TAG, "Key permanently invalidated", e);
            return 2;
        } catch (Exception e) {
            Log.e(TAG, "Consistency check failed", e);
            return 2;
        }
    }

    private static final class AttestationParseResult {
        final int mask;
        final Boolean deviceLocked;
        final Integer verifiedBootState;
        final byte[] verifiedBootHash;

        AttestationParseResult(int mask, Boolean deviceLocked, Integer verifiedBootState, byte[] verifiedBootHash) {
            this.mask = mask;
            this.deviceLocked = deviceLocked;
            this.verifiedBootState = verifiedBootState;
            this.verifiedBootHash = verifiedBootHash;
        }
    }

    private AttestationParseResult parseAndCheckASN1(X509Certificate leafCert) {
        int resultMask = 0;
        Boolean deviceLocked = null;
        Integer verifiedBootState = null;
        byte[] verifiedBootHash = null;
        try {
            byte[] extBytes = leafCert.getExtensionValue(KEY_ATTESTATION_OID);
            if (extBytes == null) return new AttestationParseResult(resultMask, deviceLocked, verifiedBootState, verifiedBootHash);

            ASN1InputStream ais = new ASN1InputStream(extBytes);
            ASN1OctetString octet = (ASN1OctetString) ais.readObject();
            ais.close();

            ais = new ASN1InputStream(octet.getOctets());
            ASN1Sequence seq = (ASN1Sequence) ais.readObject();
            ais.close();
            try {
                ASN1OctetString challengeOctet = (ASN1OctetString) seq.getObjectAt(4);
                byte[] certChallenge = challengeOctet.getOctets();

                if (!Arrays.equals(mCurrentChallenge, certChallenge)) {
                    Log.e(TAG, "Attestation Challenge Mismatch! Request=" +
                            new String(mCurrentChallenge) + ", Cert=" + new String(certChallenge));
                    resultMask |= 32;
                }
            } catch (Exception e) {
                Log.w(TAG, "Failed to parse Challenge", e);
            }

            ASN1Sequence teeEnforced = (ASN1Sequence) seq.getObjectAt(7);
            Enumeration<?> objs = teeEnforced.getObjects();
            while (objs.hasMoreElements()) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) objs.nextElement();
                if (tagged.getTagNo() == 704) {
                    ASN1Sequence rot = (ASN1Sequence) tagged.getBaseObject();
                    if (rot.size() >= 3) {
                        try {
                            ASN1Boolean locked = (ASN1Boolean) rot.getObjectAt(1);
                            deviceLocked = locked.isTrue();
                        } catch (Throwable ignored) {
                        }
                        try {
                            ASN1Enumerated state = (ASN1Enumerated) rot.getObjectAt(2);
                            verifiedBootState = state.getValue().intValue();
                        } catch (Throwable ignored) {
                        }
                    }
                    if (rot.size() >= 4) {
                        verifiedBootHash = ((ASN1OctetString) rot.getObjectAt(3)).getOctets();
                    }
                    break;
                }
            }

            if (verifiedBootHash != null) {
                String sysVbMeta = getSystemProperty("ro.boot.vbmeta.digest");
                String certVbMeta = bytesToHex(verifiedBootHash);

                Log.d(TAG, "Cert VBMeta: " + certVbMeta);
                Log.d(TAG, "Sys  VBMeta: " + sysVbMeta);

                if (sysVbMeta != null && !sysVbMeta.isEmpty() && !certVbMeta.matches("0+")) {
                    if (!sysVbMeta.equalsIgnoreCase(certVbMeta)) {
                        resultMask |= 32;
                        Log.e(TAG, "VBMeta digest mismatch: sys=" + sysVbMeta + " cert=" + certVbMeta);
                    }
                }
            } else {
                Log.w(TAG, "VerifiedBootHash not present in attestation (RootOfTrust missing or non-TEE attestation)");
            }

        } catch (Exception e) {
            Log.w(TAG, "ASN1 Error", e);
        }
        return new AttestationParseResult(resultMask, deviceLocked, verifiedBootState, verifiedBootHash);
    }

    private int runObfuscateStyleDeleteKeyProbe(boolean hookInstalled) {
        final String alias = "KeyDetector";
        int mask = 0;

        try {
            if (!generateAndSignObfuscateStyle(alias)) {
                return 2;
            }
            mask |= checkObfuscateStyleConsistency(alias, hookInstalled);

            if (!generateAndSignObfuscateStyle(alias)) {
                mask |= 2;
            } else {
                mask |= checkObfuscateStyleConsistency(alias, hookInstalled);
            }

            mask |= deleteEntryAndVerifyRemoved(alias);
        } catch (Throwable t) {
            Log.e(TAG, "Obfuscate-style probe crashed", t);
            mask |= 2;
        }

        return mask;
    }

    private boolean generateAndSignObfuscateStyle(String alias) {
        try {
            Date now = new Date();
            byte[] challenge = now.toString().getBytes(StandardCharsets.UTF_8);

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setCertificateNotBefore(now)
                    .setAttestationChallenge(challenge);

            if (Build.VERSION.SDK_INT >= 31) {
                builder.setAttestKeyAlias(null);
            }

            keyPairGenerator.initialize(builder.build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(challenge);
            signature.sign();
            return true;
        } catch (Throwable t) {
            Log.e(TAG, "Obfuscate-style key generation/sign failed: alias=" + alias, t);
            return false;
        }
    }

    private int checkObfuscateStyleConsistency(String alias, boolean hookInstalled) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            Certificate[] rawChain = keyStore.getCertificateChain(alias);
            if (rawChain == null || rawChain.length < 2) {
                Log.e(TAG, "Obfuscate-style getCertificateChain returned invalid chain for " + alias
                        + ": " + (rawChain == null ? "null" : rawChain.length));
                return 2;
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> sanitizedChain = new ArrayList<>();
            for (Certificate c : rawChain) {
                sanitizedChain.add((X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(c.getEncoded())));
            }

            if (!hookInstalled) {
                return 0;
            }

            return checkObfuscateStyleBinderConsistency(alias, sanitizedChain);
        } catch (Throwable t) {
            Log.e(TAG, "Obfuscate-style chain check failed: alias=" + alias, t);
            return 2;
        }
    }

    private int checkObfuscateStyleBinderConsistency(String alias, List<X509Certificate> keystoreChain) {
        if (alias == null || keystoreChain == null || keystoreChain.isEmpty()) return 2;

        try {
            if (keystoreChain.size() >= 2) {
                byte[] leafSpki = keystoreChain.get(0).getPublicKey().getEncoded();
                byte[] issuerSpki = keystoreChain.get(1).getPublicKey().getEncoded();
                if (Arrays.equals(leafSpki, issuerSpki)) {
                    Log.e(TAG, "Obfuscate-style: suspicious chain (leaf SPKI equals issuer SPKI)");
                    return 2;
                }
            }

            byte[] binderKeyEntryLeaf = BinderHookHandler.getKeyEntryLeafCertificate(alias);
            byte[] binderKeyEntryChainBlob = BinderHookHandler.getKeyEntryCertificateChainBlob(alias);

            List<byte[]> binderKeyEntryFull;
            if (binderKeyEntryLeaf != null) {
                binderKeyEntryFull = buildFullChainBytes(binderKeyEntryLeaf, binderKeyEntryChainBlob);
            } else {
                binderKeyEntryFull = buildLegacyFullChainBytes(alias);
            }

            if (binderKeyEntryFull == null || binderKeyEntryFull.isEmpty()) {
                Log.e(TAG, "Obfuscate-style: no binder-captured certificate data found");
                return 2;
            }
            if (!chainsEqualKeystoreVsDer(keystoreChain, binderKeyEntryFull)) {
                Log.e(TAG, "Obfuscate-style: keystore chain differs from binder chain: "
                        + describeChainMismatch(keystoreChain, binderKeyEntryFull));
                return 2;
            }

            byte[] binderGenerateLeaf = BinderHookHandler.getGenerateKeyLeafCertificate(alias);
            byte[] binderGenerateChainBlob = BinderHookHandler.getGenerateKeyCertificateChainBlob(alias);
            if (binderGenerateLeaf == null) {
                Log.e(TAG, "Obfuscate-style: missing binder-captured generateKey certificate");
                return 2;
            }

            byte[] referenceLeaf = binderKeyEntryLeaf != null ? binderKeyEntryLeaf : keystoreChain.get(0).getEncoded();
            if (!Arrays.equals(binderGenerateLeaf, referenceLeaf)) {
                Log.e(TAG, "Obfuscate-style: leaf certificate differs between generateKey and getKeyEntry");
                return 2;
            }

            if (binderKeyEntryLeaf != null) {
                List<byte[]> genFull = buildFullChainBytes(binderGenerateLeaf, binderGenerateChainBlob);
                List<byte[]> keyEntryFull = buildFullChainBytes(binderKeyEntryLeaf, binderKeyEntryChainBlob);
                if (!genFull.isEmpty() && !keyEntryFull.isEmpty() && !chainsEqualDer(genFull, keyEntryFull)) {
                    Log.e(TAG, "Obfuscate-style: chain differs between generateKey and getKeyEntry");
                    return 2;
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "Obfuscate-style binder consistency check failed", t);
            return 2;
        }

        return 0;
    }

    private int deleteEntryAndVerifyRemoved(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            if (!keyStore.containsAlias(alias)) {
                return 0;
            }

            keyStore.deleteEntry(alias);

            KeyStore verifyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            verifyStore.load(null);
            if (verifyStore.containsAlias(alias)) {
                Log.e(TAG, "Obfuscate-style deleteEntry did not remove alias: " + alias);
                return 2;
            }

            return 0;
        } catch (Throwable t) {
            Log.e(TAG, "Obfuscate-style deleteEntry failed: alias=" + alias, t);
            return 2;
        }
    }

    private int checkBinderConsistency(String alias, boolean hookInstalled, List<X509Certificate> keystoreChain) {
        if (!hookInstalled) return 0;
        if (alias == null || keystoreChain == null || keystoreChain.isEmpty()) return 0;

        int mask = 0;

        try {
            if (keystoreChain.size() >= 2) {
                byte[] leafSpki = keystoreChain.get(0).getPublicKey().getEncoded();
                byte[] issuerSpki = keystoreChain.get(1).getPublicKey().getEncoded();
                if (Arrays.equals(leafSpki, issuerSpki)) {
                    Log.e(TAG, "Suspicious chain: leaf public key equals issuer public key");
                    mask |= 2;
                }
            }

            byte[] binderKeyEntryLeaf = BinderHookHandler.getKeyEntryLeafCertificate(alias);
            byte[] binderKeyEntryChainBlob = BinderHookHandler.getKeyEntryCertificateChainBlob(alias);

            List<byte[]> binderKeyEntryFull = null;
            if (binderKeyEntryLeaf != null) {
                binderKeyEntryFull = buildFullChainBytes(binderKeyEntryLeaf, binderKeyEntryChainBlob);
            } else {
                binderKeyEntryFull = buildLegacyFullChainBytes(alias);
            }

            if (binderKeyEntryFull == null || binderKeyEntryFull.isEmpty()) {
                Log.e(TAG, "No binder-captured certificate data found (keystore2/legacy)");
                mask |= 2;
            } else if (!chainsEqualKeystoreVsDer(keystoreChain, binderKeyEntryFull)) {
                Log.e(TAG, "Keystore chain differs from Binder chain: " + describeChainMismatch(keystoreChain, binderKeyEntryFull));
                mask |= 2;
            }

            byte[] binderGenerateLeaf = BinderHookHandler.getGenerateKeyLeafCertificate(alias);
            byte[] binderGenerateChainBlob = BinderHookHandler.getGenerateKeyCertificateChainBlob(alias);
            if (binderGenerateLeaf != null) {
                byte[] referenceLeaf = binderKeyEntryLeaf != null ? binderKeyEntryLeaf : keystoreChain.get(0).getEncoded();
                if (!Arrays.equals(binderGenerateLeaf, referenceLeaf)) {
                    Log.e(TAG, "Patch mode detected: leaf certificate differs between generateKey and getKeyEntry");
                    mask |= (RESULT_PATCH_MODE | 2);
                } else if (binderKeyEntryLeaf != null) {
                    List<byte[]> genFull = buildFullChainBytes(binderGenerateLeaf, binderGenerateChainBlob);
                    List<byte[]> keyEntryFull = buildFullChainBytes(binderKeyEntryLeaf, binderKeyEntryChainBlob);
                    if (!genFull.isEmpty() && !keyEntryFull.isEmpty() && !chainsEqualDer(genFull, keyEntryFull)) {
                        Log.e(TAG, "Patch mode detected: chain differs between generateKey and getKeyEntry");
                        mask |= (RESULT_PATCH_MODE | 2);
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Binder consistency check failed", e);
        }

        return mask;
    }

    private static List<byte[]> buildFullChainBytes(byte[] leafDer, byte[] chainBlob) {
        List<byte[]> out = new ArrayList<>();
        if (leafDer == null) return out;
        out.add(leafDer);
        if (chainBlob == null || chainBlob.length == 0) return out;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs = cf.generateCertificates(new ByteArrayInputStream(chainBlob));
            for (Certificate c : certs) {
                out.add(c.getEncoded());
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    private static List<byte[]> buildLegacyFullChainBytes(String alias) {
        List<byte[]> out = new ArrayList<>();
        if (alias == null) return out;

        byte[] userCert = BinderHookHandler.getLegacyKeystoreBlob("USRCERT_" + alias);
        byte[] caCert = BinderHookHandler.getLegacyKeystoreBlob("CACERT_" + alias);
        if (userCert == null && caCert == null) return out;

        if (userCert != null) {
            out.add(userCert);
        } else if (caCert != null) {
            out.add(caCert);
        }

        if (caCert != null && caCert.length > 0) {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Collection<? extends Certificate> certs = cf.generateCertificates(new ByteArrayInputStream(caCert));
                for (Certificate c : certs) {
                    byte[] der = c.getEncoded();
                    if (!out.isEmpty() && Arrays.equals(out.get(0), der)) continue;
                    out.add(der);
                }
            } catch (Exception ignored) {
            }
        }

        return out;
    }

    private static boolean chainsEqualKeystoreVsDer(List<X509Certificate> keystoreChain, List<byte[]> otherChainDer) {
        if (keystoreChain == null || otherChainDer == null) return false;
        if (keystoreChain.size() != otherChainDer.size()) return false;
        try {
            for (int i = 0; i < keystoreChain.size(); i++) {
                if (!Arrays.equals(keystoreChain.get(i).getEncoded(), otherChainDer.get(i))) return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean chainsEqualDer(List<byte[]> a, List<byte[]> b) {
        if (a == null || b == null) return false;
        if (a.size() != b.size()) return false;
        for (int i = 0; i < a.size(); i++) {
            if (!Arrays.equals(a.get(i), b.get(i))) return false;
        }
        return true;
    }

    private String getSystemProperty(String key) {
        try {
            Class<?> c = Class.forName("android.os.SystemProperties");
            Method m = c.getDeclaredMethod("get", String.class);
            return (String) m.invoke(null, key);
        } catch (Exception e) { return null; }
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static String rootTypeToString(int rootType) {
        switch (rootType) {
            case ROOT_AOSP:
                return "AOSP";
            case ROOT_GOOGLE_F:
                return "GOOGLE_F";
            case ROOT_GOOGLE_I:
                return "GOOGLE_I";
            case ROOT_VENDOR_REQUIRED:
                return "VENDOR_REQUIRED";
            case ROOT_UNKNOWN:
            default:
                return "UNKNOWN";
        }
    }

    private static String verifiedBootStateToString(Integer state) {
        if (state == null) return "Unknown(null)";
        int v = state;
        if (v == 0) return "Verified";
        if (v == 1) return "Self-signed";
        if (v == 2) return "Unverified";
        if (v == 3) return "Failed";
        return "Unknown(" + v + ")";
    }

    private static void logResultBits(int code) {
        if ((code & RESULT_TRUSTED) == 0) {
            Log.e(TAG, "Flag missing: Trusted Boot (1)");
        }
        if ((code & 2) != 0) {
            Log.e(TAG, "Flag set: Tampered Attestation Key (2)");
        }
        if ((code & 4) != 0) {
            Log.e(TAG, "Flag set: Hook Failed (4)");
        }
        if ((code & 8) != 0) {
            Log.e(TAG, "Flag set: AOSP Attestation Key (8)");
        }
        if ((code & 16) != 0) {
            Log.e(TAG, "Flag set: Unknown Attestation Key (16)");
        }
        if ((code & 32) != 0) {
            Log.e(TAG, "Flag set: VBMeta/Challenge Mismatch (32)");
        }
        if ((code & 64) != 0) {
            Log.e(TAG, "Flag set: Broken Chain (64)");
        }
        if ((code & 128) != 0) {
            Log.e(TAG, "Flag set: Key Mismatch (128)");
        }
        if ((code & 256) != 0) {
            Log.e(TAG, "Flag set: Revoked Key (256)");
        }
        if ((code & RESULT_PATCH_MODE) != 0) {
            Log.e(TAG, "Flag set: Patch Mode Detected (512)");
        }
    }

    private static void logChain(String label, List<X509Certificate> chain) {
        if (chain == null) {
            Log.e(TAG, label + ": null");
            return;
        }
        Log.e(TAG, label + ": size=" + chain.size());
        for (int i = 0; i < chain.size(); i++) {
            logCert(label + "[" + i + "]", chain.get(i));
        }
    }

    private static void logCert(String label, X509Certificate cert) {
        if (cert == null) {
            Log.e(TAG, label + ": null");
            return;
        }
        try {
            Log.e(TAG, label
                    + " serialHex=" + cert.getSerialNumber().toString(16).toLowerCase(Locale.US)
                    + " sigAlg=" + cert.getSigAlgName()
                    + " pubKeyAlg=" + cert.getPublicKey().getAlgorithm()
                    + " notBefore=" + cert.getNotBefore()
                    + " notAfter=" + cert.getNotAfter());
            Log.e(TAG, label + " subject=" + cert.getSubjectX500Principal());
            Log.e(TAG, label + " issuer=" + cert.getIssuerX500Principal());
        } catch (Throwable t) {
            Log.e(TAG, label + ": failed to log certificate details", t);
        }
    }

    private static String describeChainMismatch(List<X509Certificate> keystoreChain, List<byte[]> otherChainDer) {
        if (keystoreChain == null || otherChainDer == null) {
            return "keystore=" + (keystoreChain == null ? "null" : "non-null")
                    + " binder=" + (otherChainDer == null ? "null" : "non-null");
        }
        int min = Math.min(keystoreChain.size(), otherChainDer.size());
        for (int i = 0; i < min; i++) {
            try {
                byte[] a = keystoreChain.get(i).getEncoded();
                byte[] b = otherChainDer.get(i);
                if (!Arrays.equals(a, b)) {
                    return "mismatchIndex=" + i
                            + " keystoreSerial=" + keystoreChain.get(i).getSerialNumber().toString(16).toLowerCase(Locale.US)
                            + " binderSerial=" + tryGetSerialHex(b);
                }
            } catch (Throwable ignored) {
                return "mismatchIndex=" + i + " (encode/parse failed)";
            }
        }
        if (keystoreChain.size() != otherChainDer.size()) {
            return "lengthMismatch keystore=" + keystoreChain.size() + " binder=" + otherChainDer.size();
        }
        return "unknown";
    }

    private static String tryGetSerialHex(byte[] certDer) {
        if (certDer == null || certDer.length == 0) return "null";
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
            return cert.getSerialNumber().toString(16).toLowerCase(Locale.US);
        } catch (Throwable t) {
            return "parse_failed";
        }
    }
}
