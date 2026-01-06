package com.xiaotong.keydetector;

import static com.xiaotong.keydetector.Constant.RESULT_TRUSTED;
import static com.xiaotong.keydetector.Constant.ROOT_AOSP;
import static com.xiaotong.keydetector.Constant.ROOT_GOOGLE_F;
import static com.xiaotong.keydetector.Constant.ROOT_GOOGLE_I;
import static com.xiaotong.keydetector.Constant.ROOT_UNKNOWN;
import static com.xiaotong.keydetector.Constant.ROOT_VENDOR_REQUIRED;

import android.util.Log;

import com.xiaotong.keydetector.checker.AOSPRootChecker;
import com.xiaotong.keydetector.checker.AttestationComplianceChecker;
import com.xiaotong.keydetector.checker.BinderConsistencyChecker;
import com.xiaotong.keydetector.checker.BinderHookChecker;
import com.xiaotong.keydetector.checker.BouncyCastleChainChecker;
import com.xiaotong.keydetector.checker.ChallengeChecker;
import com.xiaotong.keydetector.checker.Checker;
import com.xiaotong.keydetector.checker.KeyConsistencyChecker;
import com.xiaotong.keydetector.checker.PatchModeChecker;
import com.xiaotong.keydetector.checker.RevokedKeyChecker;
import com.xiaotong.keydetector.checker.UnknownRootChecker;
import com.xiaotong.keydetector.checker.VBMetaChecker;

import java.util.LinkedHashMap;
import java.util.Map;

public final class DetectorEngine {
    public static final LinkedHashMap<Integer, Checker> FlagCheckerMap = new LinkedHashMap<>();
    static {
        FlagCheckerMap.put(2, new BinderConsistencyChecker());
        FlagCheckerMap.put(4, new BinderHookChecker());
        FlagCheckerMap.put(8, new AOSPRootChecker());
        FlagCheckerMap.put(16, new UnknownRootChecker());
        FlagCheckerMap.put(32, new ChallengeChecker());
        FlagCheckerMap.put(64, new BouncyCastleChainChecker());
        FlagCheckerMap.put(128, new KeyConsistencyChecker());
        FlagCheckerMap.put(256, new RevokedKeyChecker());
        FlagCheckerMap.put(512, new PatchModeChecker());
        FlagCheckerMap.put(1024, new AttestationComplianceChecker());
        FlagCheckerMap.put(2048, new VBMetaChecker());
    }

    public int run(CheckerContext ctx) {
        int result = 0;

        for (Map.Entry<Integer, Checker> entry : DetectorEngine.FlagCheckerMap.entrySet()) {
            try {
                if (entry.getValue() == null) continue; // ?
                boolean hit = entry.getValue().check(ctx);
                if (hit) {
                    result |= entry.getKey();
                    Log.e("Detector", "Hit: " + entry.getValue().name()
                            + " flag=0x" + Integer.toHexString(entry.getKey()));
                }
            } catch (Throwable t) {
                Log.e("Detector", "Checker crashed: " + entry.getValue().name(), t);
                result |= 2;
            }
        }

        if ((result & 512) != 0) {
            result |= 2;
        }

        boolean locked = false;
        boolean verified = false;
        RootOfTrust rot = null;
        if (ctx.certChain != null && !ctx.certChain.isEmpty()) {
            rot = RootOfTrust.parse(ctx.certChain.get(0));
            locked = rot != null && Boolean.TRUE.equals(rot.getDeviceLocked());
            verified = rot != null && Integer.valueOf(0).equals(rot.getVerifiedBootState());
        }
        
        if (result == 0) {
            if (locked && verified) {
                result |= RESULT_TRUSTED;
            }
        }

        boolean trustedBoot = (result & RESULT_TRUSTED) != 0;
        boolean rootTrusted = ctx.rootType == ROOT_GOOGLE_F || ctx.rootType == ROOT_GOOGLE_I || ctx.rootType == ROOT_VENDOR_REQUIRED;
        boolean attestationOk = (result & (2 | 32 | 64 | 128 | 256 | 512)) == 0;

        boolean abnormal = (result & RESULT_TRUSTED) == 0 || (result & ~RESULT_TRUSTED) != 0;
        if (abnormal) {
            Log.e("Detector", "=== Abnormal detection === code=" + result + " (0x" + Integer.toHexString(result) + ")");
            Log.e("Detector", "TrustedBoot=" + trustedBoot
                    + " rootTrusted=" + rootTrusted
                    + " rootType=" + rootTypeToString(ctx.rootType)
                    + " deviceLocked=" + (rot != null ? rot.getDeviceLocked() : "null")
                    + " verifiedBootState=" + (rot != null ? rot.getVerifiedBootState() : "null")
                    + " (" + verifiedBootStateToString(rot != null ? rot.getVerifiedBootState() : null) + ")"
                    + " attestationOk=" + attestationOk);
            if (rot != null && rot.getVerifiedBootHash() != null) {
                Log.e("Detector", "VerifiedBootHash=" + Util.byteArrayToHexString(rot.getVerifiedBootHash()));
            }
            logResultBits(result);
            Util.logChain("CertificateChain", ctx.certChain);
        }

        Log.i("Detector", "=== Detection Finished. Code: " + result + " ===");
        
        return result;
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
            Log.e("Detector", "Flag missing: Trusted Boot (1)");
        }
        if ((code & 2) != 0) {
            Log.e("Detector", "Flag set: Tampered Attestation Key (2)");
        }
        if ((code & 4) != 0) {
            Log.e("Detector", "Flag set: Hook Failed (4)");
        }
        if ((code & 8) != 0) {
            Log.e("Detector", "Flag set: AOSP Attestation Key (8)");
        }
        if ((code & 16) != 0) {
            Log.e("Detector", "Flag set: Unknown Attestation Key (16)");
        }
        if ((code & 32) != 0) {
            Log.e("Detector", "Flag set: VBMeta/Challenge Mismatch (32)");
        }
        if ((code & 64) != 0) {
            Log.e("Detector", "Flag set: Broken Chain (64)");
        }
        if ((code & 128) != 0) {
            Log.e("Detector", "Flag set: Key Mismatch (128)");
        }
        if ((code & 256) != 0) {
            Log.e("Detector", "Flag set: Revoked Key (256)");
        }
        if ((code & 512) != 0) {
            Log.e("Detector", "Flag set: Patch Mode Detected (512)");
        }
    }
}
