package com.xiaotong.keydetector;

import static com.xiaotong.keydetector.Constant.RESULT_TRUSTED;

import android.util.Log;

import com.xiaotong.keydetector.checker.AOSPRootChecker;
import com.xiaotong.keydetector.checker.AttestationComplianceChecker;
import com.xiaotong.keydetector.checker.BinderHookChecker;
import com.xiaotong.keydetector.checker.BouncyCastleChainChecker;
import com.xiaotong.keydetector.checker.ChallengeChecker;
import com.xiaotong.keydetector.checker.Checker;
import com.xiaotong.keydetector.checker.KeyConsistencyChecker;
import com.xiaotong.keydetector.checker.RevokedKeyChecker;
import com.xiaotong.keydetector.checker.UnknownRootChecker;
import com.xiaotong.keydetector.checker.VBMetaChecker;

import java.util.HashMap;

public final class DetectorEngine {
    public static final HashMap<Integer, Checker> FlagCheckerMap = new HashMap<>();
    static {
        FlagCheckerMap.put(4, new BinderHookChecker());
        FlagCheckerMap.put(8, new AOSPRootChecker());
        FlagCheckerMap.put(16, new UnknownRootChecker());
        FlagCheckerMap.put(32, new ChallengeChecker());
        FlagCheckerMap.put(64, new BouncyCastleChainChecker());
        FlagCheckerMap.put(128, new KeyConsistencyChecker());
        FlagCheckerMap.put(256, new RevokedKeyChecker());
        // idk how to re add 512 checker
        FlagCheckerMap.put(1024, new AttestationComplianceChecker());
        FlagCheckerMap.put(2048, new VBMetaChecker());
    }

    public int run(CheckerContext ctx) {
        int result = 0;

        for (Integer flag : FlagCheckerMap.keySet()) {
            Checker checker = FlagCheckerMap.get(flag);
            try {
                if (checker == null) continue; // ?
                boolean hit = checker.check(ctx);
                if (hit) {
                    result |= flag;
                    Log.e("Detector", "Hit: " + checker.name()
                            + " flag=0x" + Integer.toHexString(flag));
                }
            } catch (Throwable t) {
                Log.e("Detector", "Checker crashed: " + checker.name(), t);
                result |= 2;
            }
        }
        return Math.max(result, RESULT_TRUSTED);
    }
}
