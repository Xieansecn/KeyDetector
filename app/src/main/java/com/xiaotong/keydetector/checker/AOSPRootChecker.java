package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Constant.ROOT_AOSP;

import android.util.Log;
import com.xiaotong.keydetector.CheckerContext;
import com.xiaotong.keydetector.Util;

public final class AOSPRootChecker extends Checker {

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        if (ctx.rootType == ROOT_AOSP) {
            Log.e("Detector", "AOSP/software attestation root key detected.");
            Util.logCert("Root", ctx.certChain.get(ctx.certChain.size() - 1));
            return true;
        }
        return false;
    }

    @Override
    public String description() {
        return "AOSP Attestation Key (%d)\n检测到软件级 (AOSP) 根证书";
    }
}
