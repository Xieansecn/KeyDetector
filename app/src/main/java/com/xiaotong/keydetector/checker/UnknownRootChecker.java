package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Constant.ROOT_UNKNOWN;

import android.util.Log;
import com.xiaotong.keydetector.CheckerContext;
import com.xiaotong.keydetector.Util;

public final class UnknownRootChecker extends Checker {
    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        if (ctx.rootType == ROOT_UNKNOWN) {
            Log.e("Detector", "Unknown attestation root key detected.");
            Util.logCert("Root", ctx.certChain.get(ctx.certChain.size() - 1));
            return true;
        }
        return false;
    }

    @Override
    public String description() {
        return "Unknown Attestation Key (%d)\n根证书未知";
    }
}
