package com.xiaotong.keydetector.checker;

import android.util.Log;

import com.xiaotong.keydetector.CheckerContext;
import com.xiaotong.keydetector.KeyboxRevocationList;

import java.security.cert.X509Certificate;
import java.util.Locale;

public final class RevokedKeyChecker extends Checker {
    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        for (X509Certificate cert : ctx.certChain) {
            String serialHex = cert.getSerialNumber().toString(16).toLowerCase(Locale.US);
            KeyboxRevocationList.RevocationEntry entry = KeyboxRevocationList.getEntry(ctx.appContext, serialHex);
            if (entry != null && entry.isRevoked()) {
                Log.e("Detector", "Revoked key detected: serial=" + serialHex + " reason=" + entry.reason);
                return true;
            }
        }
        return false;
    }

    @Override
    public String description() {
        return "Revoked Key (%d)\n检测到已泄露的黑名单密钥";
    }
}
