package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Constant.KEYSTORE_PROVIDER;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import com.xiaotong.keydetector.CheckerContext;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Keystore 2.0 ListEntries Consistency Checker
 *
 * 检测原理：
 * - Hook 框架（如 TEESimulator）拦截 containsAlias()（内部调用 getKeyEntry）
 * - Hook 框架可能不拦截 aliases()（内部调用 listEntries）
 * - containsAlias() 返回 true（Hook 返回虚假密钥）
 * - aliases() 不包含该密钥（真实 Keystore2 数据库中没有）
 * - 这种不一致说明密钥只存在于 Hook 缓存中
 *
 * 检测方法：
 * 1. 生成测试密钥
 * 2. 调用 containsAlias() 检查密钥是否存在
 * 3. 调用 aliases() 获取所有密钥列表
 * 4. 检查两者是否一致
 *
 * 关键：必须使用 Java API 的 aliases()，而不是直接调用 Binder！
 * 因为 Hook 框架在 Java API 层拦截，直接调用 Binder 会绕过 Hook。
 *
 * 检测目标：
 * - TrickyStore
 * - TEESimulator
 * - 其他不完整的 Hook 实现
 */
public final class ListEntriesChecker extends Checker {
    private static final String TEST_ALIAS = "KeyDetector_ListEntries";

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        if (Build.VERSION.SDK_INT < 31) {
            return false;
        }

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null);

        try {
            if (keyStore.containsAlias(TEST_ALIAS)) {
                keyStore.deleteEntry(TEST_ALIAS);
            }

            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
                kpg.initialize(new KeyGenParameterSpec.Builder(TEST_ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .build());
                kpg.generateKeyPair();
            } catch (Exception e) {
                Log.w("ListEntriesChecker", "Failed to generate test key", e);
                return false;
            }

            boolean containsAliasResult = keyStore.containsAlias(TEST_ALIAS);

            Enumeration<String> aliasesEnum = keyStore.aliases();
            List<String> aliasesList = new ArrayList<>();
            while (aliasesEnum.hasMoreElements()) {
                aliasesList.add(aliasesEnum.nextElement());
            }
            boolean aliasesContainsKey = aliasesList.contains(TEST_ALIAS);

            if (containsAliasResult && !aliasesContainsKey) {
                Log.e("ListEntriesChecker", "ANOMALY: listEntries inconsistency detected!");
                Log.e("ListEntriesChecker", "• containsAlias() = true (getKeyEntry intercepted by Hook)");
                Log.e("ListEntriesChecker", "• aliases() doesn't contain key (listEntries not intercepted)");
                Log.e("ListEntriesChecker", "• Key exists only in Hook's cache, not in real Keystore2 DB");
                Log.e("ListEntriesChecker", "• Total aliases from real DB: " + aliasesList.size());
                return true;
            }

            if (!containsAliasResult && aliasesContainsKey) {
                Log.e("ListEntriesChecker", "ANOMALY: Reverse inconsistency detected!");
                Log.e("ListEntriesChecker", "• containsAlias() = false");
                Log.e("ListEntriesChecker", "• aliases() contains key = true");
                Log.e("ListEntriesChecker", "• This indicates abnormal getKeyEntry interception");
                return true;
            }

            if (containsAliasResult && aliasesContainsKey) {
                Log.d("ListEntriesChecker", "Native Keystore2 behavior confirmed");
                Log.d("ListEntriesChecker", "• containsAlias() = true");
                Log.d("ListEntriesChecker", "• aliases() contains key = true");
                Log.d("ListEntriesChecker", "• Key properly persisted to Keystore2 database");
                return false;
            }

            Log.d("ListEntriesChecker", "Inconclusive: Key not found by either method");
            return false;

        } catch (Exception e) {
            Log.w("ListEntriesChecker", "Check failed", e);
            return false;
        } finally {
            try {
                if (keyStore.containsAlias(TEST_ALIAS)) {
                    keyStore.deleteEntry(TEST_ALIAS);
                }
            } catch (Exception ignored) {
            }
        }
    }

    @Override
    public String description() {
        return "IKeystoreService ListEntries Inconsistency (%d) - containsAlias/aliases 不一致";
    }
}
