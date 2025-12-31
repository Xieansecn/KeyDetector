package com.xiaotong.keydetector;

import static com.xiaotong.keydetector.Util.getCheckerContext;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.xiaotong.keydetector.checker.Checker;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 32, 32, 32);
        root.setGravity(Gravity.CENTER_HORIZONTAL);

        TextView title = new TextView(this);
        title.setText("Key Detector");
        title.setTextSize(20);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, 32);
        root.addView(title);

        Button btn = new Button(this);
        btn.setId(ViewGroup.generateViewId());
        btn.setText("开始检测 (Key Attestation)");
        root.addView(btn);

        ScrollView scrollView = new ScrollView(this);
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
        );
        scrollParams.topMargin = 32;
        scrollView.setLayoutParams(scrollParams);

        scrollView.setBackgroundColor(Color.parseColor("#F0F0F0"));
        scrollView.setPadding(16,16,16,16);

        TextView tvResult = new TextView(this);
        tvResult.setText("点击按钮开始检测...");
        tvResult.setTextSize(14);
        tvResult.setTypeface(android.graphics.Typeface.MONOSPACE);
        tvResult.setTextColor(Color.BLACK);

        scrollView.addView(tvResult);
        root.addView(scrollView);

        setContentView(root);

        btn.setOnClickListener(v -> {
            btn.setEnabled(false);
            tvResult.setText("正在生成密钥并验证证书链...\n请稍候...");
            tvResult.setTextColor(Color.DKGRAY);

            new Thread(() -> {
                DetectorEngine detector = new DetectorEngine();
                int code;
                CheckerContext ctx = getCheckerContext(this);
                if (ctx == null) {
                    code = 2;
                } else {
                    code = detector.run(ctx);
                }

                String resultText = parseResult(code);

                final int finalCode = code;
                runOnUiThread(() -> {
                    tvResult.setText(resultText);
                    int color = Color.parseColor("#006400");
                    if ((finalCode & 1) != 0) tvResult.setTextColor(Color.RED);
                    tvResult.setTextColor(color);
                    btn.setEnabled(true);
                });
            }).start();
        });
    }

    private String parseResult(int code) {
        StringBuilder sb = new StringBuilder();
        sb.append("状态码: ").append(code).append("\n");
        for (Integer flag : DetectorEngine.FlagCheckerMap.keySet()) {
            Checker checker = DetectorEngine.FlagCheckerMap.get(flag);
            if ((code & flag) != 0 && checker != null) {
                sb.append(String.format(checker.description(), flag)).append("\n");
            }
        }
        return sb.toString();
    }
}
