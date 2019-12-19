package pivx.org.pivxwallet.ui.settings_activity;

import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.MenuItem;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.flexbox.FlexboxLayout;

import java.util.List;
import java.util.Map;

import global.PivxModule;
import pivx.org.pivxwallet.R;
import pivx.org.pivxwallet.utils.AndroidUtils;
import pivx.org.pivxwallet.utils.DapsController;

public class PhraseActivity extends AppCompatActivity {
    private FlexboxLayout txt_words;
    public static PivxModule pivxModule;
    public static DapsController daps;
    String privateKey;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_phrase);

        setupView();
    }

    private void setupView() {
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        getSupportActionBar().setDisplayShowHomeEnabled(true);
        getSupportActionBar().setTitle("");

        List<String> textArray = pivxModule.getMnemonic();
        txt_words = (FlexboxLayout) findViewById(R.id.securityWords);

        if (textArray != null) {
            for (String word : textArray) {
                TextView textView = new TextView(this);
                FlexboxLayout.LayoutParams llp = new FlexboxLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
                llp.setMargins(0, 40, 20, 0);
                textView.setLayoutParams(llp);
                textView.setTextColor(Color.BLACK);
                textView.setBackgroundResource(R.drawable.bg_button_grey);
                textView.setPadding(10, 8, 10, 8);
                textView.setText(word);
                txt_words.addView(textView);
            }
        }

        privateKey = pivxModule.getWallet().currentViewKey().getPrivateKeyAsHex();

        TextView txt_key = (TextView) findViewById(R.id.txt_key);
        txt_key.setText(privateKey);
        txt_key.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                AndroidUtils.copyToClipboard(PhraseActivity.this, privateKey);
                Toast.makeText(PhraseActivity.this, R.string.copy_key_message, Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                finish();
                break;
        }
        return super.onOptionsItemSelected(item);
    }
}
