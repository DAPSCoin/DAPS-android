package pivx.org.pivxwallet.ui.history_activity;

import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.text.SpannableString;
import android.text.style.UnderlineSpan;
import android.view.MenuItem;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import pivx.org.pivxwallet.R;
import pivx.org.pivxwallet.ui.settings_activity.PhraseActivity;
import pivx.org.pivxwallet.utils.AndroidUtils;

public class TransactionActivity extends AppCompatActivity {
    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_transaction);

        setupView();
    }

    private void setupView() {
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        getSupportActionBar().setDisplayShowHomeEnabled(true);
        getSupportActionBar().setTitle("");

        TextView sentDapsTv = (TextView)findViewById(R.id.textView10);
        final TextView addressTv = (TextView)findViewById(R.id.textView21);
        final TextView transactionIdTv = (TextView)findViewById(R.id.textView23);
        ImageView addressCopyIv = (ImageView)findViewById(R.id.imageView2);
        ImageView transactionIdCopyIv = (ImageView)findViewById(R.id.imageView3);

        String sentDaps = sentDapsTv.getText().toString();
        SpannableString sentDapsSpan = new SpannableString(sentDaps);
        sentDapsSpan.setSpan(new UnderlineSpan(), 0, sentDaps.length(), 0);
        sentDapsTv.setText(sentDapsSpan);

        String address = sentDapsTv.getText().toString();
        SpannableString addressSpan = new SpannableString(address);
        addressSpan.setSpan(new UnderlineSpan(), 0, sentDaps.length(), 0);
        addressTv.setText(addressSpan);

        String transactionId = transactionIdTv.getText().toString();
        SpannableString transactionIdSpan = new SpannableString(transactionId);
        transactionIdSpan.setSpan(new UnderlineSpan(), 0, sentDaps.length(), 0);
        transactionIdTv.setText(transactionIdSpan);

        addressCopyIv.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                AndroidUtils.copyToClipboard(TransactionActivity.this, addressTv.getText().toString());
                Toast.makeText(TransactionActivity.this, R.string.copy_address_message, Toast.LENGTH_LONG).show();
            }
        });

        transactionIdCopyIv.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                AndroidUtils.copyToClipboard(TransactionActivity.this, transactionIdTv.getText().toString());
                Toast.makeText(TransactionActivity.this, R.string.copy_transaction_id_message, Toast.LENGTH_LONG).show();
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
