package pivx.org.pivxwallet.ui.history_activity;

import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.text.SpannableString;
import android.text.style.UnderlineSpan;
import android.view.MenuItem;
import android.widget.TextView;

import pivx.org.pivxwallet.R;

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
        TextView addressTv = (TextView)findViewById(R.id.textView21);
        TextView transactionIdTv = (TextView)findViewById(R.id.textView23);

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
