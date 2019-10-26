package pivx.org.pivxwallet.ui.transaction_request_activity;

import android.app.DialogFragment;
import android.app.Fragment;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.support.annotation.Nullable;
import android.support.v4.graphics.drawable.RoundedBitmapDrawable;
import android.support.v4.graphics.drawable.RoundedBitmapDrawableFactory;
import android.text.InputFilter;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.UnderlineSpan;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.ExpandableListView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.google.common.io.BaseEncoding;
import com.google.zxing.WriterException;

import org.pivxj.core.Address;
import org.pivxj.core.Coin;
import org.pivxj.core.NetworkParameters;
import org.pivxj.core.Transaction;
import org.pivxj.crypto.DeterministicKey;
import org.pivxj.uri.PivxURI;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import global.PivxModule;
import pivx.org.pivxwallet.PivxApplication;
import pivx.org.pivxwallet.R;
import pivx.org.pivxwallet.ui.base.BaseActivity;
import pivx.org.pivxwallet.ui.base.BaseDrawerActivity;
import pivx.org.pivxwallet.ui.base.PivxActivity;
import pivx.org.pivxwallet.ui.base.dialogs.SimpleTextDialog;
import pivx.org.pivxwallet.ui.transaction_send_activity.AmountInputFragment;
import pivx.org.pivxwallet.ui.transaction_send_activity.IOnFocusListenable;
import pivx.org.pivxwallet.ui.transaction_send_activity.SendActivity;
import pivx.org.pivxwallet.utils.AddressAdapter;
import pivx.org.pivxwallet.utils.AmountAdapter;
import pivx.org.pivxwallet.utils.Base32String;
import pivx.org.pivxwallet.utils.DapsController;
import pivx.org.pivxwallet.utils.DialogsUtil;
import pivx.org.pivxwallet.utils.NavigationUtils;
import pivx.org.pivxwallet.utils.PasscodeGenerator;
import pivx.org.pivxwallet.utils.TotpCounter;
import pivx.org.pivxwallet.utils.Utilities;

import static android.content.Context.INPUT_METHOD_SERVICE;
import static android.graphics.Color.WHITE;
import static pivx.org.pivxwallet.ui.qr_activity.MyAddressFragment.convertDpToPx;
import static pivx.org.pivxwallet.utils.AndroidUtils.copyToClipboard;
import static pivx.org.pivxwallet.utils.QrUtils.encodeAsBitmap;

/**
 * Created by Neoperol on 5/11/17.
 */

public class RequestActivity extends Fragment implements View.OnClickListener, IOnFocusListenable {
    PivxApplication pivxApplication;
    PivxModule pivxModule;
    DapsController daps;

    private ExpandableListView edit_address;
    private EditText edit_amount;
    private TextView payment_id, underline_text;
    private AddressAdapter addressAdapter;
    private String addressStr;
    private String pivxURI;
    private ImageView img_qr, img_copy, address_copy;
    private LinearLayout copy_data;

    public class DecimalDigitsInputFilter implements InputFilter {

        Pattern mPattern;

        public DecimalDigitsInputFilter(int digitsBeforeZero,int digitsAfterZero) {
            mPattern=Pattern.compile("[0-9]{0," + (digitsBeforeZero-1) + "}+((\\.[0-9]{0," + (digitsAfterZero-1) + "})?)||(\\.)?");
        }

        @Override
        public CharSequence filter(CharSequence source, int start, int end, Spanned dest, int dstart, int dend) {

            Matcher matcher=mPattern.matcher(dest);
            if(!matcher.matches())
                return "";
            return null;
        }

    }

    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, Bundle savedInstanceState) {
        pivxApplication = PivxActivity.pivxApplication;
        pivxModule = PivxActivity.pivxModule;
        daps = PivxActivity.daps;

        View root = inflater.inflate(R.layout.fragment_transaction_request, container, false);
        edit_amount = (EditText) root.findViewById(R.id.edit_amount);
        edit_amount.setFilters(new InputFilter[] {new DecimalDigitsInputFilter(100,8)});

        edit_address = (ExpandableListView) root.findViewById(R.id.edit_address);
        payment_id = (TextView) root.findViewById(R.id.edit_payment_id);
        underline_text = (TextView) root.findViewById(R.id.underline_text);
        img_qr = (ImageView) root.findViewById(R.id.img_qr);
        img_copy = (ImageView) root.findViewById(R.id.img_copy);
        copy_data = (LinearLayout) root.findViewById(R.id.copy_data);
        address_copy = (ImageView) root.findViewById(R.id.address_copy_iv);
        root.findViewById(R.id.btnRequest).setOnClickListener(this);
        root.findViewById(R.id.btnGenerate).setOnClickListener(this);
        img_copy.setOnClickListener(this);
        address_copy.setOnClickListener(this);

        return root;
    }

    private void generateQR() {
        try {
            showRequestQr();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            showErrorDialog(e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            showErrorDialog(e.getMessage());
        }
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        edit_address.setIndicatorBounds(edit_address.getWidth()- convertDpToPx(40), edit_address.getWidth());
    }

    @Override
    public void onResume() {
        super.onResume();

        if (addressAdapter == null) {
            List<String> list = new ArrayList<String>();
            String stealthAddress = PivxApplication.getInstance().getModule().getStealthAddress();
            Log.d("HELLO", stealthAddress);
            list.add(stealthAddress);
            addressAdapter = new AddressAdapter(getActivity(), list, stealthAddress);
            edit_address.setAdapter(addressAdapter);
        }

        if (getActivity().getCurrentFocus() != null) {
            InputMethodManager inputMethodManager = (InputMethodManager) getActivity().getSystemService(INPUT_METHOD_SERVICE);
            inputMethodManager.hideSoftInputFromWindow(getActivity().getCurrentFocus().getWindowToken(), 0);
        }

        final Handler handler = new Handler();
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                generateQR();
            }
        }, 500);
    }

    @Override
    public void onClick(View v) {
        int id = v.getId();
        if (id == R.id.btnRequest) {
            try {
                showRequestQr();
            } catch (IllegalArgumentException e) {
                e.printStackTrace();
                showErrorDialog(e.getMessage());
            } catch (Exception e) {
                e.printStackTrace();
                showErrorDialog(e.getMessage());
            }
        } else if (id == R.id.img_copy) {
            copyToClipboard(getActivity(), pivxURI);
            Toast.makeText(getActivity(), R.string.copy_uri, Toast.LENGTH_LONG).show();
        } else if (id == R.id.btnGenerate) {
            payment_id.setText("Payment_Test");
        } else if (id == R.id.address_copy_iv) {
            try {
                copyToClipboard(getActivity(), getAddressStr());
            } catch (Exception e) {
                e.printStackTrace();
            }
            Toast.makeText(getActivity(), R.string.copy_address_message, Toast.LENGTH_LONG).show();
        }
    }

    public int convertDpToPx(int dp) {
        return (int)(dp * this.getResources().getDisplayMetrics().density);
    }

    public String getAmountStr() throws Exception {
        if (edit_amount == null){
            throw new Exception("Fragment is not attached");
        }

        String amountStr = "0";
        amountStr = edit_amount.getText().toString();

        return amountStr;
    }

    public String getAddressStr() throws Exception {
        if (edit_address== null){
            throw new Exception("Fragment is not attached");
        }

        String addressStr = "0";
        View groupView = edit_address.getChildAt(0);
        TextView addressView = (TextView) groupView.findViewById(R.id.listTitle);
        addressStr = addressView.getText().toString();

        return addressStr;
    }

    private void showRequestQr() throws Exception {
        // first check amount
        String amountStr = getAmountStr();
        //if (amountStr.length() < 1) throw new IllegalArgumentException("Amount not valid");

        if (amountStr.length() == 1 && amountStr.equals(".")) {
            throw new IllegalArgumentException("Amount not valid");
        }

        Coin amount;
        if(amountStr.length() == 0) {
            amount = Coin.ZERO;
        } else {
            if (amountStr.charAt(0) == '.') {
                amountStr = "0" + amountStr;
            }

            amount = Coin.parseCoin(amountStr);

            if (amount.isZero()) throw new IllegalArgumentException("Amount zero, please correct it");
            if (amount.isLessThan(Transaction.MIN_NONDUST_OUTPUT))
                throw new IllegalArgumentException("Amount must be greater than the minimum amount accepted from miners, " + Transaction.MIN_NONDUST_OUTPUT.toFriendlyString());

        }
        addressStr = getAddressStr();

        String label = payment_id.getText().toString();
        NetworkParameters params = pivxModule.getConf().getNetworkParams();

        pivxURI = PivxURI.convertToBitcoinURI(params, addressStr, amount, label, "");
        pivxURI = pivxURI.replace("pivx:", "dapscoin:");
        if(amount == Coin.ZERO) {
            int endIndex = pivxURI.indexOf("?amount=");
            pivxURI = pivxURI.substring(0, endIndex);
        }
        if (img_qr != null) {
            int px = convertDpToPx(225);
            Bitmap qrBitmap = encodeAsBitmap(pivxURI, px, px, Color.parseColor("#1A1A1A"), WHITE);
            RoundedBitmapDrawable circularBitmapDrawable = RoundedBitmapDrawableFactory.create(getResources(), qrBitmap);
            circularBitmapDrawable.setCornerRadius(7);
            img_qr.setImageDrawable(circularBitmapDrawable);

            SpannableString content = new SpannableString(pivxURI);
            content.setSpan(new UnderlineSpan(), 0, content.length(), 0);
            underline_text.setText(content);

            copy_data.setVisibility(View.VISIBLE);
        }
    }

    private void showErrorDialog(String message) {
        Toast.makeText(getActivity(), message, Toast.LENGTH_LONG).show();
    }
}
