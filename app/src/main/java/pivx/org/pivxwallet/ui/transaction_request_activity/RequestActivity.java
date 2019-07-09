package pivx.org.pivxwallet.ui.transaction_request_activity;

import android.app.DialogFragment;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.graphics.drawable.RoundedBitmapDrawable;
import android.support.v4.graphics.drawable.RoundedBitmapDrawableFactory;
import android.text.SpannableString;
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

import org.pivxj.core.Coin;
import org.pivxj.core.NetworkParameters;
import org.pivxj.core.Transaction;
import org.pivxj.uri.PivxURI;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import pivx.org.pivxwallet.R;
import pivx.org.pivxwallet.ui.base.BaseActivity;
import pivx.org.pivxwallet.ui.base.BaseDrawerActivity;
import pivx.org.pivxwallet.ui.base.dialogs.SimpleTextDialog;
import pivx.org.pivxwallet.ui.transaction_send_activity.AmountInputFragment;
import pivx.org.pivxwallet.utils.AddressAdapter;
import pivx.org.pivxwallet.utils.AmountAdapter;
import pivx.org.pivxwallet.utils.Base32String;
import pivx.org.pivxwallet.utils.DialogsUtil;
import pivx.org.pivxwallet.utils.NavigationUtils;
import pivx.org.pivxwallet.utils.PasscodeGenerator;
import pivx.org.pivxwallet.utils.TotpCounter;
import pivx.org.pivxwallet.utils.Utilities;

import static android.graphics.Color.WHITE;
import static pivx.org.pivxwallet.ui.qr_activity.MyAddressFragment.convertDpToPx;
import static pivx.org.pivxwallet.utils.AndroidUtils.copyToClipboard;
import static pivx.org.pivxwallet.utils.QrUtils.encodeAsBitmap;

/**
 * Created by Neoperol on 5/11/17.
 */

public class RequestActivity extends BaseDrawerActivity implements View.OnClickListener {

    private ExpandableListView edit_address;
    private EditText edit_amount;
    private TextView payment_id, underline_text;
    private AmountAdapter amountAdapter;
    private AddressAdapter addressAdapter;
    private String addressStr;
    private String pivxURI;
    private SimpleTextDialog errorDialog;
    private ImageView img_qr, img_copy;
    private LinearLayout copy_data;

//    private QrDialog qrDialog;

    @Override
    protected void onCreateView(Bundle savedInstanceState, ViewGroup container) {
        View root = getLayoutInflater().inflate(R.layout.fragment_transaction_request, container);
        setTitle("Receive Transaction");
//        getSupportActionBar().setDisplayHomeAsUpEnabled(true);
//        getSupportActionBar().setDisplayShowHomeEnabled(true);

        edit_amount = (EditText) root.findViewById(R.id.edit_amount);
        edit_address = (ExpandableListView) root.findViewById(R.id.edit_address);
        payment_id = (TextView) root.findViewById(R.id.edit_payment_id);
        underline_text = (TextView) root.findViewById(R.id.underline_text);
        img_qr = (ImageView) root.findViewById(R.id.img_qr);
        img_copy = (ImageView) root.findViewById(R.id.img_copy);
        copy_data = (LinearLayout) root.findViewById(R.id.copy_data);

        root.findViewById(R.id.btnRequest).setOnClickListener(this);
        root.findViewById(R.id.btnGenerate).setOnClickListener(this);
        img_copy.setOnClickListener(this);

    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
//        edit_amount.setIndicatorBounds(edit_amount.getWidth()- convertDpToPx(40), edit_amount.getWidth());
        edit_address.setIndicatorBounds(edit_address.getWidth()- convertDpToPx(40), edit_address.getWidth());
    }

    @Override
    public void onResume() {
        super.onResume();
        setNavigationMenuItemChecked(2);

        if (addressAdapter == null) {
            List<String> list = new ArrayList<String>();
            Map address = (Map) daps.callRPC("createPrivacyAccount");
            String stealthAddress = (String) address.get("stealthaddress");

            list.add(stealthAddress);
            addressAdapter = new AddressAdapter(this, list, stealthAddress);
            edit_address.setAdapter(addressAdapter);
        }

//        if (amountAdapter == null) {
//            List<String> list = new ArrayList<String>();
//            list.add("DAPS");
//            list.add("uDAPS");
//            list.add("mDAPS");
//
//            amountAdapter = new AmountAdapter(this, list, "DAPS");
//            edit_amount.setAdapter(amountAdapter);
//
//            edit_amount.setOnGroupExpandListener(new ExpandableListView.OnGroupExpandListener() {
//
//                @Override
//                public void onGroupExpand(int groupPosition) {
//                    edit_amount.getLayoutParams().height = convertDpToPx(120);
//                }
//            });
//
//            edit_amount.setOnGroupCollapseListener(new ExpandableListView.OnGroupCollapseListener() {
//
//                @Override
//                public void onGroupCollapse(int groupPosition) {
//                    edit_amount.getLayoutParams().height = convertDpToPx(30);
//                }
//            });
//
//            edit_amount.setOnChildClickListener(new ExpandableListView.OnChildClickListener() {
//                @Override
//                public boolean onChildClick(ExpandableListView parent, View v,
//                                            int groupPosition, int childPosition, long id) {
//                    AmountAdapter adapter = (AmountAdapter) parent.getExpandableListAdapter();
//                    adapter.setUnitText((String) adapter.getChild(groupPosition, childPosition));
//
//                    parent.collapseGroup(0);
//                    return false;
//                }
//            });
//        }

        if (getCurrentFocus() != null) {
            InputMethodManager inputMethodManager = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
            inputMethodManager.hideSoftInputFromWindow(getCurrentFocus().getWindowToken(), 0);
        }
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        NavigationUtils.goBackToHome(this);
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
            copyToClipboard(this,pivxURI);
            Toast.makeText(this, R.string.copy_uri, Toast.LENGTH_LONG).show();
        } else if (id == R.id.btnGenerate) {
            payment_id.setText("Payment_Test");
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
//        View groupView = edit_amount.getChildAt(0);
//        EditText amountView = (EditText) groupView.findViewById(R.id.listAmount);
        amountStr = edit_amount.getText().toString();

        return amountStr;
    }

//    public String getUnitStr() {
//        String unitStr = "DAPS";
//        View groupView = edit_amount.getChildAt(0);
//        TextView unitView = (TextView) groupView.findViewById(R.id.listTitle);
//        unitStr = unitView.getText().toString();
//
//        return unitStr;
//    }

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
        if (amountStr.length() < 1) throw new IllegalArgumentException("Amount not valid");
        if (amountStr.length() == 1 && amountStr.equals("."))
            throw new IllegalArgumentException("Amount not valid");
        if (amountStr.charAt(0) == '.') {
            amountStr = "0" + amountStr;
        }

//        String unit = getUnitStr();
        Coin amount = Coin.parseCoin(amountStr);
//        if (unit.contains("uDAPS"))
//            amount = amount.divide(1000L);
//        else if (unit.contains("mDAPS"))
//            amount = amount.divide(1000L).divide(1000L);

        if (amount.isZero()) throw new IllegalArgumentException("Amount zero, please correct it");
        if (amount.isLessThan(Transaction.MIN_NONDUST_OUTPUT))
            throw new IllegalArgumentException("Amount must be greater than the minimum amount accepted from miners, " + Transaction.MIN_NONDUST_OUTPUT.toFriendlyString());

//        addressStr = pivxModule.getFreshNewAddress().toBase58();
        addressStr = getAddressStr();

        String label = payment_id.getText().toString();
        NetworkParameters params = pivxModule.getConf().getNetworkParams();

        pivxURI = PivxURI.convertToBitcoinURI(
                params,
                addressStr,
                amount,
                label,
                ""
        );
        pivxURI = pivxURI.replace("pivx:", "dapscoin:");

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

//        if (qrDialog != null){
//            qrDialog = null;
//        }
//        qrDialog = QrDialog.newInstance(pivxURI);
//        qrDialog.setQrText(pivxURI);
//        qrDialog.show(getFragmentManager(),"qr_dialog");

    }

    private void showErrorDialog(int resStr) {
        showErrorDialog(getString(resStr));
    }

    private void showErrorDialog(String message) {
//        if (errorDialog == null) {
//            errorDialog = DialogsUtil.buildSimpleErrorTextDialog(this, getResources().getString(R.string.invalid_inputs), message);
//        } else {
//            errorDialog.setBody(message);
//        }
//        errorDialog.show(getFragmentManager(), getResources().getString(R.string.send_error_dialog_tag));
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }

//    public static class QrDialog extends DialogFragment {
//
//        private View root;
//        private ImageView img_qr;
//        private String qrText;
//
//        @Nullable
//        @Override
//        public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
//            try {
//                root = inflater.inflate(R.layout.qr_dialog, container);
//                img_qr = (ImageView) root.findViewById(R.id.img_qr);
//                root.findViewById(R.id.btn_ok).setOnClickListener(new View.OnClickListener() {
//                    @Override
//                    public void onClick(View v) {
//                        dismiss();
//                    }
//                });
//                updateQr();
//            }catch (Exception e){
//                Toast.makeText(getActivity(),R.string.error_generic,Toast.LENGTH_SHORT).show();
//                dismiss();
//                getActivity().onBackPressed();
//            }
//            return root;
//        }
//
//        private void updateQr() throws WriterException {
//            if (img_qr != null) {
//                Resources r = getResources();
//                int px = 225;
//                Log.i("Util", qrText);
//                Bitmap qrBitmap = encodeAsBitmap(qrText, px, px, Color.parseColor("#1A1A1A"), WHITE);
//                img_qr.setImageBitmap(qrBitmap);
//            }
//        }
//
//
//        public void setQrText(String qrText) throws WriterException {
//            this.qrText = qrText;
//            updateQr();
//        }
//
//        public static QrDialog newInstance(String pivxURI) throws WriterException {
//            QrDialog qrDialog = new QrDialog();
//            qrDialog.setQrText(pivxURI);
//            return qrDialog;
//        }
//    }
}
