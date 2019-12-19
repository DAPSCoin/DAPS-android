package pivx.org.pivxwallet.ui.transaction_send_activity;

import android.app.Activity;
import android.app.Fragment;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.DialogFragment;
import android.support.v4.app.FragmentActivity;
import android.support.v4.content.ContextCompat;
import android.text.Editable;
import android.text.InputFilter;
import android.text.Spanned;
import android.text.TextWatcher;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.view.inputmethod.InputMethodManager;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ExpandableListView;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ViewFlipper;

import org.pivxj.core.Address;
import org.pivxj.core.Coin;
import org.pivxj.core.InsufficientMoneyException;
import org.pivxj.core.NetworkParameters;
import org.pivxj.core.Transaction;
import org.pivxj.core.TransactionInput;
import org.pivxj.core.TransactionOutput;
import org.pivxj.uri.BitcoinURIParseException;
import org.pivxj.uri.OptionalFieldValidationException;
import org.pivxj.uri.PivxURI;
import org.pivxj.uri.RequiredFieldValidationException;
import org.pivxj.utils.MonetaryFormat;
import org.pivxj.wallet.Wallet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.URLDecoder;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import global.PivxModule;
import pivx.org.pivxwallet.PivxApplication;
import pivx.org.pivxwallet.R;
import global.AddressLabel;
import global.exceptions.NoPeerConnectedException;
import global.PivxRate;
import pivx.org.pivxwallet.service.PivxWalletService;
import pivx.org.pivxwallet.ui.base.BaseActivity;
import pivx.org.pivxwallet.ui.base.BaseDrawerActivity;
import pivx.org.pivxwallet.ui.base.PivxActivity;
import pivx.org.pivxwallet.ui.base.dialogs.SimpleTextDialog;
import pivx.org.pivxwallet.ui.base.dialogs.SimpleTwoButtonsDialog;
import pivx.org.pivxwallet.ui.transaction_send_activity.custom.ChangeAddressActivity;
import pivx.org.pivxwallet.ui.transaction_send_activity.custom.CustomFeeActivity;
import pivx.org.pivxwallet.ui.transaction_send_activity.custom.CustomFeeFragment;
import global.wrappers.InputWrapper;
import pivx.org.pivxwallet.ui.transaction_send_activity.custom.inputs.InputsActivity;
import pivx.org.pivxwallet.ui.transaction_send_activity.custom.outputs.OutputWrapper;
import pivx.org.pivxwallet.ui.transaction_send_activity.custom.outputs.OutputsActivity;
import global.wrappers.TransactionWrapper;
import pivx.org.pivxwallet.ui.twofa_config.CutCopyPasteEditText;
import pivx.org.pivxwallet.utils.AddressAdapter;
import pivx.org.pivxwallet.utils.AmountAdapter;
import pivx.org.pivxwallet.utils.AppConf;
import pivx.org.pivxwallet.utils.Base32String;
import pivx.org.pivxwallet.utils.CrashReporter;
import pivx.org.pivxwallet.utils.DapsController;
import pivx.org.pivxwallet.utils.DialogsUtil;
import pivx.org.pivxwallet.utils.FeeAdapter;
import pivx.org.pivxwallet.utils.NavigationUtils;
import pivx.org.pivxwallet.utils.PasscodeGenerator;
import pivx.org.pivxwallet.utils.RingAdapter;
import pivx.org.pivxwallet.utils.TotpCounter;
import pivx.org.pivxwallet.utils.Utilities;
import pivx.org.pivxwallet.utils.scanner.ScanActivity;
import wallet.exceptions.InsufficientInputsException;
import wallet.exceptions.TxNotFoundException;

import static android.Manifest.permission_group.CAMERA;
import static android.content.Context.INPUT_METHOD_SERVICE;
import static pivx.org.pivxwallet.service.IntentsConstants.ACTION_BROADCAST_TRANSACTION;
import static pivx.org.pivxwallet.service.IntentsConstants.DATA_TRANSACTION_HASH;
import static pivx.org.pivxwallet.ui.transaction_detail_activity.FragmentTxDetail.TX;
import static pivx.org.pivxwallet.ui.transaction_detail_activity.FragmentTxDetail.TX_MEMO;
import static pivx.org.pivxwallet.ui.transaction_detail_activity.FragmentTxDetail.TX_WRAPPER;
import static pivx.org.pivxwallet.ui.transaction_send_activity.custom.ChangeAddressActivity.INTENT_EXTRA_CHANGE_ADDRESS;
import static pivx.org.pivxwallet.ui.transaction_send_activity.custom.ChangeAddressActivity.INTENT_EXTRA_CHANGE_SEND_ORIGIN;
import static pivx.org.pivxwallet.ui.transaction_send_activity.custom.CustomFeeFragment.INTENT_EXTRA_CLEAR;
import static pivx.org.pivxwallet.ui.transaction_send_activity.custom.CustomFeeFragment.INTENT_EXTRA_FEE;
import static pivx.org.pivxwallet.ui.transaction_send_activity.custom.CustomFeeFragment.INTENT_EXTRA_IS_FEE_PER_KB;
import static pivx.org.pivxwallet.ui.transaction_send_activity.custom.CustomFeeFragment.INTENT_EXTRA_IS_MINIMUM_FEE;
import static pivx.org.pivxwallet.ui.transaction_send_activity.custom.CustomFeeFragment.INTENT_EXTRA_IS_TOTAL_FEE;
import static pivx.org.pivxwallet.ui.transaction_send_activity.custom.inputs.InputsFragment.INTENT_EXTRA_UNSPENT_WRAPPERS;
import static pivx.org.pivxwallet.ui.transaction_send_activity.custom.outputs.OutputsActivity.INTENT_EXTRA_OUTPUTS_CLEAR;
import static pivx.org.pivxwallet.ui.transaction_send_activity.custom.outputs.OutputsActivity.INTENT_EXTRA_OUTPUTS_WRAPPERS;
import static pivx.org.pivxwallet.utils.scanner.ScanActivity.INTENT_EXTRA_RESULT;

/**
 * Created by Neoperol on 5/4/17.
 */

public class SendActivity extends Fragment implements View.OnClickListener, IOnFocusListenable {
    PivxApplication pivxApplication;
    PivxModule pivxModule;
    DapsController daps;
    private FragmentActivity myContext;

    private Logger logger = LoggerFactory.getLogger(SendActivity.class);

    public static final String INTENT_EXTRA_TOTAL_AMOUNT = "total_amount";
    public static final String INTENT_ADDRESS = "intent_address";
    public static final String INTENT_MEMO = "intent_memo";

    private static final int PIN_RESULT = 121;
    private static final int SCANNER_RESULT = 122;
    private static final int CUSTOM_FEE_RESULT = 123;
    private static final int MULTIPLE_ADDRESSES_SEND_RESULT = 124;
    private static final int CUSTOM_INPUTS = 125;
    private static final int SEND_DETAIL = 126;
    private static final int CUSTOM_CHANGE_ADDRESS = 127;
    private final MonetaryFormat DAPS_FORMAT = MonetaryFormat.BTC.minDecimals(8).optionalDecimals(0).noCode();

    private SendDialog sendDialog;
    private TwoFAConfirmDialog confirmDialog;
    private View root;
    private Button buttonSend, addAllPiv;
    private EditText edit_address;
    private TextView txt_custom_fee;

    private ExpandableListView edit_fee/*, edit_ring*/;
    private EditText edit_memo, edit_amount;
    private AddressAdapter addressAdapter;
    private AmountAdapter amountAdapter;

    private FeeAdapter feeAdapter;
    private String addressStr;
    private PivxRate pivxRate;
    private SimpleTextDialog errorDialog;

    private boolean inPivs = true;
    private Transaction transaction;
    /** Several outputs */
    private List<OutputWrapper> outputWrappers;
    /** Custom inputs */
    private Set<InputWrapper> unspent;
    /** Custom fee selector */
    private CustomFeeFragment.FeeSelector customFee;
    /** Clean wallet flag */
    private boolean cleanWallet;
    /** Is multi send */
    private boolean isMultiSend;
    /** Change address */
    private boolean changeToOrigin;
    private Address changeAddress;

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

    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, Bundle savedInstanceState) {        pivxApplication = PivxActivity.pivxApplication;
        pivxApplication = PivxActivity.pivxApplication;
        pivxModule = PivxActivity.pivxModule;
        daps = PivxActivity.daps;

        View root = inflater.inflate(R.layout.fragment_transaction_send, container, false);

        edit_address = (EditText) root.findViewById(R.id.edit_address);
        edit_amount = (EditText) root.findViewById(R.id.edit_amount);
        edit_amount.setFilters(new InputFilter[] {new DecimalDigitsInputFilter(100,8)});

        edit_fee = (ExpandableListView) root.findViewById(R.id.edit_fee);
        edit_memo = (EditText) root.findViewById(R.id.edit_memo);
//
        txt_custom_fee = (TextView) root.findViewById(R.id.txt_custom_fee);
//
        root.findViewById(R.id.button_qr).setOnClickListener(this);
        buttonSend = (Button) root.findViewById(R.id.btnSend);
        buttonSend.setOnClickListener(this);

        return root;
    }

    @Override
    public void onAttach(Activity activity) {
        myContext=(FragmentActivity) activity;
        super.onAttach(activity);
    }

    private void startChangeAddressActivity(Address changeAddress, boolean changeToOrigin) {
        Intent intent = new Intent(getActivity(), ChangeAddressActivity.class);
        if (changeAddress!=null){
            intent.putExtra(INTENT_EXTRA_CHANGE_ADDRESS,changeAddress.toBase58());
        }
        intent.putExtra(INTENT_EXTRA_CHANGE_SEND_ORIGIN,changeToOrigin);
        startActivityForResult(intent,CUSTOM_CHANGE_ADDRESS);
    }

    private void startCustomFeeActivity(CustomFeeFragment.FeeSelector customFee) {
        Intent intent = new Intent(getActivity(), CustomFeeActivity.class);
        if (customFee != null) {
            intent.putExtra(INTENT_EXTRA_IS_FEE_PER_KB, customFee.isFeePerKbSelected());
            intent.putExtra(INTENT_EXTRA_IS_TOTAL_FEE, !customFee.isFeePerKbSelected());
            intent.putExtra(INTENT_EXTRA_IS_MINIMUM_FEE, customFee.isPayMinimum());
            intent.putExtra(INTENT_EXTRA_FEE, customFee.getAmount());
        }
        startActivityForResult(intent,CUSTOM_FEE_RESULT);
    }

    private void startMultiAddressSendActivity(List<OutputWrapper> outputWrappers) {
        Intent intent = new Intent(getActivity(), OutputsActivity.class);
        Bundle bundle = new Bundle();
        if (outputWrappers!=null)
            bundle.putSerializable(INTENT_EXTRA_OUTPUTS_WRAPPERS, (Serializable) outputWrappers);
        intent.putExtras(bundle);
        startActivityForResult(intent,MULTIPLE_ADDRESSES_SEND_RESULT);
    }

    private void startCoinControlActivity(Set<InputWrapper> unspent) {
        String amountStr = getAmountStr();
        if (amountStr.length()>0){
            Intent intent = new Intent(getActivity(), InputsActivity.class);
            Bundle bundle = new Bundle();
            bundle.putString(INTENT_EXTRA_TOTAL_AMOUNT,amountStr);
            if (unspent!=null)
                bundle.putSerializable(INTENT_EXTRA_UNSPENT_WRAPPERS, (Serializable) unspent);
            intent.putExtras(bundle);
            startActivityForResult(intent,CUSTOM_INPUTS);
        }else {
            Toast.makeText(getActivity(), R.string.send_amount_input_error,Toast.LENGTH_LONG).show();
        }
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        if (transaction!=null) {
            outState.putSerializable(TX,transaction.unsafeBitcoinSerialize());
        }
    }

    @Override
    public void onViewStateRestored(Bundle savedInstanceState) {
        super.onViewStateRestored(savedInstanceState);
        if (savedInstanceState != null && savedInstanceState.containsKey(TX)){
            transaction = new Transaction(pivxModule.getConf().getNetworkParams(),savedInstanceState.getByteArray(TX));
        }
    }

    @Override
    public void onResume() {
        super.onResume();

        if (feeAdapter==null) {
            List<String> list = new ArrayList<String>();
            list.add("Slow (0.005x DAPS/KB)");
            list.add("Medium (0.5x DAPS/KB)");
            list.add("Faster (0.6x DAPS/KB)");
            list.add("Fast (0.9x DAPS/KB)");

            feeAdapter= new FeeAdapter(getActivity(), list,"Medium (0.5x DAPS/KB)");
            edit_fee.setAdapter(feeAdapter);

            edit_fee.setOnGroupExpandListener(new ExpandableListView.OnGroupExpandListener() {

                @Override
                public void onGroupExpand(int groupPosition) {
                    edit_fee.getLayoutParams().height = convertDpToPx(150);
                }
            });

            edit_fee.setOnGroupCollapseListener(new ExpandableListView.OnGroupCollapseListener() {

                @Override
                public void onGroupCollapse(int groupPosition) {
                    edit_fee.getLayoutParams().height = convertDpToPx(30);
                }
            });

            edit_fee.setOnChildClickListener(new ExpandableListView.OnChildClickListener() {
                @Override
                public boolean onChildClick(ExpandableListView parent, View v,
                                            int groupPosition, int childPosition, long id) {
                    FeeAdapter adapter = (FeeAdapter)parent.getExpandableListAdapter();
                    adapter.setText((String)adapter.getChild(groupPosition, childPosition));

                    parent.collapseGroup(0);
                    return false;
                }
            });
        }

        if(getActivity().getCurrentFocus()!=null) {
            InputMethodManager inputMethodManager = (InputMethodManager) getActivity().getSystemService(INPUT_METHOD_SERVICE);
            inputMethodManager.hideSoftInputFromWindow(getActivity().getCurrentFocus().getWindowToken(), 0);
        }
    }

    @Override
    public void onClick(View v) {
        int id = v.getId();
        if (id == R.id.btnSend){
            try {
                if (checkConnectivity()) {
                    AppConf appConf = pivxApplication.getAppConf();
                    String status = appConf.getTwoFA();
                    if (status.compareTo("enabled") == 0) {
                        String lastTime = appConf.getTwoFALastTime();
                        String period = appConf.getTwoFAPeriod();
                        Date currentTime = Calendar.getInstance().getTime();
                        long diffTime = currentTime.getTime() - Long.valueOf(lastTime);
                        if (diffTime <= Long.valueOf(period) * 24 * 60 * 60)
                            send(false);
                        else {
                            if (confirmDialog != null) {
                                confirmDialog = null;
                            }
                            confirmDialog = TwoFAConfirmDialog.newInstance(daps, SendActivity.this);
                            confirmDialog.show(myContext.getSupportFragmentManager(), "twofa_confirm dialog");
                        }
                    } else
                        send(false);
                }
            }catch (IllegalArgumentException e){
                e.printStackTrace();
                showErrorDialog(e.getMessage());
            }catch (Exception e){
                e.printStackTrace();
                showErrorDialog(e.getMessage());
            }
        }else if (id == R.id.button_qr){
            if (!checkPermission(CAMERA)) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    int permsRequestCode = 200;
                    String[] perms = {"android.permission.CAMERA"};
                    requestPermissions(perms, permsRequestCode);
                }
            }
            startActivityForResult(new Intent(getActivity(), ScanActivity.class),SCANNER_RESULT);
        }
    }

    private boolean checkPermission(String permission) {
        int result = ContextCompat.checkSelfPermission(getActivity().getApplicationContext(),permission);
        return result == PackageManager.PERMISSION_GRANTED;
    }

    private boolean checkConnectivity() {
        if (!isOnline()){
            SimpleTwoButtonsDialog noConnectivityDialog = DialogsUtil.buildSimpleTwoBtnsDialog(
                    getActivity(),
                    getString(R.string.error_no_connectivity_title),
                    getString(R.string.error_no_connectivity_body),
                    new SimpleTwoButtonsDialog.SimpleTwoBtnsDialogListener() {
                        @Override
                        public void onRightBtnClicked(SimpleTwoButtonsDialog dialog) {
                            try {
                                send(true);
                            }catch (Exception e){
                                e.printStackTrace();
                                showErrorDialog(e.getMessage());
                            }
                            dialog.dismiss();

                        }

                        @Override
                        public void onLeftBtnClicked(SimpleTwoButtonsDialog dialog) {
                            dialog.dismiss();
                        }
                    }
            );
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                noConnectivityDialog.setRightBtnTextColor(getActivity().getColor(R.color.lightGreen));
            }else {
                noConnectivityDialog.setRightBtnTextColor(ContextCompat.getColor(getActivity(), R.color.lightGreen));
            }
            noConnectivityDialog.setLeftBtnTextColor(Color.WHITE)
                    .setRightBtnTextColor(Color.BLACK)
                    .setRightBtnBackgroundColor(Color.WHITE)
                    .setLeftBtnTextColor(Color.BLACK)
                    .setLeftBtnText(getString(R.string.button_cancel))
                    .setRightBtnText(getString(R.string.button_ok))
                    .show();

            return false;
        }
        return true;
    }

    public boolean isOnline() {
        ConnectivityManager cm =
                (ConnectivityManager) getActivity().getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo netInfo = cm.getActiveNetworkInfo();
        return netInfo != null && netInfo.isConnectedOrConnecting();
    }


    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == SCANNER_RESULT){
            if (resultCode==getActivity().RESULT_OK) {
                String address = "";
                try {
                    address = data.getStringExtra(INTENT_EXTRA_RESULT);
                    String usedAddress;

                    NetworkParameters params = pivxModule.getConf().getNetworkParams();
//                    String scheme = params.getUriScheme();
                    String scheme = "dapscoin";
                    if (!address.contains(scheme + ":")){
                        usedAddress = address;
                    }else {
                        usedAddress = address.substring(scheme.length() + 1);
                        String[] addressSplitTokens = usedAddress.split("\\?", 2);
                        if (addressSplitTokens.length != 0)
                            usedAddress = addressSplitTokens[0];
                        String[] nameValuePairTokens = new String[0];
                        if (addressSplitTokens.length > 1)
                            nameValuePairTokens = addressSplitTokens[1].split("&");

                        Coin amount = null;
                        String memo = "";
                        for(int i = 0; i < nameValuePairTokens.length; ++i) {
                            String nameValuePairToken = nameValuePairTokens[i];
                            int sepIndex = nameValuePairToken.indexOf(61);
                            if (sepIndex == -1) {
                                throw new BitcoinURIParseException("Malformed Pivx URI - no separator in '" + nameValuePairToken + "'");
                            }

                            if (sepIndex == 0) {
                                throw new BitcoinURIParseException("Malformed Bitcoin URI - empty name '" + nameValuePairToken + "'");
                            }

                            String nameToken = nameValuePairToken.substring(0, sepIndex).toLowerCase(Locale.ENGLISH);
                            String valueToken = nameValuePairToken.substring(sepIndex + 1);
                            if ("amount".equals(nameToken)) {
                                try {
                                    amount = Coin.parseCoin(valueToken);
                                    if (params != null && amount.isGreaterThan(params.getMaxMoney())) {
                                        throw new BitcoinURIParseException("Max number of coins exceeded");
                                    }

                                    if (amount.signum() < 0) {
                                        throw new ArithmeticException("Negative coins specified");
                                    }

                                } catch (IllegalArgumentException e) {
                                    throw new OptionalFieldValidationException(String.format(Locale.US, "'%s' is not a valid amount", valueToken), e);
                                } catch (ArithmeticException e) {
                                    throw new OptionalFieldValidationException(String.format(Locale.US, "'%s' has too many decimal places", valueToken), e);
                                }
                            } else {
                                if (nameToken.startsWith("req-")) {
                                    throw new RequiredFieldValidationException("'" + nameToken + "' is required but not known, this URI is not valid");
                                }

                                try {
                                    if (valueToken.length() > 0) {
                                        if ("message".equals(nameToken))
                                            memo = URLDecoder.decode(valueToken, "UTF-8");
                                    }
                                } catch (UnsupportedEncodingException e) {
                                    throw new RuntimeException(e);
                                }
                            }
                        }

                        edit_address.setText(usedAddress);
                        if (amount != null){
                            edit_amount.setText(amount.toPlainString());
                        }
                    }
                }catch (Exception e){
                    e.printStackTrace();
                    Toast.makeText(getActivity(),"Bad address "+address,Toast.LENGTH_LONG).show();
                }
            }
        }else if(requestCode == SEND_DETAIL){
            if (resultCode==getActivity().RESULT_OK) {
                try {
                    // pin ok, send the tx now
                    sendConfirmed();
                }catch (Exception e){
                    e.printStackTrace();
                    CrashReporter.saveBackgroundTrace(e,pivxApplication.getPackageInfo());
                    showErrorDialog(R.string.commit_tx_fail);
                }
            }
        }

        super.onActivityResult(requestCode, resultCode, data);
    }

    public int convertDpToPx(int dp) {
        return (int)(dp * SendActivity.this.getResources().getDisplayMetrics().density);
    }

    private void showErrorDialog(int resStr){
        showErrorDialog(getString(resStr));
    }

    private void showErrorDialog(String message) {
//        if (errorDialog==null){
//            errorDialog = DialogsUtil.buildSimpleErrorTextDialog(this,getResources().getString(R.string.invalid_inputs),message);
//        }else {
//            errorDialog.setBody(message);
//        }
//        errorDialog.show(getFragmentManager(),getResources().getString(R.string.send_error_dialog_tag));
        Toast.makeText(getActivity(), message, Toast.LENGTH_LONG).show();
    }

    private String getAmountStr(){
        String amountStr = "0";
        if (inPivs) {
            amountStr = edit_amount.getText().toString();
        } else {

        }
        return amountStr;
    }

    public void setAmountAndBlock(Coin amount) {
        if (inPivs) {
//            ((AmountAdapter)edit_amount.getExpandableListAdapter()).setAmountText(amount.toPlainString());
            edit_amount.setText(amount.toPlainString());
//            edit_amount.setEnabled(false);
        }else {
//            BigDecimal result = new BigDecimal(amount.toPlainString()).multiply(pivxRate.getRate()).setScale(6,RoundingMode.FLOOR);
//            editCurrency.setText(result.toPlainString());
//            edit_amount.setEnabled(false);
        }
    }

    public void unBlockAmount(){
//        if (inPivs) {
//            edit_amount.setEnabled(true);
//        }else {
//            edit_amount.setEnabled(true);
//        }
    }

    private void send(boolean sendOffline) {
        try {
            // first check amount
            String amountStr = getAmountStr();
            if (amountStr.length() < 1) throw new IllegalArgumentException("Amount not valid");
            if (amountStr.length()==1 && amountStr.equals(".")) throw new IllegalArgumentException("Amount not valid");
            if (amountStr.charAt(0)=='.'){
                amountStr = "0"+amountStr;
            }

//            String unit = getUnitStr();
            Coin amount = Coin.parseCoin(amountStr);
//            if (unit.contains("uDAPS"))
//                amount = amount.divide(1000L);
//            else if (unit.contains("mDAPS"))
//                amount = amount.divide(1000L).divide(1000L);

            if (amount.isZero()) throw new IllegalArgumentException("Amount zero, please correct it");
            if (amount.isLessThan(Transaction.MIN_NONDUST_OUTPUT)) throw new IllegalArgumentException("Amount must be greater than the minimum amount accepted from miners, "+Transaction.MIN_NONDUST_OUTPUT.toFriendlyString());

            String availableBalance = (String) daps.callRPC("getBalance");
            if (availableBalance == null)
                availableBalance = "0";
            Coin feePerKb = getFee();
//            if (amount.isGreaterThan(Coin.valueOf(pivxModule.getAvailableBalance())))
            if (amount.plus(feePerKb).isGreaterThan(Coin.parseCoin(availableBalance)))
                throw new IllegalArgumentException("Insuficient balance");

            // memo
            String memo = edit_memo.getText().toString();

            NetworkParameters params = pivxModule.getConf().getNetworkParams();

//            if ( (outputWrappers==null || outputWrappers.isEmpty()) && (unspent==null || unspent.isEmpty()) ){
                addressStr = edit_address.getText().toString();
//
                if (sendDialog != null){
                    sendDialog = null;
                }
                sendDialog = SendDialog.newInstance(DAPS_FORMAT.format(amount).toString(), "", DAPS_FORMAT.format(feePerKb).toString(), addressStr, daps);
                sendDialog.show(myContext.getSupportFragmentManager(), "send_dialog");
        } catch (Wallet.DustySendRequested e){
            e.printStackTrace();
            throw new IllegalArgumentException("Dusty send output, please increase the value of your outputs");
        }
    }

    private Transaction changeChangeAddressToOriginAddress(Transaction transaction, Address currentChangeAddress) {
        NetworkParameters params = transaction.getParams();
        // origin address is the highest from the inputs.
        TransactionInput origin = null;
        for (TransactionInput input : transaction.getInputs()) {
            if (origin==null)
                origin = input;
            else {
                if (origin.getValue().isLessThan(input.getValue())){
                    origin = input;
                }
            }
        }
        Address originAddress = origin.getConnectedOutput().getScriptPubKey().getToAddress(params,true);
        // check if the address is mine just in case
        if (!pivxModule.isAddressUsed(originAddress)) throw new IllegalStateException("origin address is not on the wallet: "+originAddress);

        // Now i just have to re organize the outputs.
        TransactionOutput changeOutput = null;
        List<TransactionOutput> outputs = new ArrayList<>();
        for (TransactionOutput transactionOutput : transaction.getOutputs()) {
            if(transactionOutput.getScriptPubKey().getToAddress(params,true).equals(currentChangeAddress)){
                changeOutput = transactionOutput;
            }else {
                outputs.add(transactionOutput);
            }
        }
        transaction.clearOutputs();
        for (TransactionOutput output : outputs) {
            transaction.addOutput(output);
        }
        // now the new change address with the same value
        transaction.addOutput(changeOutput.getValue(),originAddress);
        return transaction;
    }

    public Coin getFee() {
        Coin feePerKb = Coin.valueOf(10000L);
        // tx size calculation -> (148*inputs)+(34*outputs)+10
        //long txSize = 148 * transaction.getInputs().size() + 34 * transaction.getOutputs().size() + 10;

//        if (customFee!=null){
//            if (customFee.isPayMinimum()){
//                feePerKb = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE;
//            }else {
//                if (customFee.isFeePerKbSelected()){
//                    // fee per kB
//                    feePerKb = customFee.getAmount();
//                }else {
//                    // todo: total fee..
//                    feePerKb = customFee.getAmount();
//                }
//            }
//        }else {
//            feePerKb = Transaction.DEFAULT_TX_FEE;
//        }

        View groupView = edit_fee.getChildAt(0);
        TextView feeView = (TextView) groupView.findViewById(R.id.listTitle);
        String feeStr = feeView.getText().toString();

        if (feeStr.contains("0.005x"))
            feePerKb = Coin.valueOf(500000L);
        else if (feeStr.contains("0.5x"))
            feePerKb = Coin.valueOf(50000000L);
        else if (feeStr.contains("0.6x"))
            feePerKb = Coin.valueOf(50000000L);
        else if (feeStr.contains("0.9x"))
            feePerKb = Coin.valueOf(90000000L);

        return feePerKb;
    }

    private void sendConfirmed(){
        if(transaction==null) {
            logger.error("## trying to send a NULL transaction");
            try {
                CrashReporter.appendSavedBackgroundTraces(new StringBuilder().append("ERROR ### sendActivity - sendConfirmed - transaction NULL"));
            } catch (IOException e) {
                e.printStackTrace();
            }
            showErrorDialog(R.string.commit_tx_fail);
            return;
        }
        pivxModule.commitTx(transaction);
        Intent intent = new Intent(getActivity(), PivxWalletService.class);
        intent.setAction(ACTION_BROADCAST_TRANSACTION);
        intent.putExtra(DATA_TRANSACTION_HASH,transaction.getHash().getBytes());
        getActivity().startService(intent);
        Toast.makeText(getActivity(),R.string.sending_tx,Toast.LENGTH_LONG).show();
    }

    public void dialog_finished() {
        send(false);
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        edit_fee.setIndicatorBounds(edit_fee.getWidth()- convertDpToPx(40), edit_fee.getWidth());
    }

    public static class SendDialog extends DialogFragment {
        private View root;
        private TextView txt_amount, txt_fee, txt_to_address, txt_description;
        private String amount, fee, address, description;
        private DapsController rpc;

        @Nullable
        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            try {
                getDialog().getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
                root = inflater.inflate(R.layout.send_dialog, container);
                txt_amount = (TextView) root.findViewById(R.id.txt_amount);
                txt_fee = (TextView) root.findViewById(R.id.tx_fee);
                txt_to_address = (TextView) root.findViewById(R.id.to_address);
                txt_description = (TextView) root.findViewById(R.id.tx_description);

                txt_amount.setText(amount + " DAPS");
                txt_description.setText(description);
                txt_fee.setText(fee + " DAPS");
                txt_to_address.setText(address);

                root.findViewById(R.id.btn_ok).setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {

                        rpc.callRPC("setTxFee", fee);

                        String txId = (String)rpc.callRPC("sendToStealthAddress", address, amount);
                        Toast.makeText(getActivity(),"Tx: " + txId, Toast.LENGTH_SHORT).show();
                        Log.i("APP","tx: "+txId);

                        dismiss();
                    }
                });

                root.findViewById(R.id.btn_cancel).setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        dismiss();
                    }
                });
            } catch (Exception e){
                Toast.makeText(getActivity(),R.string.error_generic,Toast.LENGTH_SHORT).show();
                dismiss();
            }
            return root;
        }

        public void updateData(String amount, String description, String fee, String address, DapsController controller) {
            this.amount = amount;
            this.description = description;
            this.fee = fee;
            this.address = address;
            this.rpc = controller;

            if (txt_amount != null)
                txt_amount.setText(amount + " DAPS");
            if (txt_description != null)
                txt_description.setText(description);
            if (txt_fee != null)
                txt_fee.setText(fee + " DAPS");
            if (txt_to_address != null)
                txt_to_address.setText(address);
        }

        public static SendDialog newInstance(String amount, String description, String fee, String address, DapsController controller) {
            SendDialog sendDialog = new SendDialog();
            sendDialog.updateData(amount, description, fee, address, controller);
            return sendDialog;
        }
    }

    public static class TwoFAConfirmDialog extends DialogFragment implements CutCopyPasteEditText.OnCutCopyPasteListener {
        private View root;
        private DapsController rpc;
        public Fragment parenFragment;
        private CutCopyPasteEditText code1, code2, code3, code4, code5, code6;

        @Nullable
        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            try {
                getDialog().getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
                root = inflater.inflate(R.layout.twofa_confirm_dialog, container);
                code1= (CutCopyPasteEditText) root.findViewById(R.id.code_1);
                code1.setOnCutCopyPasteListener(this);
                code2= (CutCopyPasteEditText) root.findViewById(R.id.code_2);
                code2.setOnCutCopyPasteListener(this);
                code3= (CutCopyPasteEditText) root.findViewById(R.id.code_3);
                code3.setOnCutCopyPasteListener(this);
                code4= (CutCopyPasteEditText) root.findViewById(R.id.code_4);
                code4.setOnCutCopyPasteListener(this);
                code5= (CutCopyPasteEditText) root.findViewById(R.id.code_5);
                code5.setOnCutCopyPasteListener(this);
                code6= (CutCopyPasteEditText) root.findViewById(R.id.code_6);
                code6.setOnCutCopyPasteListener(this);

                root.findViewById(R.id.btn_confirm).setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        String code = "";
                        code += code1.getText().toString();
                        code += code2.getText().toString();
                        code += code3.getText().toString();
                        code += code4.getText().toString();
                        code += code5.getText().toString();
                        code += code6.getText().toString();

                        String address = (String)rpc.callRPC("getAccountAddress");
                        address = address.replaceAll("[^A-Za-z]","");
                        String checkCode = null;
                        try {
                            checkCode = getCheckCode(address);
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        } catch (Base32String.DecodingException e) {
                            e.printStackTrace();
                        }

                        if (checkCode.compareTo(code) != 0) {
                            Toast.makeText(getActivity(), "No match code", Toast.LENGTH_SHORT).show();
                            return;
                        }

                        AppConf appConf = PivxActivity.pivxApplication.getAppConf();
                        Date currentTime = Calendar.getInstance().getTime();
                        appConf.saveTwoFALastTime(String.valueOf(currentTime.getTime()));

                        dismiss();
                        ((SendActivity)parenFragment).dialog_finished();
                    }
                });

                root.findViewById(R.id.btn_cancel).setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        dismiss();
                    }
                });
            } catch (Exception e){
                Toast.makeText(getActivity(),R.string.error_generic,Toast.LENGTH_SHORT).show();
                dismiss();
            }
            return root;
        }

        private String getCheckCode(String secret) throws GeneralSecurityException,
                Base32String.DecodingException {
            final byte[] keyBytes = Base32String.decode(secret);
            Mac mac = Mac.getInstance("HMACSHA1");
            mac.init(new SecretKeySpec(keyBytes, ""));
            PasscodeGenerator pcg = new PasscodeGenerator(mac);
            TotpCounter mTotpCounter = new TotpCounter(30);
            return pcg.generateResponseCode(mTotpCounter.getValueAtTime(Utilities.millisToSeconds(System.currentTimeMillis())));
        }

        public void updateData(DapsController controller) {
            this.rpc = controller;
        }

        public void setFragment(Fragment fragment) {
            this.parenFragment = fragment;
        }

        public static TwoFAConfirmDialog newInstance(DapsController controller, Fragment fragment) {
            TwoFAConfirmDialog dlg = new TwoFAConfirmDialog();
            dlg.setCancelable(false);
            dlg.updateData(controller);
            dlg.setFragment(fragment);
            return dlg;
        }

        @Override
        public void onCut() {

        }

        @Override
        public void onCopy() {

        }

        @Override
        public void onPaste(EditText v) {
            ClipboardManager clipboardManager = (ClipboardManager)getActivity().getSystemService(Context.CLIPBOARD_SERVICE);

            if(clipboardManager.hasPrimaryClip()) {
                ClipData.Item item = clipboardManager.getPrimaryClip().getItemAt(0);

                String ptext = item.getText().toString();
                if (ptext.length() != 6) {
                    v.setText("");
                    return;
                }

                String[] splitCode = ptext.split("");
                code1.setText(splitCode[1]);
                code2.setText(splitCode[2]);
                code3.setText(splitCode[3]);
                code4.setText(splitCode[4]);
                code5.setText(splitCode[5]);
                code6.setText(splitCode[6]);
            }
        }
    }
}
