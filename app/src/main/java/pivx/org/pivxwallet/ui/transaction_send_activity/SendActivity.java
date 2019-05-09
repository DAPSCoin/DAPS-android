package pivx.org.pivxwallet.ui.transaction_send_activity;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.DialogFragment;
import android.support.v4.content.ContextCompat;
import android.text.Editable;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import pivx.org.pivxwallet.R;
import global.AddressLabel;
import global.exceptions.NoPeerConnectedException;
import global.PivxRate;
import pivx.org.pivxwallet.service.PivxWalletService;
import pivx.org.pivxwallet.ui.base.BaseActivity;
import pivx.org.pivxwallet.ui.base.BaseDrawerActivity;
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
import pivx.org.pivxwallet.utils.AddressAdapter;
import pivx.org.pivxwallet.utils.AmountAdapter;
import pivx.org.pivxwallet.utils.CrashReporter;
import pivx.org.pivxwallet.utils.DapsController;
import pivx.org.pivxwallet.utils.DialogsUtil;
import pivx.org.pivxwallet.utils.FeeAdapter;
import pivx.org.pivxwallet.utils.NavigationUtils;
import pivx.org.pivxwallet.utils.RingAdapter;
import pivx.org.pivxwallet.utils.scanner.ScanActivity;
import wallet.exceptions.InsufficientInputsException;
import wallet.exceptions.TxNotFoundException;

import static android.Manifest.permission_group.CAMERA;
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

public class SendActivity extends BaseDrawerActivity implements View.OnClickListener {

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
    private View root;
    private Button buttonSend, addAllPiv;
    private EditText edit_address;
    private TextView txt_custom_fee;
//    private TextView txt_local_currency , txt_coin_selection, txt_custom_fee, txt_change_address, txtShowPiv;
//    private TextView txt_multiple_outputs, txt_currency_amount;
//    private View container_address;
    private ExpandableListView edit_fee/*, edit_ring*/;
    private EditText edit_memo, edit_amount;
    private AddressAdapter addressAdapter;
    private AmountAdapter amountAdapter;
//    private RingAdapter ringAdapter;
    private FeeAdapter feeAdapter;
    private String addressStr;
    private PivxRate pivxRate;
    private SimpleTextDialog errorDialog;
//    private ImageButton btnSwap;
//    private ViewFlipper amountSwap;

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


    @Override
    protected void onCreateView(Bundle savedInstanceState,ViewGroup container) {
        root = getLayoutInflater().inflate(R.layout.fragment_transaction_send, container);
        setTitle("Send Transaction");
//        getSupportActionBar().setDisplayHomeAsUpEnabled(true);
//        getSupportActionBar().setDisplayShowHomeEnabled(true);
        edit_address = (EditText) findViewById(R.id.edit_address);
        edit_amount = (EditText) findViewById(R.id.edit_amount);
        edit_fee = (ExpandableListView) findViewById(R.id.edit_fee);
//        edit_ring= (ExpandableListView) findViewById(R.id.edit_ring);
        edit_memo = (EditText) findViewById(R.id.edit_memo);
//        container_address = root.findViewById(R.id.container_address);
//        txt_local_currency = (TextView) findViewById(R.id.txt_local_currency);
//        txt_multiple_outputs = (TextView) root.findViewById(R.id.txt_multiple_outputs);
//        txt_multiple_outputs.setOnClickListener(this);
//        txt_coin_selection = (TextView) root.findViewById(R.id.txt_coin_selection);
//        txt_coin_selection.setOnClickListener(this);
        txt_custom_fee = (TextView) root.findViewById(R.id.txt_custom_fee);
//        txt_custom_fee.setOnClickListener(this);
//        txt_change_address = (TextView) root.findViewById(R.id.txt_change_address);
//        txt_change_address.setOnClickListener(this);
        findViewById(R.id.button_qr).setOnClickListener(this);
        buttonSend = (Button) findViewById(R.id.btnSend);
        buttonSend.setOnClickListener(this);

        //Swap type of ammounts
//        amountSwap = (ViewFlipper) findViewById( R.id.viewFlipper );
//        amountSwap.setInAnimation(AnimationUtils.loadAnimation(this,
//                android.R.anim.slide_in_left));
//        amountSwap.setOutAnimation(AnimationUtils.loadAnimation(this,
//                android.R.anim.slide_out_right));
//        btnSwap = (ImageButton) findViewById(R.id.btn_swap);
//        btnSwap.setOnClickListener(this);

        //Sending amount currency
//        editCurrency = (EditText) findViewById(R.id.edit_amount_currency);
//        txt_currency_amount = (TextView) root.findViewById(R.id.txt_currency_amount);
//        txtShowPiv = (TextView) findViewById(R.id.txt_show_piv) ;

        //Sending amount piv
//        addAllPiv =  (Button) findViewById(R.id.btn_add_all);
//        addAllPiv.setOnClickListener(this);
//        pivxRate = pivxModule.getRate(pivxApplication.getAppConf().getSelectedRateCoin());

//        txt_local_currency.setText("0 " + pivxRate.getCode());

//        editCurrency.addTextChangedListener(new TextWatcher() {
//            @Override
//            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
//
//            }
//
//            @Override
//            public void onTextChanged(CharSequence s, int start, int before, int count) {
//
//            }
//
//            @Override
//            public void afterTextChanged(Editable s) {
//                if (pivxRate != null) {
//                    if (s.length() > 0) {
//                        String valueStr = s.toString();
//                        if (valueStr.charAt(0) == '.') {
//                            valueStr = "0" + valueStr;
//                        }
//                        valueStr = valueStr.replace(",", "");
//                        BigDecimal result = new BigDecimal(valueStr).divide(pivxRate.getRate(), 6, BigDecimal.ROUND_DOWN);
//                        txtShowPiv.setText(result.toPlainString() + " DAPS");
//                    } else {
//                        txtShowPiv.setText("0 " + pivxRate.getCode());
//                    }
//                }else {
//                    txtShowPiv.setText(R.string.no_rate);
//                }
//                cleanWallet = false;
//            }
//        });

//        edit_amount.addTextChangedListener(new TextWatcher() {
//            @Override
//            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
//
//            }
//
//            @Override
//            public void onTextChanged(CharSequence s, int start, int before, int count) {
//
//            }
//
//            @Override
//            public void afterTextChanged(Editable s) {
//                if (s.length()>0) {
//                    if (pivxRate != null) {
//                        String valueStr = s.toString();
//                        if (valueStr.charAt(0) == '.') {
//                            valueStr = "0" + valueStr;
//                        }
//                        Coin coin = Coin.parseCoin(valueStr);
//                        txt_local_currency.setText(
//                                pivxApplication.getCentralFormats().format(
//                                        new BigDecimal(coin.getValue() * pivxRate.getRate().doubleValue()).movePointLeft(8)
//                                )
//                                        + " " + pivxRate.getCode()
//                        );
//                    }else {
//                        // rate null -> no connection.
//                        txt_local_currency.setText(R.string.no_rate);
//                    }
//                }else {
//                    if (pivxRate!=null)
//                        txt_local_currency.setText("0 "+pivxRate.getCode());
//                    else
//                        txt_local_currency.setText(R.string.no_rate);
//                }
//                cleanWallet = false;
//
//            }
//        });

        // Load data if exists
//        Intent intent = getIntent();
//        String address = intent.getStringExtra(INTENT_ADDRESS);
//        if (intent != null && address != null){
//            edit_address.setText(address);
//            Coin amount = (Coin) intent.getSerializableExtra(INTENT_EXTRA_TOTAL_AMOUNT);
//            edit_amount.setText(amount.toPlainString());
//            edit_amount.getAdapter()
//            String memo = intent.getStringExtra(INTENT_MEMO);
//            if (memo != null)
//                edit_memo.setText(memo);
//        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
//        getMenuInflater().inflate(R.menu.send_menu,menu);
        return super.onCreateOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.option_fee){
            startCustomFeeActivity(customFee);
            return true;
//        }else if(id == R.id.option_multiple_addresses){
//            startMultiAddressSendActivity(outputWrappers);
//            return true;
        }else if(id == R.id.option_select_inputs){
            startCoinControlActivity(unspent);
        }else if (id == R.id.option_change_address){
            startChangeAddressActivity(changeAddress,changeToOrigin);
        }
        return super.onOptionsItemSelected(item);
    }

    private void startChangeAddressActivity(Address changeAddress,boolean changeToOrigin) {
        Intent intent = new Intent(this, ChangeAddressActivity.class);
        if (changeAddress!=null){
            intent.putExtra(INTENT_EXTRA_CHANGE_ADDRESS,changeAddress.toBase58());
        }
        intent.putExtra(INTENT_EXTRA_CHANGE_SEND_ORIGIN,changeToOrigin);
        startActivityForResult(intent,CUSTOM_CHANGE_ADDRESS);
    }

    private void startCustomFeeActivity(CustomFeeFragment.FeeSelector customFee) {
        Intent intent = new Intent(this, CustomFeeActivity.class);
        if (customFee != null) {
            intent.putExtra(INTENT_EXTRA_IS_FEE_PER_KB, customFee.isFeePerKbSelected());
            intent.putExtra(INTENT_EXTRA_IS_TOTAL_FEE, !customFee.isFeePerKbSelected());
            intent.putExtra(INTENT_EXTRA_IS_MINIMUM_FEE, customFee.isPayMinimum());
            intent.putExtra(INTENT_EXTRA_FEE, customFee.getAmount());
        }
        startActivityForResult(intent,CUSTOM_FEE_RESULT);
    }

    private void startMultiAddressSendActivity(List<OutputWrapper> outputWrappers) {
        Intent intent = new Intent(this, OutputsActivity.class);
        Bundle bundle = new Bundle();
        if (outputWrappers!=null)
            bundle.putSerializable(INTENT_EXTRA_OUTPUTS_WRAPPERS, (Serializable) outputWrappers);
        intent.putExtras(bundle);
        startActivityForResult(intent,MULTIPLE_ADDRESSES_SEND_RESULT);
    }

    private void startCoinControlActivity(Set<InputWrapper> unspent) {
        String amountStr = getAmountStr();
        if (amountStr.length()>0){
            Intent intent = new Intent(this, InputsActivity.class);
            Bundle bundle = new Bundle();
            bundle.putString(INTENT_EXTRA_TOTAL_AMOUNT,amountStr);
            if (unspent!=null)
                bundle.putSerializable(INTENT_EXTRA_UNSPENT_WRAPPERS, (Serializable) unspent);
            intent.putExtras(bundle);
            startActivityForResult(intent,CUSTOM_INPUTS);
        }else {
            Toast.makeText(this,R.string.send_amount_input_error,Toast.LENGTH_LONG).show();
        }
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        if (transaction!=null)
            outState.putSerializable(TX,transaction.unsafeBitcoinSerialize());
    }

    @Override
    protected void onRestoreInstanceState(Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);
        // todo: test this roting the screen..
        if (savedInstanceState.containsKey(TX)){
            transaction = new Transaction(pivxModule.getConf().getNetworkParams(),savedInstanceState.getByteArray(TX));
        }
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        NavigationUtils.goBackToHome(this);
    }

    @Override
    protected void onResume() {
        super.onResume();
        setNavigationMenuItemChecked(1);

//        if (amountAdapter==null) {
//            List<String> list = new ArrayList<String>();
//            list.add("DAPS");
//            list.add("uDAPS");
//            list.add("mDAPS");
//
//            amountAdapter= new AmountAdapter(this, list,"DAPS");
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
//                    AmountAdapter adapter = (AmountAdapter)parent.getExpandableListAdapter();
//                    adapter.setUnitText((String)adapter.getChild(groupPosition, childPosition));
//
//                    parent.collapseGroup(0);
//                    return false;
//                }
//            });
//        }

        if (feeAdapter==null) {
            List<String> list = new ArrayList<String>();
            list.add("Slow (0.005x DAPS/KB)");
            list.add("Medium (0.5x DAPS/KB)");
            list.add("Faster (0.6x DAPS/KB)");
            list.add("Fast (0.9x DAPS/KB)");

            feeAdapter= new FeeAdapter(this, list,"Medium (0.5x DAPS/KB)");
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

//        if (ringAdapter==null) {
//            List<String> list = new ArrayList<String>();
//            list.add("6");
//            list.add("7");
//            list.add("8");
//            list.add("9");
//            list.add("10");
//
//            ringAdapter= new RingAdapter(this, list,"7");
//            edit_ring.setAdapter(ringAdapter);
//
//            edit_ring.setOnGroupExpandListener(new ExpandableListView.OnGroupExpandListener() {
//
//                @Override
//                public void onGroupExpand(int groupPosition) {
//                    edit_ring.getLayoutParams().height = convertDpToPx(150);
//                }
//            });
//
//            edit_ring.setOnGroupCollapseListener(new ExpandableListView.OnGroupCollapseListener() {
//
//                @Override
//                public void onGroupCollapse(int groupPosition) {
//                    edit_ring.getLayoutParams().height = convertDpToPx(30);
//                }
//            });
//
//            edit_ring.setOnChildClickListener(new ExpandableListView.OnChildClickListener() {
//                @Override
//                public boolean onChildClick(ExpandableListView parent, View v,
//                                            int groupPosition, int childPosition, long id) {
//                    RingAdapter adapter = (RingAdapter)parent.getExpandableListAdapter();
//                    adapter.setText((String)adapter.getChild(groupPosition, childPosition));
//
//                    parent.collapseGroup(0);
//                    return false;
//                }
//            });
//
//            edit_ring.setOnTouchListener(new View.OnTouchListener() {
//                // Setting on Touch Listener for handling the touch inside ScrollView
//                @Override
//                public boolean onTouch(View v, MotionEvent event) {
//                    // Disallow the touch request for parent scroll on touch of child view
//                    v.getParent().requestDisallowInterceptTouchEvent(true);
//                    return false;
//                }
//            });
//        }

        if(getCurrentFocus()!=null) {
            InputMethodManager inputMethodManager = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
            inputMethodManager.hideSoftInputFromWindow(getCurrentFocus().getWindowToken(), 0);
        }
    }

    @Override
    public void onClick(View v) {
        int id = v.getId();
        if (id == R.id.btnSend){
            try {
                if (checkConnectivity()){
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
            startActivityForResult(new Intent(this, ScanActivity.class),SCANNER_RESULT);
//        }else if(id == R.id.btn_add_all){
//            if (!isMultiSend) {
//                cleanWallet = true;
////                Coin coin = pivxModule.getAvailableBalanceCoin();
//                String availableBalance = (String) daps.callRPC("getBalance");
//                if (availableBalance == null)
//                    availableBalance = "0";
//                Coin coin = Coin.valueOf(new BigDecimal(availableBalance).longValue());
//                if (inPivs) {
//                    edit_amount.setText(coin.toPlainString());
//                    txt_local_currency.setText(
//                            pivxApplication.getCentralFormats().format(
//                                    new BigDecimal(coin.getValue() * pivxRate.getRate().doubleValue()).movePointLeft(8)
//                            )
//                                    + " " + pivxRate.getCode()
//                    );
//                } else {
//                    editCurrency.setText(
//                            pivxApplication.getCentralFormats().format(
//                                    new BigDecimal(coin.getValue() * pivxRate.getRate().doubleValue()).movePointLeft(8)
//                            )
//                    );
//                    txtShowPiv.setText(coin.toFriendlyString());
//                }
//            }else {
//                Toast.makeText(this,R.string.validate_multi_send_enabled,Toast.LENGTH_SHORT).show();
//            }
//        }else if(id == R.id.btn_swap){
//            if (!isMultiSend){
//                inPivs = !inPivs;
//                amountSwap.showNext();
//            }else {
//                Toast.makeText(this,R.string.validate_multi_send_enabled,Toast.LENGTH_LONG).show();
//            }
//        }else if (id == R.id.txt_coin_selection){
//            startCoinControlActivity(unspent);
//        }else if(id == R.id.txt_multiple_outputs){
//            startMultiAddressSendActivity(outputWrappers);
//        }else if(id == R.id.txt_custom_fee){
//            startCustomFeeActivity(customFee);
//        }else if (id == R.id.txt_change_address){
//            startChangeAddressActivity(changeAddress,changeToOrigin);
        }
    }

    private boolean checkPermission(String permission) {
        int result = ContextCompat.checkSelfPermission(getApplicationContext(),permission);
        return result == PackageManager.PERMISSION_GRANTED;
    }

    private boolean checkConnectivity() {
        if (!isOnline()){
            SimpleTwoButtonsDialog noConnectivityDialog = DialogsUtil.buildSimpleTwoBtnsDialog(
                    this,
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
                noConnectivityDialog.setRightBtnTextColor(getColor(R.color.lightGreen));
            }else {
                noConnectivityDialog.setRightBtnTextColor(ContextCompat.getColor(this, R.color.lightGreen));
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
                (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo netInfo = cm.getActiveNetworkInfo();
        return netInfo != null && netInfo.isConnectedOrConnecting();
    }


    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == SCANNER_RESULT){
            if (resultCode==RESULT_OK) {
                String address = "";
                try {
                    address = data.getStringExtra(INTENT_EXTRA_RESULT);
                    String usedAddress;

                    NetworkParameters params = pivxModule.getConf().getNetworkParams();
                    String scheme = params.getUriScheme();
                    if (!address.contains("dapscoin:")){
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

                        if (amount != null){
                            edit_address.setText(usedAddress);
                            edit_amount.setText(amount.toPlainString());
                        }
                    }
                }catch (Exception e){
                    e.printStackTrace();
                    Toast.makeText(this,"Bad address "+address,Toast.LENGTH_LONG).show();
                }
            }
        }else if(requestCode == SEND_DETAIL){
            if (resultCode==RESULT_OK) {
                try {
                    // pin ok, send the tx now
                    sendConfirmed();
                }catch (Exception e){
                    e.printStackTrace();
                    CrashReporter.saveBackgroundTrace(e,pivxApplication.getPackageInfo());
                    showErrorDialog(R.string.commit_tx_fail);
                }
            }
//        }else if(requestCode == MULTIPLE_ADDRESSES_SEND_RESULT){
//            if (resultCode == RESULT_OK){
//                if (data.hasExtra(INTENT_EXTRA_OUTPUTS_CLEAR)){
//                    outputWrappers = null;
//                    txt_multiple_outputs.setVisibility(View.GONE);
//                    container_address.setVisibility(View.VISIBLE);
//                    unBlockAmount();
//                    isMultiSend = false;
//                }else {
//                    outputWrappers = (List<OutputWrapper>) data.getSerializableExtra(INTENT_EXTRA_OUTPUTS_WRAPPERS);
//                    Coin totalAmount = Coin.ZERO;
//                    for (OutputWrapper outputWrapper : outputWrappers) {
//                        totalAmount = outputWrapper.getAmount().plus(totalAmount);
//                    }
//                    setAmountAndBlock(totalAmount);
//                    txt_multiple_outputs.setText(getString(R.string.multiple_address_send, outputWrappers.size()));
//                    txt_multiple_outputs.setVisibility(View.VISIBLE);
//                    container_address.setVisibility(View.GONE);
//                    isMultiSend = true;
//                }
//            }
//        }else if (requestCode == CUSTOM_INPUTS){
//            if (resultCode == RESULT_OK) {
//                try {
//                    Set<InputWrapper> unspents = (Set<InputWrapper>) data.getSerializableExtra(INTENT_EXTRA_UNSPENT_WRAPPERS);
//                    for (InputWrapper inputWrapper : unspents) {
//                        inputWrapper.setUnspent(pivxModule.getUnspent(inputWrapper.getParentTxHash(), inputWrapper.getIndex()));
//                    }
//                    unspent = unspents;
//                    txt_coin_selection.setVisibility(View.VISIBLE);
//                } catch (TxNotFoundException e) {
//                    e.printStackTrace();
//                    CrashReporter.saveBackgroundTrace(e,pivxApplication.getPackageInfo());
//                    Toast.makeText(this,R.string.load_inputs_fail,Toast.LENGTH_LONG).show();
//                } catch (Exception e){
//                    CrashReporter.saveBackgroundTrace(e,pivxApplication.getPackageInfo());
//                    Toast.makeText(this,R.string.load_inputs_fail,Toast.LENGTH_LONG).show();
//                }
//            }
//        }else if (requestCode == CUSTOM_FEE_RESULT){
//            if (resultCode == RESULT_OK){
//                if (data.hasExtra(INTENT_EXTRA_CLEAR)){
//                    customFee = null;
//                    txt_custom_fee.setVisibility(View.GONE);
//                }else {
//                    boolean isPerKb = data.getBooleanExtra(INTENT_EXTRA_IS_FEE_PER_KB, false);
//                    boolean isTotal = data.getBooleanExtra(INTENT_EXTRA_IS_TOTAL_FEE, false);
//                    boolean isMinimum = data.getBooleanExtra(INTENT_EXTRA_IS_MINIMUM_FEE, false);
//                    Coin feeAmount = (Coin) data.getSerializableExtra(INTENT_EXTRA_FEE);
//                    customFee = new CustomFeeFragment.FeeSelector(isPerKb, feeAmount, isMinimum);
//                    txt_custom_fee.setVisibility(View.VISIBLE);
//                }
//            }
//        }else if(requestCode == CUSTOM_CHANGE_ADDRESS){
//            if (resultCode == RESULT_OK){
//                if (data.hasExtra(ChangeAddressActivity.INTENT_EXTRA_CLEAR_CHANGE_ADDRESS)){
//                    changeAddress = null;
//                    changeToOrigin = false;
//                    txt_change_address.setVisibility(View.GONE);
//                }else {
//                    if (data.hasExtra(INTENT_EXTRA_CHANGE_SEND_ORIGIN)){
//                        changeAddress = null;
//                        changeToOrigin = true;
//                    }else {
//                        if (data.hasExtra(INTENT_EXTRA_CHANGE_ADDRESS)) {
//                            String address = data.getStringExtra(INTENT_EXTRA_CHANGE_ADDRESS);
//                            changeAddress = Address.fromBase58(pivxModule.getConf().getNetworkParams(),address);
//                        }
//                    }
//                    txt_change_address.setVisibility(View.VISIBLE);
//                }
//            }
        }

        super.onActivityResult(requestCode, resultCode, data);
    }

    public int convertDpToPx(int dp) {
        return (int)(dp * SendActivity.this.getResources().getDisplayMetrics().density);
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
//        edit_amount.setIndicatorBounds(edit_amount.getWidth()- convertDpToPx(40), edit_amount.getWidth());
        edit_fee.setIndicatorBounds(edit_fee.getWidth()- convertDpToPx(40), edit_fee.getWidth());
//        edit_ring.setIndicatorBounds(edit_ring.getWidth()- convertDpToPx(40), edit_ring.getWidth());
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
    }

//    private String getUnitStr() {
//        String unitStr = "DAPS";
//        View groupView = edit_amount.getChildAt(0);
//        TextView unitView = (TextView) groupView.findViewById(R.id.listTitle);
//        unitStr = unitView.getText().toString();
//
//        return unitStr;
//    }

    private String getAmountStr(){
        String amountStr = "0";
        if (inPivs) {
//            View groupView = edit_amount.getChildAt(0);
//            EditText amountView = (EditText) groupView.findViewById(R.id.listAmount);
            amountStr = edit_amount.getText().toString();
        }else {
//            // the value is already converted
//            String valueStr = txtShowPiv.getText().toString();
//            amountStr = valueStr.replace(" DAPS","");
//            if(valueStr.length() > 0) {
//                if (valueStr.charAt(0) == '.') {
//                    amountStr = "0" + valueStr;
//                }
//            }
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

            // check if the wallet is still syncing
//            try {
//                if(!pivxModule.isSyncWithNode()){
//                    throw new IllegalArgumentException(getString(R.string.wallet_is_not_sync));
//                }
//            } catch (NoPeerConnectedException e) {
//                if (!sendOffline) {
//                    e.printStackTrace();
//                    throw new IllegalArgumentException(getString(R.string.no_peer_connection));
//                }
//            }

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
//            if (amount.isGreaterThan(Coin.valueOf(pivxModule.getAvailableBalance())))
            if (amount.isGreaterThan(Coin.parseCoin(availableBalance)))
                throw new IllegalArgumentException("Insuficient balance");

            // memo
            String memo = edit_memo.getText().toString();

            NetworkParameters params = pivxModule.getConf().getNetworkParams();

//            if ( (outputWrappers==null || outputWrappers.isEmpty()) && (unspent==null || unspent.isEmpty()) ){
                addressStr = edit_address.getText().toString();
//                if (!pivxModule.chechAddress(addressStr))
//                    throw new IllegalArgumentException("Address not valid");
//                Coin feePerKb = getFee();
//                Address changeAddressTemp = null;
//                if (changeAddress!=null){
//                    changeAddressTemp = changeAddress;
//                }else {
//                    changeAddressTemp = pivxModule.getReceiveAddress();
//                }
//                transaction = pivxModule.buildSendTx(addressStr,amount,feePerKb,memo,changeAddressTemp);
//
//                // check if there is a need to change the change address
//                if (changeToOrigin){
//                    transaction = changeChangeAddressToOriginAddress(transaction,changeAddressTemp);
//                    transaction = pivxModule.completeTx(transaction);
//                }
//            }else {
//                transaction = new Transaction(params);
//                // then outputs
//                if (outputWrappers != null && !outputWrappers.isEmpty()) {
//                    for (OutputWrapper outputWrapper : outputWrappers) {
//                        transaction.addOutput(
//                                outputWrapper.getAmount(),
//                                Address.fromBase58(params, outputWrapper.getAddress())
//                        );
//                    }
//                } else {
//                    addressStr = edit_address.getText().toString();
//                    if (!pivxModule.chechAddress(addressStr))
//                        throw new IllegalArgumentException("Address not valid");
//                    transaction.addOutput(amount, Address.fromBase58(pivxModule.getConf().getNetworkParams(), addressStr));
//                }
//
//                // then check custom inputs if there is any
//                if (unspent != null && !unspent.isEmpty()) {
//                    for (InputWrapper inputWrapper : unspent) {
//                        transaction.addInput(inputWrapper.getUnspent());
//                    }
//                }
//                // satisfy output with inputs if it's neccesary
//                Coin ouputsSum = transaction.getOutputSum();
//                Coin inputsSum = transaction.getInputSum();
//
//                if (ouputsSum.isGreaterThan(inputsSum)) {
//                    List<TransactionOutput> unspent = pivxModule.getRandomUnspentNotInListToFullCoins(transaction.getInputs(), ouputsSum);
//                    for (TransactionOutput transactionOutput : unspent) {
//                        transaction.addInput(transactionOutput);
//                    }
//                    // update the input amount
//                    inputsSum = transaction.getInputSum();
//                }
//
//                // then fee and change address
                Coin feePerKb = getFee();
                if (sendDialog != null){
                    sendDialog = null;
                }
                sendDialog = SendDialog.newInstance(DAPS_FORMAT.format(amount).toString(), "", DAPS_FORMAT.format(feePerKb).toString(), addressStr, daps);
                sendDialog.show(getSupportFragmentManager(), "send_dialog");
//
//                if (memo.length()>0)
//                    transaction.setMemo(memo);
//
//                Address changeAddressTemp = null;
//                if (changeAddress==null){
//                    changeAddressTemp = changeAddress;
//                }else {
//                    changeAddressTemp = pivxModule.getReceiveAddress();
//                }
//
//                transaction = pivxModule.completeTx(transaction,changeAddressTemp,feePerKb);
//
//                // check if there is a need to change the change address
//                // check if there is a need to change the change address
//                if (changeToOrigin){
//                    transaction = changeChangeAddressToOriginAddress(transaction,changeAddressTemp);
//                    transaction = pivxModule.completeTx(transaction);
//                }
//            }

//            Log.i("APP","tx: "+transaction.toString());

//            TransactionWrapper transactionWrapper = new TransactionWrapper(transaction,null,null,amount, TransactionWrapper.TransactionUse.SENT_SINGLE);
//
//            // Confirmation screen
//            Intent intent = new Intent(this,SendTxDetailActivity.class);
//            Bundle bundle = new Bundle();
//            bundle.putSerializable(TX_WRAPPER,transactionWrapper);
//            bundle.putSerializable(TX,transaction.bitcoinSerialize());
//            if (memo.length()>0)
//                bundle.putString(TX_MEMO,memo);
//            intent.putExtras(bundle);
//            startActivityForResult(intent,SEND_DETAIL);



//        } catch (InsufficientMoneyException e) {
//            e.printStackTrace();
//            throw new IllegalArgumentException("Insuficient balance\nMissing coins "+e.missing.toFriendlyString());
//        } catch (InsufficientInputsException e) {
//            e.printStackTrace();
//            throw new IllegalArgumentException("Insuficient balance\nMissing coins "+e.getMissing().toFriendlyString());
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
        if(transaction==null){
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
        Intent intent = new Intent(SendActivity.this, PivxWalletService.class);
        intent.setAction(ACTION_BROADCAST_TRANSACTION);
        intent.putExtra(DATA_TRANSACTION_HASH,transaction.getHash().getBytes());
        startService(intent);
        Toast.makeText(SendActivity.this,R.string.sending_tx,Toast.LENGTH_LONG).show();
        finish();
        NavigationUtils.goBackToHome(this);
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
            }catch (Exception e){
                Toast.makeText(getActivity(),R.string.error_generic,Toast.LENGTH_SHORT).show();
                dismiss();
                getActivity().onBackPressed();
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
}
