package pivx.org.pivxwallet.ui.wallet_activity;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.support.v4.content.ContextCompat;
import android.support.v4.content.LocalBroadcastManager;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import com.github.clans.fab.FloatingActionMenu;

import org.pivxj.core.Coin;
import org.pivxj.core.NetworkParameters;
import org.pivxj.core.Transaction;
import org.pivxj.uri.BitcoinURIParseException;
import org.pivxj.uri.OptionalFieldValidationException;
import org.pivxj.uri.PivxURI;
import org.pivxj.uri.RequiredFieldValidationException;
import org.pivxj.utils.MonetaryFormat;

import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import chain.BlockchainState;
import pivx.org.pivxwallet.R;
import global.exceptions.NoPeerConnectedException;
import global.PivxRate;
import pivx.org.pivxwallet.ui.base.BaseDrawerActivity;
import pivx.org.pivxwallet.ui.base.dialogs.SimpleTextDialog;
import pivx.org.pivxwallet.ui.base.dialogs.SimpleTwoButtonsDialog;
import pivx.org.pivxwallet.ui.qr_activity.QrActivity;
import pivx.org.pivxwallet.ui.settings_backup_activity.SettingsBackupActivity;
import pivx.org.pivxwallet.ui.transaction_request_activity.RequestActivity;
import pivx.org.pivxwallet.ui.transaction_send_activity.SendActivity;
import pivx.org.pivxwallet.ui.upgrade.UpgradeWalletActivity;
import pivx.org.pivxwallet.utils.AnimationUtils;
import pivx.org.pivxwallet.utils.DapsController;
import pivx.org.pivxwallet.utils.DialogsUtil;
import pivx.org.pivxwallet.utils.scanner.ScanActivity;

import static android.Manifest.permission.CAMERA;
import static pivx.org.pivxwallet.service.IntentsConstants.ACTION_NOTIFICATION;
import static pivx.org.pivxwallet.service.IntentsConstants.INTENT_BROADCAST_DATA_ON_COIN_RECEIVED;
import static pivx.org.pivxwallet.service.IntentsConstants.INTENT_BROADCAST_DATA_TYPE;
import static pivx.org.pivxwallet.ui.transaction_send_activity.SendActivity.INTENT_ADDRESS;
import static pivx.org.pivxwallet.ui.transaction_send_activity.SendActivity.INTENT_EXTRA_TOTAL_AMOUNT;
import static pivx.org.pivxwallet.ui.transaction_send_activity.SendActivity.INTENT_MEMO;
import static pivx.org.pivxwallet.utils.scanner.ScanActivity.INTENT_EXTRA_RESULT;

/**
 * Created by Neoperol on 5/11/17.
 */

public class WalletActivity extends BaseDrawerActivity {

    private static final int SCANNER_RESULT = 122;

    private View root;
    private View container_txs;
    private View syncing_txs;
    private final MonetaryFormat DAPS_FORMAT = MonetaryFormat.BTC.minDecimals(8).optionalDecimals(0).noCode();

    private TextView txt_value, txt_height, txt_syncing_value, txt_syncing_height, txt_pending_value;
//    private TextView txt_unnavailable;
//    private View view_background;
//    private View container_syncing;
    private PivxRate pivxRate;
//    private TransactionsFragmentBase txsFragment;

    // Receiver
    private LocalBroadcastManager localBroadcastManager;

    private IntentFilter pivxServiceFilter = new IntentFilter(ACTION_NOTIFICATION);
    private BroadcastReceiver pivxServiceReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action.equals(ACTION_NOTIFICATION)){
                if(intent.getStringExtra(INTENT_BROADCAST_DATA_TYPE).equals(INTENT_BROADCAST_DATA_ON_COIN_RECEIVED)){
                    // Check if the app is on foreground to update the view.
                    if (!isOnForeground)return;
                    updateBalance();
//                    txsFragment.refresh();
                }
            }

        }
    };

    private final int interval = 3000; // 3 Second
    private Handler handler = new Handler();
    private Runnable runnable = new Runnable(){
        public void run() {
            container_txs.setVisibility(View.VISIBLE);
            syncing_txs.setVisibility(View.GONE);
        }
    };

    private void updateWallet() {
        container_txs.setVisibility(View.GONE);
        syncing_txs.setVisibility(View.VISIBLE);

        updateBalance();

        handler.postDelayed(runnable, interval);
    }

    @Override
    protected void beforeCreate(){
        /*
        if (!appConf.isAppInit()){
            Intent intent = new Intent(this, SplashActivity.class);
            startActivity(intent);
            finish();
        }
        // show report dialog if something happen with the previous process
        */
        localBroadcastManager = LocalBroadcastManager.getInstance(this);
    }

    @Override
    protected void onCreateView(Bundle savedInstanceState, ViewGroup container) {
        setTitle("DAPS COIN");
        root = getLayoutInflater().inflate(R.layout.fragment_wallet, container);
//        View containerHeader = getLayoutInflater().inflate(R.layout.fragment_pivx_amount,header_container);
        header_container.setVisibility(View.VISIBLE);
        txt_value = (TextView) root.findViewById(R.id.pivValue);
        txt_height = (TextView) root.findViewById(R.id.txt_block_height);
        txt_syncing_height = (TextView) root.findViewById(R.id.txt_blocks_syncing);
        txt_syncing_value = (TextView) root.findViewById(R.id.pivValue_syncing);
        txt_pending_value = (TextView) root.findViewById(R.id.txt_pending_balance_syncing);
        container_txs = root.findViewById(R.id.container_txs);
        syncing_txs = root.findViewById(R.id.syncing_txs);
//        view_background = root.findViewById(R.id.view_background);
//        container_syncing = root.findViewById(R.id.container_syncing);
        // Open Send
        root.findViewById(R.id.btnSyncStart).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                updateWallet();
            }
        });

//        root.findViewById(R.id.fab_request).setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                startActivity(new Intent(v.getContext(), RequestActivity.class));
//            }
//        });

//        FloatingActionMenu floatingActionMenu = (FloatingActionMenu) root.findViewById(R.id.fab_menu);
//        floatingActionMenu.setOnMenuToggleListener(new FloatingActionMenu.OnMenuToggleListener() {
//            @Override
//            public void onMenuToggle(boolean opened) {
//                if (opened){
//                    AnimationUtils.fadeInView(view_background,200);
//                }else {
//                    AnimationUtils.fadeOutGoneView(view_background,200);
//                }
//            }
//        });

//        txsFragment = (TransactionsFragmentBase) getSupportFragmentManager().findFragmentById(R.id.transactions_fragment);
        updateWallet();

    }

    @Override
    protected void onResume() {
        super.onResume();
        // to check current activity in the navigation drawer
        setNavigationMenuItemChecked(0);

//        init();

        // register
        localBroadcastManager.registerReceiver(pivxServiceReceiver,pivxServiceFilter);

        updateState();
        updateBalance();

        // check if this wallet need an update:
        try {
            if(pivxModule.isBip32Wallet() && pivxModule.isSyncWithNode()){
                if (!pivxModule.isWalletWatchOnly() && pivxModule.getAvailableBalanceCoin().isGreaterThan(Transaction.DEFAULT_TX_FEE)) {
                    Intent intent = UpgradeWalletActivity.createStartIntent(
                            this,
                            getString(R.string.upgrade_wallet),
                            "An old wallet version with bip32 key was detected, in order to upgrade the wallet your coins are going to be sweeped" +
                                    " to a new wallet with bip44 account.\n\nThis means that your current mnemonic code and" +
                                    " backup file are not going to be valid anymore, please write the mnemonic code in paper " +
                                    "or export the backup file again to be able to backup your coins." +
                                    "\n\nPlease wait and not close this screen. The upgrade + blockchain sychronization could take a while."
                                    +"\n\nTip: If this screen is closed for user's mistake before the upgrade is finished you can find two backups files in the 'Download' folder" +
                                    " with prefix 'old' and 'upgrade' to be able to continue the restore manually."
                                    + "\n\nThanks!",
                            "sweepBip32"
                    );
                    startActivity(intent);
                }
            }
        } catch (NoPeerConnectedException e) {
            e.printStackTrace();
        }
    }

    private void updateState() {
//        txt_watch_only.setVisibility(pivxModule.isWalletWatchOnly()?View.VISIBLE:View.GONE);
    }

    private void init() {
        // Start service if it's not started.
        pivxApplication.startPivxService();

        if (!pivxApplication.getAppConf().hasBackup()){
            long now = System.currentTimeMillis();
            if (pivxApplication.getLastTimeRequestedBackup()+1800000L<now) {
                pivxApplication.setLastTimeBackupRequested(now);
                SimpleTwoButtonsDialog reminderDialog = DialogsUtil.buildSimpleTwoBtnsDialog(
                        this,
                        getString(R.string.reminder_backup),
                        getString(R.string.reminder_backup_body),
                        new SimpleTwoButtonsDialog.SimpleTwoBtnsDialogListener() {
                            @Override
                            public void onRightBtnClicked(SimpleTwoButtonsDialog dialog) {
                                startActivity(new Intent(WalletActivity.this, SettingsBackupActivity.class));
                                dialog.dismiss();
                            }

                            @Override
                            public void onLeftBtnClicked(SimpleTwoButtonsDialog dialog) {
                                dialog.dismiss();
                            }
                        }
                );
                reminderDialog.setLeftBtnText(getString(R.string.button_dismiss));
                reminderDialog.setLeftBtnTextColor(Color.BLACK);
                reminderDialog.setRightBtnText(getString(R.string.button_ok));
                reminderDialog.show();
            }
        }
    }

    @Override
    protected void onStop() {
        super.onStop();
        // unregister
        //localBroadcastManager.unregisterReceiver(localReceiver);
        localBroadcastManager.unregisterReceiver(pivxServiceReceiver);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
//        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId()==R.id.action_qr){
            startActivity(new Intent(this, QrActivity.class));
            return true;
        }else if (item.getItemId()==R.id.action_scan){
            if (!checkPermission(CAMERA)) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    int permsRequestCode = 200;
                    String[] perms = {"android.permission.CAMERA"};
                    requestPermissions(perms, permsRequestCode);
                }
            }
            startActivityForResult(new Intent(this, ScanActivity.class),SCANNER_RESULT);
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    //Create a list of Data objects
    public List<TransactionData> fill_with_data() {

        List<TransactionData> data = new ArrayList<>();

        data.add(new TransactionData("Sent Pivx", "18:23", R.mipmap.ic_transaction_receive,"56.32", "701 USD" ));
        data.add(new TransactionData("Sent Pivx", "1 days ago", R.mipmap.ic_transaction_send,"56.32", "701 USD"));
        data.add(new TransactionData("Sent Pivx", "2 days ago", R.mipmap.ic_transaction_receive,"56.32", "701 USD"));
        data.add(new TransactionData("Sent Pivx", "2 days ago", R.mipmap.ic_transaction_receive,"56.32", "701 USD"));
        data.add(new TransactionData("Sent Pivx", "3 days ago", R.mipmap.ic_transaction_send,"56.32", "701 USD"));
        data.add(new TransactionData("Sent Pivx", "3 days ago", R.mipmap.ic_transaction_receive,"56.32", "701 USD"));

        data.add(new TransactionData("Sent Pivx", "4 days ago", R.mipmap.ic_transaction_receive,"56.32", "701 USD"));
        data.add(new TransactionData("Sent Pivx", "4 days ago", R.mipmap.ic_transaction_receive,"56.32", "701 USD"));
        data.add(new TransactionData("Sent Pivx", "one week ago", R.mipmap.ic_transaction_send,"56.32", "701 USD"));
        data.add(new TransactionData("Sent Pivx", "one week ago", R.mipmap.ic_transaction_receive,"56.32", "701 USD"));
        data.add(new TransactionData("Sent Pivx", "one week ago", R.mipmap.ic_transaction_receive,"56.32", "701 USD"));
        data.add(new TransactionData("Sent Pivx", "one week ago", R.mipmap.ic_transaction_receive,"56.32", "701 USD" ));

        return data;
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == SCANNER_RESULT){
            if (resultCode==RESULT_OK) {
                try {
                    String address = data.getStringExtra(INTENT_EXTRA_RESULT);
//                    String address = "pivx:41imzPFKNhAe2SEg74ubXVMhu45SsQz3vgNhgnxs5MBb4pzZ7cVrJ7yBRVVQyD2W17PwELVvBmkvfhnxpTpKeDGs17mqkCsK5sj?amount=10&label=Payment%20Request&message=aaaa";
                    String usedAddress;
//                    if (pivxModule.chechAddress(address)){
//                        usedAddress = address;
//                    }else {
//                        PivxURI pivxUri = new PivxURI(address);
//                        usedAddress = pivxUri.getAddress().toBase58();
//                        final Coin amount = pivxUri.getAmount();
//                        if (amount != null){
//                            final String memo = pivxUri.getMessage();
//                            StringBuilder text = new StringBuilder();
//                            text.append(getString(R.string.amount)).append(": ").append(amount.toFriendlyString());
//                            if (memo != null){
//                                text.append("\n").append(getString(R.string.description)).append(": ").append(memo);
//                            }
//
//                            SimpleTextDialog dialogFragment = DialogsUtil.buildSimpleTextDialog(this,
//                                    getString(R.string.payment_request_received),
//                                    text.toString())
//                                .setOkBtnClickListener(new View.OnClickListener() {
//                                    @Override
//                                    public void onClick(View v) {
//                                        Intent intent = new Intent(v.getContext(), SendActivity.class);
//                                        intent.putExtra(INTENT_ADDRESS,usedAddress);
//                                        intent.putExtra(INTENT_EXTRA_TOTAL_AMOUNT,amount);
//                                        intent.putExtra(INTENT_MEMO,memo);
//                                        startActivity(intent);
//                                    }
//                                });
//                            dialogFragment.setImgAlertRes(R.drawable.ic_send_action);
//                            dialogFragment.setAlignBody(SimpleTextDialog.Align.LEFT);
//                            dialogFragment.setImgAlertRes(R.drawable.ic_fab_recieve);
//                            dialogFragment.show(getFragmentManager(),"payment_request_dialog");
//                            return;
//                        }
//
//                    }
                    NetworkParameters params = pivxModule.getConf().getNetworkParams();
                    String scheme = params.getUriScheme();
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

                        if (amount != null){
                            StringBuilder text = new StringBuilder();
                            text.append(getString(R.string.amount)).append(": ").append(amount.toFriendlyString());
                            if (memo != null){
                                text.append("\n").append(getString(R.string.description)).append(": ").append(memo);
                            }

                            final String finalUsedAddress = usedAddress;
                            final Coin finalAmount = amount;
                            final String finalMemo = memo;
                            SimpleTextDialog dialogFragment = DialogsUtil.buildSimpleTextDialog(this,
                                    getString(R.string.payment_request_received),
                                    text.toString())
                                    .setOkBtnClickListener(new View.OnClickListener() {
                                        @Override
                                        public void onClick(View v) {
                                            Intent intent = new Intent(v.getContext(), SendActivity.class);
                                            intent.putExtra(INTENT_ADDRESS, finalUsedAddress);
                                            intent.putExtra(INTENT_EXTRA_TOTAL_AMOUNT, finalAmount);
                                            intent.putExtra(INTENT_MEMO, finalMemo);
                                            startActivity(intent);
                                        }
                                    });
                            dialogFragment.setImgAlertRes(R.drawable.ic_send_action);
                            dialogFragment.setAlignBody(SimpleTextDialog.Align.LEFT);
                            dialogFragment.setImgAlertRes(R.drawable.ic_fab_recieve);
                            dialogFragment.show(getFragmentManager(),"payment_request_dialog");
                            return;
                        }

                    }
                    DialogsUtil.showCreateAddressLabelDialog(this,usedAddress);
                }catch (Exception e){
                    e.printStackTrace();
                    Toast.makeText(this,"Bad address",Toast.LENGTH_LONG).show();
                }
            }
        }
        super.onActivityResult(requestCode, resultCode, data);
    }



    private boolean checkPermission(String permission) {
        int result = ContextCompat.checkSelfPermission(getApplicationContext(),permission);

        return result == PackageManager.PERMISSION_GRANTED;
    }


    private void updateBalance() {
//        Coin availableBalance = pivxModule.getAvailableBalanceCoin();
//        txt_value.setText(!availableBalance.isZero()?availableBalance.toFriendlyString():"0 Pivs");
//        Coin unnavailableBalance = pivxModule.getUnnavailableBalanceCoin();
//        txt_unnavailable.setText(!unnavailableBalance.isZero()?unnavailableBalance.toFriendlyString():"0 Pivs");
//        if (pivxRate == null)
//            pivxRate = pivxModule.getRate(pivxApplication.getAppConf().getSelectedRateCoin());
//        if (pivxRate!=null) {
//            txt_local_currency.setText(
//                    pivxApplication.getCentralFormats().format(
//                            new BigDecimal(availableBalance.getValue() * pivxRate.getRate().doubleValue()).movePointLeft(8)
//                    )
//                    + " "+pivxRate.getCode()
//            );
//        }else {
//            txt_local_currency.setText("0");
//        }

        String availableBalance = (String) daps.callRPC("getBalance");
        if (availableBalance == null)
            availableBalance = "0";
        Coin availableBalanceCoin = Coin.valueOf(new BigDecimal(availableBalance).longValue());
        if (availableBalanceCoin.isZero())
            txt_value.setText("0.00000000 DAPS");
        else
            txt_value.setText(DAPS_FORMAT.format(availableBalanceCoin).toString() + " DAPS");
        txt_syncing_value.setText(txt_value.getText());

        Map result = (Map) daps.callRPC("getPendingBalance");
        String pendingBalance = String.valueOf(result.get("pending"));
        if (pendingBalance == null)
            pendingBalance = "0";
        Coin pendingBalanceCoin = Coin.valueOf(new BigDecimal(pendingBalance).longValue());
        if (pendingBalanceCoin.isZero())
            txt_pending_value.setText("0.00000000 DAPS");
        else
            txt_pending_value.setText(DAPS_FORMAT.format(pendingBalanceCoin).toString() + " DAPS");

        String blockHeight = (String) daps.callRPC("getBlockCount");
        if (blockHeight == null)
            blockHeight = "0";
        txt_height.setText(blockHeight);
        txt_syncing_height.setText(blockHeight + " / " + blockHeight);

//        txt_unnavailable.setText("0 Daps");
        if (pivxRate == null)
            pivxRate = pivxModule.getRate(pivxApplication.getAppConf().getSelectedRateCoin());
//        if (pivxRate!=null) {
//            txt_local_currency.setText(
//                    pivxApplication.getCentralFormats().format(
//                            new BigDecimal(Double.parseDouble(availableBalance) * pivxRate.getRate().doubleValue()).movePointLeft(8)
//                    )
//                            + " "+pivxRate.getCode()
//            );
//        }else {
//            txt_local_currency.setText("0");
//        }
    }

    @Override
    protected void onBlockchainStateChange(){
//        if (blockchainState == BlockchainState.SYNCING){
//            AnimationUtils.fadeInView(container_syncing,500);
//        }else if (blockchainState == BlockchainState.SYNC){
//            AnimationUtils.fadeOutGoneView(container_syncing,500);
//        }else if (blockchainState == BlockchainState.NOT_CONNECTION){
//            AnimationUtils.fadeInView(container_syncing,500);
//        }
    }
}
