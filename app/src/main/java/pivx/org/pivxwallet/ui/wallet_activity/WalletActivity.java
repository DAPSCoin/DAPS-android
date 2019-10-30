package pivx.org.pivxwallet.ui.wallet_activity;

import android.app.Fragment;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.os.Handler;
import android.support.annotation.Nullable;
import android.support.v4.content.ContextCompat;
import android.support.v4.content.LocalBroadcastManager;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;


import org.pivxj.core.Coin;
import org.pivxj.core.NetworkParameters;
import org.pivxj.core.Transaction;
import org.pivxj.utils.MonetaryFormat;
import java.util.TimerTask;
import java.util.Timer;
import global.PivxModule;
import pivx.org.pivxwallet.PivxApplication;
import pivx.org.pivxwallet.R;
import global.exceptions.NoPeerConnectedException;
import global.PivxRate;
import pivx.org.pivxwallet.ui.base.PivxActivity;
import pivx.org.pivxwallet.ui.upgrade.UpgradeWalletActivity;
import pivx.org.pivxwallet.utils.DapsController;
import static pivx.org.pivxwallet.service.IntentsConstants.ACTION_NOTIFICATION;
import static pivx.org.pivxwallet.service.IntentsConstants.INTENT_BROADCAST_DATA_ON_COIN_RECEIVED;
import static pivx.org.pivxwallet.service.IntentsConstants.INTENT_BROADCAST_DATA_TYPE;

/**
 * Created by Neoperol on 5/11/17.
 */

public class WalletActivity extends Fragment {
    PivxApplication pivxApplication;
    PivxModule pivxModule;
    DapsController daps;
    Timer t;
    String blockHeight;

    View root;
    private View container_txs;
    private View syncing_txs;
    private final MonetaryFormat DAPS_FORMAT = MonetaryFormat.BTC.minDecimals(8).optionalDecimals(0).noCode();
    private TextView txt_value, txt_height, txt_syncing_value, txt_syncing_height, txt_pending_value;
    private PivxRate pivxRate;

    // Receiver
    private LocalBroadcastManager localBroadcastManager;

    private IntentFilter pivxServiceFilter = new IntentFilter(ACTION_NOTIFICATION);
    private BroadcastReceiver pivxServiceReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action.equals(ACTION_NOTIFICATION)){
                if(intent.getStringExtra(INTENT_BROADCAST_DATA_TYPE).equals(INTENT_BROADCAST_DATA_ON_COIN_RECEIVED)){
                    if (!PivxActivity.isOnForeground) {
                        return;
                    }

                    updateBalance();
                }
            }
        }
    };

    private final int interval = 3000; // 3 Second
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
        new Handler().postDelayed(runnable, interval);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, Bundle savedInstanceState) {
        localBroadcastManager = LocalBroadcastManager.getInstance(getActivity());
        pivxApplication = PivxActivity.pivxApplication;
        pivxModule = PivxActivity.pivxModule;
        daps = PivxActivity.daps;

        root = inflater.inflate(R.layout.fragment_wallet, container, false);
        setupView();

        updateWallet();
        startUpdateBalanceTimer();

        return root;
    }

    private void setupView() {
        txt_value = (TextView) root.findViewById(R.id.pivValue);
        txt_height = (TextView) root.findViewById(R.id.txt_block_height);
        txt_syncing_height = (TextView) root.findViewById(R.id.txt_blocks_syncing);
        txt_syncing_value = (TextView) root.findViewById(R.id.pivValue_syncing);
        txt_pending_value = (TextView) root.findViewById(R.id.txt_pending_balance_syncing);
        container_txs = root.findViewById(R.id.container_txs);
        syncing_txs = root.findViewById(R.id.syncing_txs);

        root.findViewById(R.id.btnSyncStart).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                updateWallet();

                /*String blockHeight = (String) daps.callRPC("getBlockCount");
                if (blockHeight == null)
                    blockHeight = "0";
                txt_height.setText(blockHeight);
                txt_syncing_height.setText(blockHeight + " / " + blockHeight);
                int lastBlock = PivxApplication.getInstance().getModule().getWallet().getLastBlockSeenHeight();
                if (lastBlock == -1) {
                    lastBlock = Integer.parseInt(blockHeight) - 310;
                }

                syncTransactions(lastBlock + 1, Integer.parseInt(blockHeight));*/
            }
        });
    }

    private void startUpdateBalanceTimer() {
        t = new Timer();
        TimerTask timer = new TimerTask() {
            @Override
            public void run() {
                updateBalance();
            }
        };
        t.scheduleAtFixedRate(timer , 0 , 40000);
    }

    void killTimer() {
        if(t != null) {
            t.cancel();
            t = null;
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        localBroadcastManager.registerReceiver(pivxServiceReceiver,pivxServiceFilter);

        updateBalance();
        // check if this wallet need an update:
        try {
            if(pivxModule.isBip32Wallet() && pivxModule.isSyncWithNode()){
                if (!pivxModule.isWalletWatchOnly() && pivxModule.getAvailableBalanceCoin().isGreaterThan(Transaction.DEFAULT_TX_FEE)) {
                    Intent intent = UpgradeWalletActivity.createStartIntent(
                            getActivity(),
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

    @Override
    public void onStop() {
        super.onStop();
        localBroadcastManager.unregisterReceiver(pivxServiceReceiver);
        killTimer();
    }

    private void syncTransactions(int lastBlock, int currentBlock) {
        final int _lastBlock = lastBlock;
        final int _currentBlock = currentBlock;
        daps.callRPC("getrawtransactionbyblockheight", "" + _lastBlock, "" + _currentBlock);
    }

    private void updateBalance() {
        Coin availableBalance = PivxApplication.getInstance().getModule().getWallet().getBalance();
        if (availableBalance == null)
            availableBalance = Coin.ZERO;
        if (availableBalance.isZero()) {
            txt_value.setText("0.00000000 DAPS");
        }
        else {
            txt_value.setText(DAPS_FORMAT.format(availableBalance).toString() + " DAPS");
        }
        txt_syncing_value.setText(txt_value.getText());

        new Thread() {
            @Override
            public void run() {
                blockHeight = (String) daps.callRPC("getBlockCount");
                if (blockHeight == null) {
                    blockHeight = "0";
                }

                if(getActivity()!= null) {
                    getActivity().runOnUiThread(new Runnable() {
                        public void run() {
                            txt_height.setText(blockHeight);
                            txt_syncing_height.setText(blockHeight + " / " + blockHeight);
                        }
                    });
                }
            }
        }.start();

        if (pivxRate == null) {
            pivxRate = pivxModule.getRate(pivxApplication.getAppConf().getSelectedRateCoin());
        }
    }
}
