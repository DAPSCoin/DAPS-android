package pivx.org.pivxwallet.ui.initial;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;

import org.pivxj.wallet.Wallet;

import pivx.org.pivxwallet.PivxApplication;
import pivx.org.pivxwallet.ui.base.BaseDrawerActivity;
import pivx.org.pivxwallet.ui.restore_activity.RestoreActivity;
import pivx.org.pivxwallet.ui.splash_activity.SplashActivity;
import pivx.org.pivxwallet.ui.wallet_activity.WalletActivity;
import pivx.org.pivxwallet.utils.AppConf;
import pivx.org.pivxwallet.utils.DapsController;

/**
 * Created by furszy on 8/19/17.
 */

public class InitialActivity extends AppCompatActivity {

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        PivxApplication pivxApplication = PivxApplication.getInstance();
        pivxApplication.startPivxService();

        AppConf appConf = pivxApplication.getAppConf();
        Intent intent;

        //-----Restore wallet intro screen
        SharedPreferences pref = getApplicationContext().getSharedPreferences("MyPref", MODE_PRIVATE);
        boolean restoreWalletDone = pref.getBoolean("RestoreWalletDone", false);

        // show report dialog if something happen with the previous process
        if (!appConf.isAppInit() || appConf.isSplashSoundEnabled()){
            intent = new Intent(this, SplashActivity.class);
            startActivity(intent);
            finish();
        } else {
            if(!restoreWalletDone) {
                intent = new Intent(InitialActivity.this, RestoreActivity.class);
                RestoreActivity.fromIntroScreen = true;
                RestoreActivity.pivxModule = pivxApplication.getModule();
                RestoreActivity.daps = new DapsController();
                RestoreActivity.pivxApplication = pivxApplication;;
                startActivity(intent);
                finish();
                return;
            }

            intent = new Intent(this, BaseDrawerActivity.class);
            startActivity(intent);
            finish();
        }
    }
}
