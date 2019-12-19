package pivx.org.pivxwallet.ui.splash_activity;

import android.content.Intent;
import android.content.SharedPreferences;
import android.media.MediaPlayer;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.support.v7.app.AppCompatActivity;
import android.widget.ImageView;
import android.widget.VideoView;

import pivx.org.pivxwallet.PivxApplication;
import pivx.org.pivxwallet.R;
import pivx.org.pivxwallet.ui.base.BaseDrawerActivity;
import pivx.org.pivxwallet.ui.base.PivxActivity;
import pivx.org.pivxwallet.ui.restore_activity.RestoreActivity;
import pivx.org.pivxwallet.ui.start_activity.StartActivity;
import pivx.org.pivxwallet.ui.wallet_activity.WalletActivity;
import pivx.org.pivxwallet.utils.DapsController;

/**
 * Created by Neoperol on 6/13/17.
 */

public class SplashActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_splash);

        Handler mhandler = new Handler();
        mhandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                jump();
            }
        }, 3000);
    }


    private void jump() {
        SharedPreferences pref = getApplicationContext().getSharedPreferences("MyPref", MODE_PRIVATE);
        boolean restoreWalletDone = pref.getBoolean("RestoreWalletDone", false);

        if(!restoreWalletDone) {
            Intent intent = new Intent(SplashActivity.this, RestoreActivity.class);
            RestoreActivity.fromIntroScreen = true;
            RestoreActivity.pivxModule = PivxApplication.getInstance().getModule();
            RestoreActivity.daps = new DapsController();
            RestoreActivity.pivxApplication = PivxApplication.getInstance();;
            startActivity(intent);
            return;
        }

        Intent intent = new Intent(this, BaseDrawerActivity.class);
        startActivity(intent);
        finish();
    }
}
