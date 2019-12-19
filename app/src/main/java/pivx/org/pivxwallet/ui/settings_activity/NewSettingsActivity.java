package pivx.org.pivxwallet.ui.settings_activity;

import android.app.Fragment;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.constraint.ConstraintLayout;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.flexbox.FlexboxLayout;

import java.util.List;

import global.PivxModule;
import pivx.org.pivxwallet.PivxApplication;
import pivx.org.pivxwallet.R;
import pivx.org.pivxwallet.ui.backup_mnemonic_activity.MnemonicActivity;
import pivx.org.pivxwallet.ui.base.BaseDrawerActivity;
import pivx.org.pivxwallet.ui.base.PivxActivity;
import pivx.org.pivxwallet.ui.restore_activity.RestoreActivity;
import pivx.org.pivxwallet.ui.settings_backup_activity.SettingsBackupActivity;
import pivx.org.pivxwallet.ui.settings_restore_activity.SettingsRestoreActivity;
import pivx.org.pivxwallet.utils.DapsController;

public class NewSettingsActivity extends Fragment {
    PivxApplication pivxApplication;
    PivxModule pivxModule;
    DapsController daps;

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setHasOptionsMenu(true);
    }

    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, Bundle savedInstanceState) {
        pivxApplication = PivxActivity.pivxApplication;
        pivxModule = PivxActivity.pivxModule;
        daps = PivxActivity.daps;

        View root = inflater.inflate(R.layout.fragment_new_settings, container, false);
        setupView(root);
        return root;
    }

    private void setupView(View root) {
        Button submitBt = (Button) root.findViewById(R.id.submit_bt);
        submitBt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

            }
        });

        Button showPhraseBt = (Button) root.findViewById(R.id.show_phrase_bt);
        showPhraseBt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(getActivity(), PhraseActivity.class);
                PhraseActivity.pivxModule = pivxModule;
                PhraseActivity.daps = daps;
                startActivity(intent);
            }
        });
    }

    @Override
    public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
        menu.add(0,0,0, R.string.backup_wallet);
        menu.add(1,1,1, R.string.restore_wallet);
        super.onCreateOptionsMenu(menu, inflater);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        Intent intent;
        switch (item.getItemId()) {
            case 0:
                intent = new Intent(getActivity(), SettingsBackupActivity.class);
                SettingsBackupActivity.pivxModule = pivxModule;
                SettingsBackupActivity.daps = daps;
                SettingsBackupActivity.pivxApplication = pivxApplication;
                startActivity(intent);
                return true;
            case 1:
                intent = new Intent(getActivity(), RestoreActivity.class);
                RestoreActivity.pivxModule = pivxModule;
                RestoreActivity.daps = daps;
                RestoreActivity.pivxApplication = pivxApplication;
                RestoreActivity.fromIntroScreen = false;
                startActivity(intent);
                return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
