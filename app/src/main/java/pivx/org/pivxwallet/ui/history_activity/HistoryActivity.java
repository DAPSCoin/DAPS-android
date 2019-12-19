package pivx.org.pivxwallet.ui.history_activity;

import android.app.Dialog;
import android.app.Fragment;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ExpandableListView;
import android.widget.ListView;
import android.widget.Spinner;
import android.widget.TextView;

import org.pivxj.core.Transaction;

import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import global.PivxModule;
import pivx.org.pivxwallet.PivxApplication;
import pivx.org.pivxwallet.R;
import pivx.org.pivxwallet.ui.base.BaseDrawerActivity;
import pivx.org.pivxwallet.ui.base.PivxActivity;
import pivx.org.pivxwallet.ui.node_activity.NodeActivity;
import pivx.org.pivxwallet.utils.DapsController;
import pivx.org.pivxwallet.utils.NodeAdapter;
import pivx.org.pivxwallet.utils.NodeInfo;

public class HistoryActivity extends Fragment {
    PivxApplication pivxApplication;
    PivxModule pivxModule;
    DapsController daps;

    Dialog searchDialog;
    Spinner typeSpinner;

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setHasOptionsMenu(true);
    }

    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, Bundle savedInstanceState) {
        pivxApplication = PivxActivity.pivxApplication;
        pivxModule = PivxActivity.pivxModule;
        daps = PivxActivity.daps;

        View root = inflater.inflate(R.layout.fragment_history, container, false);
        setupView(root);
        return root;
    }

    private void setupView(View root) {
        ListView historyLv = (ListView) root.findViewById(R.id.history_lv);
        Set<Transaction> transactions = pivxModule.getWallet().getTransactions(true);
        historyLv.setAdapter(new HistoryAdapter(getActivity(), transactions));

        historyLv.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                Intent intent = new Intent(getActivity(), TransactionActivity.class);
                startActivity(intent);
            }
        });
    }

    @Override
    public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
        inflater.inflate(R.menu.menu_search, menu);
        super.onCreateOptionsMenu(menu, inflater);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if(item.getItemId() == R.id.action_search) {
            showSearchDialog();
        }

        return super.onOptionsItemSelected(item);
    }

    private void showSearchDialog() {
        searchDialog = new Dialog(getActivity());
        searchDialog.requestWindowFeature(getActivity().getWindow().FEATURE_NO_TITLE);
        searchDialog.getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        searchDialog.setContentView(R.layout.dialog_search);
        searchDialog.getWindow().setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.MATCH_PARENT);
        searchDialog.getWindow().setGravity(Gravity.CENTER);
        searchDialog.show();


        Button cancelBt = searchDialog.findViewById(R.id.button2);
        cancelBt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                searchDialog.dismiss();
            }
        });


        final String []types = new String[2];
        types[0] = "Sent";
        types[1] = "Received";

        typeSpinner = (Spinner) searchDialog.findViewById(R.id.type_node);
        final ArrayAdapter<String> typeSpinnerAdapter = new ArrayAdapter<String>(getActivity(), R.layout.item_spinner, types);
        typeSpinner.setAdapter(typeSpinnerAdapter);
        typeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                ((TextView) parent.getChildAt(0)).setTextColor(Color.WHITE);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {

            }
        });
    }

    public int convertDpToPx(int dp) {
        return (int)(dp * this.getResources().getDisplayMetrics().density);
    }
}
