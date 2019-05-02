package pivx.org.pivxwallet.ui.transaction_send_activity;

import android.os.Bundle;
import android.support.annotation.Nullable;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.widget.EditText;
import android.widget.ExpandableListView;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.ViewFlipper;

import org.pivxj.core.Coin;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import pivx.org.pivxwallet.R;
import global.PivxRate;
import pivx.org.pivxwallet.ui.base.BaseFragment;
import pivx.org.pivxwallet.utils.AddressAdapter;
import pivx.org.pivxwallet.utils.AmountAdapter;
import pivx.org.pivxwallet.utils.DapsController;

/**
 * Created by furszy on 2/9/18.
 */

public class AmountInputFragment extends BaseFragment{

    private View root;

    private ExpandableListView edit_amount, edit_address;
    private AmountAdapter amountAdapter;
    private AddressAdapter addressAdapter;
    private DapsController daps;

    @Nullable
    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        root = inflater.inflate(R.layout.amount_input, container, false);
        edit_amount = (ExpandableListView) root.findViewById(R.id.edit_amount);
        edit_address = (ExpandableListView) root.findViewById(R.id.edit_address);
        daps = new DapsController();

        return root;
    }
}
