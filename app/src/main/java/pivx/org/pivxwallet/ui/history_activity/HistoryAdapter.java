package pivx.org.pivxwallet.ui.history_activity;

import android.app.Activity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import org.pivxj.core.Transaction;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

import pivx.org.pivxwallet.R;

public class HistoryAdapter extends BaseAdapter {
    Activity activity;
    ArrayList<Transaction> transactionArr;

    @Override
    public int getCount() {
        return 8;//transactionArr.size();
    }

    @Override
    public Object getItem(int i) {
        return null;
    }

    @Override
    public long getItemId(int i) {
        return 0;
    }

    @Override
    public View getView(int i, View view, ViewGroup viewGroup) {
        LayoutInflater inflater = activity.getLayoutInflater();
        View vi = inflater.inflate(R.layout.item_history, viewGroup, false);
        //configureItem(vi, i);
        return vi;
    }

    private void configureItem(View view, int i) {
        TextView descTv = view.findViewById(R.id.textView3);
        TextView dateTv = view.findViewById(R.id.textView3);
        TextView timeTv = view.findViewById(R.id.textView4);
        TextView dapsTv = view.findViewById(R.id.textView5);

        Transaction transaction = transactionArr.get(i);
        descTv.setText(transaction.getMemo());

        Date updatedTime = transaction.getUpdateTime();
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd/mm/yyyy");
        String dateStr = dateFormat.format(updatedTime);
        dateTv.setText(dateStr);

        dateFormat = new SimpleDateFormat("HH:mm:ss");
        String timeStr = dateFormat.format(updatedTime);
        timeTv.setText(timeStr);

        //dapsTv.setText(transaction.getOutputSum());
    }

    public HistoryAdapter(Activity activity, Set<Transaction> transactions) {
        this.activity = activity;
        transactionArr = new ArrayList<>();

        for (Iterator<Transaction> it = transactions.iterator(); it.hasNext(); ) {
            Transaction transaction = it.next();
            transactionArr.add(transaction);
        }
    }
}
