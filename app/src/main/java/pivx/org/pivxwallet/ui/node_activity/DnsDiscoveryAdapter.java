package pivx.org.pivxwallet.ui.node_activity;

import android.app.Activity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;

import pivx.org.pivxwallet.R;

public class DnsDiscoveryAdapter extends BaseAdapter {
    Activity activity;

    @Override
    public int getCount() {
        return 10;
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
        View vi = inflater.inflate(R.layout.item_dns, viewGroup, false);
        return vi;
    }

    public DnsDiscoveryAdapter(Activity activity) {
        this.activity = activity;
    }
}
