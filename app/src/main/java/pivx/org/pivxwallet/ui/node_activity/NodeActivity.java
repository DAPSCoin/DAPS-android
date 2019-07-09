package pivx.org.pivxwallet.ui.node_activity;

import android.content.Intent;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.ExpandableListView;
import android.widget.Toast;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.util.ArrayList;
import java.util.List;

import pivx.org.pivxwallet.R;
import pivx.org.pivxwallet.ui.base.BaseDrawerActivity;
import pivx.org.pivxwallet.utils.AppConf;
import pivx.org.pivxwallet.utils.FeeAdapter;
import pivx.org.pivxwallet.utils.NavigationUtils;
import pivx.org.pivxwallet.utils.NodeAdapter;
import pivx.org.pivxwallet.utils.NodeInfo;

/**
 * Created by Neoperol on 5/4/17.
 */

public class NodeActivity extends BaseDrawerActivity implements View.OnClickListener {

    private Logger logger = LoggerFactory.getLogger(NodeActivity.class);

    private View root;
    private ExpandableListView edit_node;
    private EditText edit_name, edit_host, edit_port, edit_user, edit_password;
    private NodeAdapter nodeAdapter;

    @Override
    protected void onCreateView(Bundle savedInstanceState,ViewGroup container) {
        root = getLayoutInflater().inflate(R.layout.fragment_node_settings, container);
        setTitle("Node Select");

        edit_node = (ExpandableListView) findViewById(R.id.edit_node);
        edit_name = (EditText) findViewById(R.id.edit_name);
        edit_host = (EditText) findViewById(R.id.edit_host);
        edit_port = (EditText) findViewById(R.id.edit_port);
        edit_user = (EditText) findViewById(R.id.edit_user);
        edit_password = (EditText) findViewById(R.id.edit_password);

        root.findViewById(R.id.btnNodeUpdate).setOnClickListener(this);

        AppConf appConf = pivxApplication.getAppConf();
        NodeActivity.this.edit_name.setText(appConf.getCurNodeInfo().name);
        NodeActivity.this.edit_host.setText(appConf.getCurNodeInfo().host);
        NodeActivity.this.edit_port.setText(String.valueOf(appConf.getCurNodeInfo().port));
        NodeActivity.this.edit_user.setText(appConf.getCurNodeInfo().user);
        NodeActivity.this.edit_password.setText(appConf.getCurNodeInfo().password);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
//        getMenuInflater().inflate(R.menu.send_menu,menu);
        return super.onCreateOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {

        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
    }

    @Override
    protected void onRestoreInstanceState(Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        NavigationUtils.goBackToHome(this);
    }

    @Override
    protected void onResume() {
        super.onResume();
        setNavigationMenuItemChecked(3);

        if(getCurrentFocus()!=null) {
            InputMethodManager inputMethodManager = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
            inputMethodManager.hideSoftInputFromWindow(getCurrentFocus().getWindowToken(), 0);
        }

        if (nodeAdapter==null) {
            final AppConf appConf = pivxApplication.getAppConf();
            List<String> list = new ArrayList<String>();
            List<NodeInfo> nodeList = appConf.getNodeList();
            for (int i = 0; i < nodeList.size(); i++) {
                list.add(nodeList.get(i).name);
            }

            nodeAdapter= new NodeAdapter(this, list, appConf.getCurNodeInfo().name);
            edit_node.setAdapter(nodeAdapter);

            edit_node.setOnGroupExpandListener(new ExpandableListView.OnGroupExpandListener() {

                @Override
                public void onGroupExpand(int groupPosition) {
                    edit_node.getLayoutParams().height = convertDpToPx(90);
                }
            });

            edit_node.setOnGroupCollapseListener(new ExpandableListView.OnGroupCollapseListener() {

                @Override
                public void onGroupCollapse(int groupPosition) {
                    edit_node.getLayoutParams().height = convertDpToPx(30);
                }
            });

            edit_node.setOnChildClickListener(new ExpandableListView.OnChildClickListener() {
                @Override
                public boolean onChildClick(ExpandableListView parent, View v,
                                            int groupPosition, int childPosition, long id) {
                    NodeAdapter adapter = (NodeAdapter)parent.getExpandableListAdapter();
                    adapter.setText((String)adapter.getChild(groupPosition, childPosition));
                    appConf.setCurNodeIndex(childPosition);

                    List<NodeInfo> list = appConf.getNodeList();
                    NodeActivity.this.edit_name.setText(list.get(childPosition).name);
                    NodeActivity.this.edit_host.setText(list.get(childPosition).host);
                    NodeActivity.this.edit_port.setText(String.valueOf(list.get(childPosition).port));
                    NodeActivity.this.edit_user.setText(list.get(childPosition).user);
                    NodeActivity.this.edit_password.setText(list.get(childPosition).password);

                    parent.collapseGroup(0);
                    return false;
                }
            });
        }
    }

    @Override
    public void onClick(View v) {
        int id = v.getId();
        if (id == R.id.btnNodeUpdate){
            AppConf appConf = pivxApplication.getAppConf();

            String name = this.edit_name.getText().toString();
            String host = this.edit_host.getText().toString();
            int port = Integer.valueOf(this.edit_port.getText().toString());
            String user = this.edit_user.getText().toString();
            String password = this.edit_password.getText().toString();

            appConf.updateCurNode(new NodeInfo(name, host, port, user, password));

            List<String> list = new ArrayList<String>();
            List<NodeInfo> nodeList = appConf.getNodeList();
            for (int i = 0; i < nodeList.size(); i++) {
                list.add(nodeList.get(i).name);
            }

            nodeAdapter.updateData(list, appConf.getCurNodeInfo().name);
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
    }

    public int convertDpToPx(int dp) {
        return (int)(dp * NodeActivity.this.getResources().getDisplayMetrics().density);
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);

        edit_node.setIndicatorBounds(edit_node.getWidth()- convertDpToPx(40), edit_node.getWidth());
    }

    private void showErrorDialog(int resStr){
        showErrorDialog(getString(resStr));
    }

    private void showErrorDialog(String message) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }
}
