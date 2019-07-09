package pivx.org.pivxwallet.utils;

import android.os.AsyncTask;

import java.math.BigDecimal;
import java.net.MalformedURLException;
import java.net.URL;

import pivx.org.pivxwallet.PivxApplication;
import wf.bitcoin.javabitcoindrpcclient.BitcoinJSONRPCClient;


/**
 * Created by furszy on 6/12/17.
 *
 * Class in charge of have the default params and save data from the network like servers.
 */

public class DapsControllerAsync extends AsyncTask<String, Void, Object> {
    private BitcoinJSONRPCClient rpcClient = null;
    protected PivxApplication pivxApplication;

    public DapsControllerAsync() {
        pivxApplication = PivxApplication.getInstance();
        try {
            AppConf appConf = pivxApplication.getAppConf();
            NodeInfo node = appConf.getCurNodeInfo();

            URL url = new URL("http://" + node.user + ':' + node.password + "@" + node.host + ":" + node.port + "/");
            rpcClient = new BitcoinJSONRPCClient(url);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
    }

    @Override
    protected Object doInBackground(String... params) {
        String funcName = params[0];
        try {
            switch (funcName) {
                case "getBlockCount":
                    return String.valueOf(rpcClient.getBlockCount());
                case "getBalance":
                    return String.valueOf(rpcClient.getBalance());
                case "getAccountAddress":
                    return String.valueOf(rpcClient.getAccountAddress(""));
                case "backupWallet":
                    rpcClient.backupWallet(params[1]);
                    return null;
                case "importWallet":
                    rpcClient.importWallet(params[1]);
                    return null;
                case "createPrivacyAccount":
                    return rpcClient.query("createprivacyaccount");
                case "setTxFee":
                    return rpcClient.setTxFee(new BigDecimal(params[1]));
                case "sendToStealthAddress":
                    return rpcClient.query("sendtostealthaddress", params[1], new BigDecimal(params[2]));
                case "listTransactions":
                    return rpcClient.query("listtransactions");
                case "getPendingBalance":
                    return rpcClient.query("getbalances");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}