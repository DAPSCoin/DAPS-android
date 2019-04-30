package pivx.org.pivxwallet.utils;

import android.os.AsyncTask;

import java.math.BigDecimal;
import java.net.MalformedURLException;
import java.net.URL;

import wf.bitcoin.javabitcoindrpcclient.BitcoinJSONRPCClient;


/**
 * Created by furszy on 6/12/17.
 *
 * Class in charge of have the default params and save data from the network like servers.
 */

public class DapsControllerAsync extends AsyncTask<String, Void, Object> {
    private final String user = "bilbo";
    private final String password = "baggins";
    private final String host = "35.227.81.1";
    private final String port = "53573";
    private BitcoinJSONRPCClient rpcClient = null;

    public DapsControllerAsync() {
        try {
            if (rpcClient == null) {
                URL url = new URL("http://" + user + ':' + password + "@" + host + ":" + port + "/");
                rpcClient = new BitcoinJSONRPCClient(url);
            }

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
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}