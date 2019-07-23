package pivx.org.pivxwallet.utils;

import android.os.AsyncTask;

import org.pivxj.core.NetworkParameters;
import org.pivxj.core.Sha256Hash;
import org.pivxj.core.Transaction;
import org.pivxj.core.Utils;

import java.math.BigDecimal;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Map;

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
                case "getrawtransactionbyblockheight":
                    for (int i = Integer.parseInt(params[1]); i <= Integer.parseInt(params[2]); i++) {
                        Map map = (Map) rpcClient.query("getrawtransactionbyblockheight", i);
                        NetworkParameters n = NetworkParameters.fromID(NetworkParameters.ID_MAINNET);
                        PivxApplication.getInstance().getModule().getWallet().setLastBlockSeenHeight(i);
                        PivxApplication.getInstance().getModule().getWallet().setLastBlockSeenHash(Sha256Hash.wrap((String)map.get("blockhash")));
                        PivxApplication.getInstance().getModule().getWallet().setLastBlockSeenTimeSecs((Long)map.get("blocktime"));
                        ArrayList<String> hexs = (ArrayList<String>) map.get("hexs");
                        PivxApplication.getInstance().getModule().getWallet().isTransactionForMe(new Transaction(n, Utils.HEX.decode("0100000001fd922fc7c27adf51aa89c47c47357dea2d3eebc29c0e998028bcbe7dfe44c4f00200000000ffffffff0021029910bf6091e05c48a92f3ebd7e97dd3a8401c8e041abf2059271b6e0a988ed1506953f226fafb55460050567ce45f3cb047dbcccfb0ff8ad89a83660f9473f50ab03000000160687c17c034cba2a5b587b6bbaacbcc989825fc920f5b142c721e0717af5260200000077de3aadcf635bad759cf838d77a15d6a57b36bca170f48901387c3cf217c6260100000068c08204a65401b71b47d73d054b95c25c7c865807c8bf55afb4e96fd7babf3c010000008f89114e3d2cbac2d969b9a6b9a3802668adb49f4691b59234f54ec2f8320d85030000004e1c1b398e2122831279e41ea9affdd158597f66ced10c75d3dcce707a4dd0ca01000000000000020000000000000000232103b14f666b2e5df865b91b802f6c888c537ce8b88061e7fcd18441d7532f140311ac002103fb148d148ec087d83ab9fb4acac3e6e5218eab3c2d155892fdc4061fa5e4cf3b837eebf91b2d9bd01f32a9fd372a3fd50b2d4de024911a21d5819b64fb8ac74fde27da2c6f07a567152bfde8cd0840d8ce666ecb9d57744a6cb021be60554b2ed4581ce2be251c979b2b4577891d9d9686da64772d626494a7c86979b1332db900210808969684a4633c4efda32cb615a08d77317b45944050d41f88639925cd31921100000000000000002321025f5e55b4657f110c0071edbdd93f598217aea5d3bd0167a7535c21db61bba89bac0021033a7cb045e9e5f419b1334f8660fb5259eedf39ff365326162a3b48b76240fe6891f6e6c6986f3f68f6099b998136ea0b9c064e41f263e7ac43ce18d8d58f85a897017fcb3cbe7bdd0edb1ab7711dffdbdfb8976ae708b22d471b93837243319e3174a64d1ce5559c4718d8abccbe7a814b07658968a7557bac9895b972e458ea002108e84b6199d34ae5389e7056f5392c2c26292987743cb5e689acc9d87c39d1830b000000000000000000fde302cb1dae287acc828a1382261cdde9c455e34ee0462ffa1f608ed429fa4c88e3387b1fc1dc0baee821dd308f88d9582207f97c3441d1035eedd5741d7219d3188c0d70e5cb128314477f401a25f433dfb52bb03ecb6082aa03bd6ff0d55d5d39fdea39181c172d55c4677ebe82ff5bf35a6736d904d1f86e6c3bc9cab99987681c32f2025e0b9f4bf84b12a30a7a1b084e92563a1626e88fefeea9b24bd3f8bcb7c57c2642831f1644619fdf3f4920c1d161dc746149c30a5b16af573d57a4244aff53e99d04902975b92d6d57b25026b0a303b94b8e43b8e1575d62473d20bbaab06cd5db8764d208cb71ad7a0a1174f928a389a0c3b81682dada7e393636423a3ac8e66efb3421ee1afe344316bab8605d830fa58f05a9cc3bf062e35405fe858fe8250bbc5823cffe10fe5d89c01c77ce7571f2b666801269ffe59f2f3d4ba42d98cedab2199161db312156a0768f8f0bcd1e052d45ccfb4e6c94b81bf0645e0e4d06789fb7d7ca96e1d2af3d67c79aa557a42c333b1e8621d4c6a93275336c42d3356c38dee561cd124e9c955b063d5bd772a3cfb92190d99aa4845576f11df5db29028a745523152ce8eb7a856d03364b6b71c5cb387ebaa262058bd49a71650649a313c863b3e4502a4683e99afdd6aa610f0eec5f88edeaeb09224d37051ec1c397169d499145568ca7f5a5d105df534f73eaad12a847b88df0a366cd2c35852134fb91a8f0b56623012db9f22a34d66cb18c6cb5416cae0185f472fb5076e0c0b86e61df0a07daad5ed585c03fa3705e34706fca279d6d7cfe95530f26c489cc77a43013a2bbf905e233c5015ce181f028c57cccf7a6623bfdaea358a7e2e62c08f297141072463db5d7dc858db63dfc939085c43600a888a7b793758bf51b293726451f1a740694b2f83cb40ce86dff90adcabff5300ad74eb09fdb664a3946e82d5367bf683ea660d20b5dd723cd3cf2654d9dde85867a93eff67c650be22506b3a75058ae02623b2c730db86a3c2938b55a244032cec2694368814aa9b84cd0a272010000000098e5cf87abc7ea7ab8c6677a007bc557a69a7d96a0ee6406a4a5d28759086ed507024c98fba71780d9477727af67a386714c4e15b2b79445f30acb4261f8ca52b60ba6fdf8e51e2b968e6aad7a90a79d8a79fabbbd0f21505240074feaea6ffe1c9e02308f39cf343625008aeea2e350fdc03b07c6996bb2559d3c44cc20674d5d58a6cb990454189c4ea5b3eaf7e86bb9a15c3e958976f6bb98ebdf37d518357619ce0214dff01515db74c09f98ec8c1970e36f2d3e8bfc9e83f8a54c2e2267d7c679f2233e8d3867e2c4cab955522e5a31586ba656c01154ab3d00700776a82995df650282d1380aef403441eb9ebe0d044e0cdacaa0a7c2a5ee372c878b2624d215e60a184dde5ec73a046fb29470157ad3da5fd845e04aac94e2b4da647b5ea28c7adc02f5e501f47c76cefc519e24b15d2d6db69b8cd2491d4df8f67ae13f42ac19507fe6d2aed3cc278a5a50217320022a8f5fb08d5e29ddffd9a5f6fb629eefd58c480235abb24fc31cb6157f4d948f865c735a92b73e0093b8b82df9e85426ffe4c92ef2f03d6d876b455209a6405aeaf084e22222e3505527ce21aab177985254d41802f1a1aff5ea9f94347b5805c03b7ab5d2f5fc038244940e0b400fd5d16cba6f658b3354a9b3355c420042ec8474b30d9c52d9acb8d380357f2b3bf75d732c5b2321036adfe9d3042aed377c6e91e36fe8e0de4d205edcaa29e85f9ca67ad9c55f55d3")), null, 0);
                        for (String hex: hexs) {
                            Transaction tx = new Transaction(n, Utils.HEX.decode(hex));
                            System.out.println("Transaction Hash " + tx.getHashAsString());
                            if (PivxApplication.getInstance().getModule().getWallet().isTransactionForMe(tx, Sha256Hash.wrap((String)map.get("blockhash")), i)) {
                                System.out.println("Transaction " + tx.getHashAsString() + " belongs to me");
                            }
                        }
                    }
                    PivxApplication.getInstance().getModule().saveWallet();
                    return Integer.parseInt(params[2]);
                case "getrawtransaction":
                    return rpcClient.query("getrawtransacion", params[1]);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}