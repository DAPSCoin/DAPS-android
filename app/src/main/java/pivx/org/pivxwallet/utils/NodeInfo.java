package pivx.org.pivxwallet.utils;

import android.content.SharedPreferences;

/**
 * Created by mati on 22/11/16.
 */
public class NodeInfo {
    public String name;
    public String host;
    public int port;
    public String user;
    public String password;

    public NodeInfo(String name, String host, int port, String rpcuser, String rpcpassword) {
        if (name.equals(""))
            this.name = host + ":" + String.valueOf(port);
        else
            this.name = name;
        this.host = host;
        this.port = port;
        this.user = rpcuser;
        this.password = rpcpassword;
    }
}