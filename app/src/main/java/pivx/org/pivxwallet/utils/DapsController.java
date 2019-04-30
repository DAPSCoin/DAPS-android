package pivx.org.pivxwallet.utils;


import java.util.concurrent.ExecutionException;

/**
 * Created by furszy on 6/12/17.
 *
 * Class in charge of have the default params and save data from the network like servers.
 */

public class DapsController{
    public Object callRPC(String... params) {
        try {
            return new DapsControllerAsync().execute(params).get();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }

        return null;
    }
}