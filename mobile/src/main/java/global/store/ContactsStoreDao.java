package global.store;

import global.AddressLabel;

import java.util.List;

/**
 * Created by furszy on 3/3/18.
 */

public interface ContactsStoreDao<T> extends AbstractDbDao<T> {

    AddressLabel getContact(String address);

    void delete(AddressLabel data);

    List<AddressLabel> getMyAddresses();

    List<AddressLabel> getContacts();
}
