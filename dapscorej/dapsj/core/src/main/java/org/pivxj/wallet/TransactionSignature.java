package org.pivxj.wallet;

import static org.pivxj.core.Utils.int64ToByteStreamLE;
import static org.pivxj.core.Utils.uint32ToByteStreamLE;
import static org.pivxj.core.Utils.uint64ToByteStreamLE;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.pivxj.core.Message;
import org.pivxj.core.ProtocolException;
import org.pivxj.core.Sha256Hash;
import org.pivxj.core.Transaction;
import org.pivxj.core.TransactionInput;
import org.pivxj.core.TransactionOutput;
import org.pivxj.core.VarInt;

public class TransactionSignature extends Message {
    private long version;
    private List<TransactionInput> inputs;
    private List<TransactionOutput> outputs;
    private long lockTime;
	//For stealth transactions
    private BigInteger txPrivM;    //only  in-memory
    private byte hasPaymentID;
    private BigInteger paymentID;
    private long txType;

    private long nTxFee;
    
    public TransactionSignature(Transaction tx) {
    	this.version = tx.getVersion();
    	this.inputs = tx.getInputs();
    	this.outputs = tx.getOutputs();
    	this.lockTime = tx.getLockTime();
    	this.hasPaymentID = tx.getHasPaymentID();
    	this.paymentID = tx.getPaymentID();
    	this.txType = tx.getTxType();
    	this.nTxFee = tx.getnTxFee();
    }

	@Override
	protected void parse() throws ProtocolException {
		// TODO Auto-generated method stub
		
	}
	
	@Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        uint32ToByteStreamLE(version, stream);
        stream.write(new VarInt(inputs.size()).encode());
        for (TransactionInput in : inputs)
            in.bitcoinSerialize(stream);
        stream.write(new VarInt(outputs.size()).encode());
        for (TransactionOutput out : outputs)
            out.bitcoinSerialize(stream);
        uint32ToByteStreamLE(lockTime, stream);
        stream.write(hasPaymentID);
        if (hasPaymentID != 0) {
        	uint64ToByteStreamLE(paymentID, stream);
        }
        uint32ToByteStreamLE(txType, stream);
                
        int64ToByteStreamLE(nTxFee, stream);
    }
	
	public byte[] getSigHash() {
		return Sha256Hash.hashTwice(unsafeBitcoinSerialize());
	}
}
