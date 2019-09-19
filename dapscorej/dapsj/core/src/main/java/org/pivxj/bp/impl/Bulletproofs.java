package org.pivxj.bp.impl;

import java.math.BigInteger;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.pivxj.core.ECKey;
import org.pivxj.core.Sha256Hash;
import org.pivxj.core.Utils;
import org.pivxj.crypto.LazyECPoint;

public class Bulletproofs {
	BigInteger negTaux; //blinding factor
	BigInteger negMu;//blinding factor in A and S
	BigInteger tHat; //the result of inner product l(x) . r(x)
	LazyECPoint T1; //// A commitment to the t_1 coefficient of t(X).
	LazyECPoint T2; // A commitment to the t_2 coefficient of t(X).
	LazyECPoint A; // A commitment to aL and aR.
	LazyECPoint S;// A commitment to the blinding vectors sL and sR.
	List<BigInteger> a, b; // Constants at the tail of the inner product proof.
	List<LazyECPoint> Ls, Rs;   // The log(n) points from the inner product proof.
	
	public static Bulletproofs generateRangeProof(int numBit, 
												List<LazyECPoint> commitments, 
												long value, 
												LazyECPoint g, LazyECPoint h, 
												List<LazyECPoint> Gs, List<LazyECPoint> Hs, 
												byte[] nonce, List<BigInteger> powersOfTwo) {
		byte[] commit = new byte[32];
		Bulletproofs bp = new Bulletproofs();
	    for (int i = 0; i < commitments.size(); i++) {
	    	commit = bp.updateCommit(commit, commitments.get(i), h);
	    }
	    
	    if (numBit != 64) return null;
	    Map.Entry<BigInteger, BigInteger> e = bp.hashToScalars(nonce, 0);
	    BigInteger alpha = e.getKey();
	    BigInteger rho = e.getValue();
	    
	    Map.Entry<BigInteger, BigInteger> e2 = bp.hashToScalars(nonce, 1);
	    BigInteger tau1 = e2.getKey();
	    BigInteger tau2 = e2.getValue();
		return null;

	}
	
	public byte[] updateCommit(byte[] commit, LazyECPoint commitment, LazyECPoint h) {
		//TODO: check quadratic: first byte = 3 => quadratic, = 2==> not
		byte lrParity = 0;
		byte[] encoded = commitment.getEncoded(true);
		if (encoded[0] != 3) {
			lrParity = 2;
		}
		byte[] encodedH = h.getEncoded(true);
		if (encodedH[0] != 2) {
			lrParity++;
		}
		byte[] hs = new byte[97];
		System.arraycopy(commit, 0, hs, 0, 32);
		hs[32] = lrParity;
		System.arraycopy(commitment.getAffineXCoord().getEncoded(), 0, hs, 33, 32);
		System.arraycopy(h.getAffineXCoord().getEncoded(), 0, hs, 65, 32);
		byte[] hash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(hs)).getBytes();
		System.arraycopy(hash, 0, commit, 0, 32);
		return commit;
	}
	
	public Map.Entry<BigInteger, BigInteger> hashToScalars(byte[] seed, long idx) {
		long overflowCount = 0;
		BigInteger r1, r2;
		long[] sigma = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
		// Repeatedly call chacha20 until we have two ints that are valid field
		// elements.
		do {
			long v00 = sigma[0];
			long v01 = sigma[1];
			long v02 = sigma[2];
			long v03 = sigma[3];
			long v04 = Utils.readUint32(seed, 0);
			long v05 = Utils.readUint32(seed, 4);
			long v06 = Utils.readUint32(seed, 8);
			long v07 = Utils.readUint32(seed, 12);
			long v08 = Utils.readUint32(seed, 16);
			long v09 = Utils.readUint32(seed, 20);
			long v10 = Utils.readUint32(seed, 24);
			long v11 = Utils.readUint32(seed, 28);
			long v12 = idx;
			long v13 = idx >> 32;
	    	long v14 = 0;
	    	long v15 = overflowCount;

	    	for (int i = 0; i < 20; i += 2) {
	    		v00 += v04;
	    		v12 ^= v00;
	    		v12 = (v12 << 16) | (v12 >> 16);
	    		v08 += v12;
	    		v04 ^= v08;
	    		v04 = (v04 << 12) | (v04 >> 20);
	    		v00 += v04;
	    		v12 ^= v00;
	    		v12 = (v12 << 8) | (v12 >> 24);
	    		v08 += v12;
	    		v04 ^= v08;
	    		v04 = (v04 << 7) | (v04 >> 25);
	    		v01 += v05;
	    		v13 ^= v01;
	    		v13 = (v13 << 16) | (v13 >> 16);
	    		v09 += v13;
	    		v05 ^= v09;
	    		v05 = (v05 << 12) | (v05 >> 20);
	    		v01 += v05;
	    		v13 ^= v01;
	    		v13 = (v13 << 8) | (v13 >> 24);
	    		v09 += v13;
	    		v05 ^= v09;
	    		v05 = (v05 << 7) | (v05 >> 25);
	    		v02 += v06;
	    		v14 ^= v02;
	    		v14 = (v14 << 16) | (v14 >> 16);
	    		v10 += v14;
	    		v06 ^= v10;
	    		v06 = (v06 << 12) | (v06 >> 20);
	    		v02 += v06;
	    		v14 ^= v02;
	    		v14 = (v14 << 8) | (v14 >> 24);
	    		v10 += v14;
	    		v06 ^= v10;
	    		v06 = (v06 << 7) | (v06 >> 25);
	    		v03 += v07;
	    		v15 ^= v03;
	    		v15 = (v15 << 16) | (v15 >> 16);
	    		v11 += v15;
	    		v07 ^= v11;
	    		v07 = (v07 << 12) | (v07 >> 20);
	    		v03 += v07;
	    		v15 ^= v03;
	    		v15 = (v15 << 8) | (v15 >> 24);
	    		v11 += v15;
	    		v07 ^= v11;
	    		v07 = (v07 << 7) | (v07 >> 25);
	    		v00 += v05;
	    		v15 ^= v00;
	    		v15 = (v15 << 16) | (v15 >> 16);
	    		v10 += v15;
	    		v05 ^= v10;
	    		v05 = (v05 << 12) | (v05 >> 20);
	    		v00 += v05;
	    		v15 ^= v00;
	    		v15 = (v15 << 8) | (v15 >> 24);
	    		v10 += v15;
	    		v05 ^= v10;
	    		v05 = (v05 << 7) | (v05 >> 25);
	    		v01 += v06;
	    		v12 ^= v01;
	    		v12 = (v12 << 16) | (v12 >> 16);
	    		v11 += v12;
	    		v06 ^= v11;
	    		v06 = (v06 << 12) | (v06 >> 20);
	    		v01 += v06;
	    		v12 ^= v01;
	    		v12 = (v12 << 8) | (v12 >> 24);
	    		v11 += v12;
	    		v06 ^= v11;
	    		v06 = (v06 << 7) | (v06 >> 25);
	    		v02 += v07;
	    		v13 ^= v02;
	    		v13 = (v13 << 16) | (v13 >> 16);
	    		v08 += v13;
	    		v07 ^= v08;
	    		v07 = (v07 << 12) | (v07 >> 20);
	    		v02 += v07;
	    		v13 ^= v02;
	    		v13 = (v13 << 8) | (v13 >> 24);
	    		v08 += v13;
	    		v07 ^= v08;
	    		v07 = (v07 << 7) | (v07 >> 25);
	    		v03 += v04;
	    		v14 ^= v03;
	    		v14 = (v14 << 16) | (v14 >> 16);
	    		v09 += v14;
	    		v04 ^= v09;
	    		v04 = (v04 << 12) | (v04 >> 20);
	    		v03 += v04;
	    		v14 ^= v03;
	    		v14 = (v14 << 8) | (v14 >> 24);
	    		v09 += v14;
	    		v04 ^= v09;
	    		v04 = (v04 << 7) | (v04 >> 25);
	    	}

	    	v00 += sigma[0];
	    	v01 += sigma[1];
	    	v02 += sigma[2];
	    	v03 += sigma[3];
	    	v04 = Utils.readUint32(seed, 0);
			v05 = Utils.readUint32(seed, 4);
			v06 = Utils.readUint32(seed, 8);
			v07 = Utils.readUint32(seed, 12);
			v08 = Utils.readUint32(seed, 16);
			v09 = Utils.readUint32(seed, 20);
			v10 = Utils.readUint32(seed, 24);
			v11 = Utils.readUint32(seed, 28);
			v12 += idx;
			v13 += idx >> 32;
	    	v14 += 0;
	    	v15 += overflowCount;

	    	byte[] resulta = new byte[32];
	    	byte[] resultb = new byte[32];
	    	
	    	Utils.uint32ToByteArrayLE(v00, resulta, 0);
	    	Utils.uint32ToByteArrayLE(v01, resulta, 4);
	    	Utils.uint32ToByteArrayLE(v02, resulta, 8);
	    	Utils.uint32ToByteArrayLE(v03, resulta, 12);
	    	Utils.uint32ToByteArrayLE(v04, resulta, 16);
	    	Utils.uint32ToByteArrayLE(v05, resulta, 20);
	    	Utils.uint32ToByteArrayLE(v06, resulta, 24);
	    	Utils.uint32ToByteArrayLE(v07, resulta, 28);
	    	
	    	Utils.uint32ToByteArrayLE(v08, resultb, 0);
	    	Utils.uint32ToByteArrayLE(v09, resultb, 4);
	    	Utils.uint32ToByteArrayLE(v10, resultb, 8);
	    	Utils.uint32ToByteArrayLE(v11, resultb, 12);
	    	Utils.uint32ToByteArrayLE(v12, resultb, 16);
	    	Utils.uint32ToByteArrayLE(v13, resultb, 20);
	    	Utils.uint32ToByteArrayLE(v14, resultb, 24);
	    	Utils.uint32ToByteArrayLE(v15, resultb, 28);
	    	
	    	r1 = new BigInteger(resulta);
	    	r2 = new BigInteger(resultb);

	    	// If these are not valid field elements then re-hash and try again.
	    	// This is to avoid biases.
	    	if (r1.compareTo(ECKey.CURVE.getN()) == 1 || r2.compareTo(ECKey.CURVE.getN()) == 1) {
	    		overflowCount++;
	    	} else {
	    		return new AbstractMap.SimpleEntry<BigInteger, BigInteger>(r1, r2);
	    	}
		} while (true);
	}
}
