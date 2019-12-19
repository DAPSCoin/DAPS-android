/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.pivxj.core;

import com.google.common.base.Objects;
import org.pivxj.net.discovery.HttpDiscovery;
import org.pivxj.params.*;
import org.pivxj.script.Script;
import org.pivxj.script.ScriptBuilder;
import org.pivxj.script.ScriptChunk;
import org.pivxj.script.ScriptOpCodes;
import org.pivxj.store.BlockStore;
import org.pivxj.store.BlockStoreException;
import org.pivxj.utils.MonetaryFormat;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.EnumSet;

import static org.pivxj.core.Coin.*;
import org.pivxj.utils.VersionTally;

/**
 * <p>NetworkParameters contains the data needed for working with an instantiation of a Bitcoin chain.</p>
 *
 * <p>This is an abstract class, concrete instantiations can be found in the context package. There are four:
 * one for the main network ({@link MainNetParams}), one for the public test network, and two others that are
 * intended for unit testing and local app development purposes. Although this class contains some aliases for
 * them, you are encouraged to call the static get() methods on each specific context class directly.</p>
 */
public abstract class NetworkParameters {
    /**
     * The alert signing key originally owned by Satoshi, and now passed on to Gavin along with a few others.
     */

    public static final byte[] SATOSHI_KEY = Utils.HEX.decode(CoinDefinition.SATOSHI_KEY); //Hex.decode("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284");

    /** The string returned by getId() for the main, production network where people trade things. */
    public static final String ID_MAINNET = CoinDefinition.ID_MAINNET; //"org.bitcoin.production";
    /** The string returned by getId() for the testnet. */

    public static final String ID_TESTNET = CoinDefinition.ID_TESTNET; //"org.bitcoin.test";
    /** Unit test network. */
    public static final String ID_UNITTESTNET = CoinDefinition.ID_UNITTESTNET; //"com.google.bitcoin.unittest";
    /** The string returned by getId() for regtest mode. */
    public static final String ID_REGTEST = "org.pivx.regtest";

    /** The string used by the payment protocol to represent the main net. */
    public static final String PAYMENT_PROTOCOL_ID_MAINNET = "main";
    /** The string used by the payment protocol to represent the test net. */
    public static final String PAYMENT_PROTOCOL_ID_TESTNET = "test";
    /** The string used by the payment protocol to represent unit testing (note that this is non-standard). */
    public static final String PAYMENT_PROTOCOL_ID_UNIT_TESTS = "unittest";
    public static final String PAYMENT_PROTOCOL_ID_REGTEST = "regtest";

    // TODO: Seed nodes should be here as well.

    protected Block genesisBlock;
    protected BigInteger maxTarget;
    protected int port;
    protected long packetMagic;  // Indicates message origin network and is used to seek to the next message when stream state is unknown.
    protected int addressHeader;
    protected int p2shHeader;
    protected int dumpedPrivateKeyHeader;
    protected int interval;
    protected int targetTimespan;
    protected byte[] alertSigningKey;
    protected int bip32HeaderPub;
    protected int bip32HeaderPriv;

    protected long zerocoinStartedHeight;

    /** Used to check majorities for block version upgrade */
    protected int majorityEnforceBlockUpgrade;
    protected int majorityRejectBlockOutdated;
    protected int majorityWindow;

    /**
     * See getId(). This may be null for old deserialized wallets. In that case we derive it heuristically
     * by looking at the port number.
     */
    protected String id;

    /**
     * The depth of blocks required for a coinbase transaction to be spendable.
     */
    protected int spendableCoinbaseDepth;
    protected int subsidyDecreaseBlockCount;
    
    protected int[] acceptableAddressCodes;
    protected String[] dnsSeeds;
    protected int[] addrSeeds;
    protected HttpDiscovery.Details[] httpSeeds = {};
    protected Map<Integer, Sha256Hash> checkpoints = new HashMap<Integer, Sha256Hash>();
    protected transient MessageSerializer defaultSerializer = null;




    //Dash Extra Parameters
    protected String strSporkKey;
    String strMasternodePaymentsPubKey;
    String strDarksendPoolDummyAddress;
    long nStartMasternodePayments;



    public String getSporkKey() {
        return strSporkKey;
    }

    protected NetworkParameters() {
        alertSigningKey = SATOSHI_KEY;
        genesisBlock = createGenesis(this);
    }
    //TODO:  put these bytes into the CoinDefinition
    private static Block createGenesis(NetworkParameters n) {
        Block genesisBlock = new Block(n, Block.BLOCK_VERSION_GENESIS);
        //Block genesisBlock = new Block(n, Utils.HEX.decode("010000000000000000000000000000000000000000000000000000000000000000000000ed69f921702a99211f3306959127498a94c986625fc64882bbe2bcff96b6fc037628e55cf0ff0f1e0957d0000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3204ffff001d01042a536570203132203230313820576974682044617073636f696e20446576656c6f706d656e74205465616dffffffff0000000000000100000000000000004341041db2a1b75bc00fc1a18e9f8de27c65fede32eb9ac1c11e2587402a66732656d71f7b5de649c8dc7f94aeb433485ce3122ba856644b02e433c2d5fc94ea26bf8eac0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
    	byte[] txBytes = Utils.HEX.decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3204ffff001d01042a536570203132203230313820576974682044617073636f696e20446576656c6f706d656e74205465616dffffffff0000000000000100000000000000004341041db2a1b75bc00fc1a18e9f8de27c65fede32eb9ac1c11e2587402a66732656d71f7b5de649c8dc7f94aeb433485ce3122ba856644b02e433c2d5fc94ea26bf8eac0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        //byte[] txBytes = Utils.HEX.decode("010000000107257658c248e20915b06982b65e40cd33f4583a6a99a8d7145f29caedb00e880100000049483045022100fcd06a6ca479451db915953ab751021dec19f6932d3037eced48d0a0af73ad43022025019d0d897bc7fe941dcd5c7b0d4f9ba2dcea0aabe5fc21967b7df5b66e61ce01ffffffff210368232d66802d954b9a7ad31c50638bee8fa6735d01de51c510e4c7331bab67dd21025e422e0549d4994cc260225f989e0a4bd3a1e88949ea0e36385a42b562c72e20000020aad6cfbba624fa7cc12e02ea0a29a7b0b5e2b6b3580db2de29f19926d362bec52102bb0c5d2541488506da11a42ad2c88568c8c9f07d1f87ba02dd52b4d6e88b27a8040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000203d88792d00002321024f14e510edf04a70eb35558cb865d03e6b542f346531072d1277c86d8123e9e3ac00210328fbd5f449a743ae20ebe1e513365a89f8f7baff19f335dcd7165677ef0f0f9f0813ca4e7bdf632d2fb2b40ffbe277a586c26e5fb7e206c4bab2507aaaeb899b0e0956db0deac3167824cdc635b4985328cf0b621f4ee99795323a8d462fc71859294e22f96ac6b65da196de73c8230c428edd90c36e72965359a10634d3d65b002109f1928a02dfb322501932d9ae5ef5987b4622d5df17a6ceb0d925996a6c7cec790068c461080000002321032941c0cd9a27149f0225d16d8a31c6b629a051f39674a4796abda492ce26fd2eac002103b0c0925008777cf9d44e5441a9865660e84b9c3d7207dc84c4792987dc3c0d84125f5cf59e07bd815820cc66dfca61b7e049db13dba08a1693cbbf4fbbcfe7433f4c56bc7616511eeb1854d44847e55b5c7db99be37c3e56a4b4c7a2a099084c0165fbf226e45e2a700b0bcf7fdf095d770eec4c911c5604b044f1e828e200350021087f302ee3281457ac2cbe9c6411006769b40502850618ce3f00c07385f6377a0a009ca6920c000000232102799ecbe700c48a621fccdaa36e1b04b41e423e64d9aa79a5dc5b2a57f6ed0751ac2040c2376707101d84cf3f69092c392ce8e58583dbfc21063852d640941c51329d2102996d01c71276f223552059471fc38218a6736b424b849d0b5b3dce749ca6b3779511c1553375dc80bc0eeafb8d47c94ecf11c98f552f1633f486a8ef848ee0fb050d6ea17ce840df37a6b0b34b98ffdf0af9eff2717e1572f5e726434f9915f3044b911b0fc87b88c4cdd0f8dd66c3410f1ae1d94425c05384a4e6d05d11729f6334316d33486953705179746347686b6265486b4b71756238576a5376783235344a4846333163584e6162554a564c6b74324664364756563746526f50333958456f73526844707753587072614a4441523170676772704a68313542504769706570784421082770a7e25353eca612e1a413d20424e98888bf82a71ad9993fc8f81c85f9a52800000000000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

        Transaction tx = new Transaction(n, txBytes);
        //System.out.println(tx.getOutput(0).toString());
        System.out.println("genesis tx hash: " + tx.getHashAsString());
        genesisBlock.addTransaction(tx);
        // genesis tx should be -> 1b2ef6e2f28be914103a277377ae7729dcd125dfeb8bf97bd5964ba72b6dc39b
        
        //TODO: modify genesis laterß
        //if (!tx.getHashAsString().equals("1b2ef6e2f28be914103a277377ae7729dcd125dfeb8bf97bd5964ba72b6dc39b")) throw new IllegalStateException("invalid genesis tx: "+tx.getHashAsString());
        return genesisBlock;
    }



    public static final int TARGET_TIMESPAN = CoinDefinition.TARGET_TIMESPAN;//14 * 24 * 60 * 60;  // 2 weeks per difficulty cycle, on average.
    public static final int TARGET_SPACING = CoinDefinition.TARGET_SPACING;// 10 * 60;  // 10 minutes per block.
    public static final int INTERVAL = CoinDefinition.INTERVAL;//TARGET_TIMESPAN / TARGET_SPACING;
    
    /**
     * Blocks with a timestamp after this should enforce BIP 16, aka "Pay to script hash". This BIP changed the
     * network rules in a soft-forking manner, that is, blocks that don't follow the rules are accepted but not
     * mined upon and thus will be quickly re-orged out as long as the majority are enforcing the rule.
     */
    public static final int BIP16_ENFORCE_TIME = 1333238400;
    
    /**
     * The maximum number of coins to be generated
     */
    public static final long MAX_COINS = CoinDefinition.MAX_COINS;

    /**
     * The maximum money to be generated
     */

    public static final Coin MAX_MONEY = COIN.multiply(MAX_COINS);


    /** Alias for TestNet3Params.get(), use that instead. */
    @Deprecated
    public static NetworkParameters testNet() {
        return TestNet3Params.get();
    }

    /** Alias for TestNet2Params.get(), use that instead. */
    @Deprecated
    public static NetworkParameters testNet2() {
        return TestNet2Params.get();
    }

    /** Alias for TestNet3Params.get(), use that instead. */
    @Deprecated
    public static NetworkParameters testNet3() {
        return TestNet3Params.get();
    }

    /** Alias for MainNetParams.get(), use that instead */
    @Deprecated
    public static NetworkParameters prodNet() {
        return MainNetParams.get();
    }

    /** Returns a testnet context modified to allow any difficulty target. */
    @Deprecated
    public static NetworkParameters unitTests() {
        return UnitTestParams.get();
    }

    /** Returns a standard regression test context (similar to unitTests) */
    @Deprecated
    public static NetworkParameters regTests() {
        return RegTestParams.get();
    }

    /**
     * A Java package style string acting as unique ID for these parameters
     */
    public String getId() {
        return id;
    }

    public abstract String getPaymentProtocolId();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return getId().equals(((NetworkParameters)o).getId());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getId());
    }

    /** Returns the network parameters for the given string ID or NULL if not recognized. */
    @Nullable
    public static NetworkParameters fromID(String id) {
        if (id.equals(ID_MAINNET)) {
            return MainNetParams.get();
        } else if (id.equals(ID_TESTNET)) {
            return TestNet3Params.get();
        } else if (id.equals(ID_UNITTESTNET)) {
            return UnitTestParams.get();
        } else if (id.equals(ID_REGTEST)) {
            return RegTestParams.get();
        } else {
            return null;
        }
    }

    /** Returns the network parameters for the given string paymentProtocolID or NULL if not recognized. */
    @Nullable
    public static NetworkParameters fromPmtProtocolID(String pmtProtocolId) {
        if (pmtProtocolId.equals(PAYMENT_PROTOCOL_ID_MAINNET)) {
            return MainNetParams.get();
        } else if (pmtProtocolId.equals(PAYMENT_PROTOCOL_ID_TESTNET)) {
            return TestNet3Params.get();
        } else if (pmtProtocolId.equals(PAYMENT_PROTOCOL_ID_UNIT_TESTS)) {
            return UnitTestParams.get();
        } else if (pmtProtocolId.equals(PAYMENT_PROTOCOL_ID_REGTEST)) {
            return RegTestParams.get();
        } else {
            return null;
        }
    }

    public int getSpendableCoinbaseDepth() {
        return spendableCoinbaseDepth;
    }

    /**
     * Throws an exception if the block's difficulty is not correct.
     *
     * @throws VerificationException if the block's difficulty is not correct.
     */
    public abstract void checkDifficultyTransitions(StoredBlock storedPrev, Block next, final BlockStore blockStore) throws VerificationException, BlockStoreException;

    /**
     * Returns true if the block height is either not a checkpoint, or is a checkpoint and the hash matches.
     */
    public boolean passesCheckpoint(int height, Sha256Hash hash) {
        Sha256Hash checkpointHash = checkpoints.get(height);
        return checkpointHash == null || checkpointHash.equals(hash);
    }

    /**
     * Returns true if the given height has a recorded checkpoint.
     */
    public boolean isCheckpoint(int height) {
        Sha256Hash checkpointHash = checkpoints.get(height);
        return checkpointHash != null;
    }

    public int getSubsidyDecreaseBlockCount() {
        return subsidyDecreaseBlockCount;
    }

    /** Returns DNS names that when resolved, give IP addresses of active peers. */
    public String[] getDnsSeeds() {
        return dnsSeeds;
    }

    /** Returns IP address of active peers. */
    public int[] getAddrSeeds() {
        return addrSeeds;
    }

    /** Returns discovery objects for seeds implementing the Cartographer protocol. See {@link org.pivxj.net.discovery.HttpDiscovery} for more info. */
    public HttpDiscovery.Details[] getHttpSeeds() {
        return httpSeeds;
    }

    /**
     * <p>Genesis block for this chain.</p>
     *
     * <p>The first block in every chain is a well known constant shared between all Bitcoin implemenetations. For a
     * block to be valid, it must be eventually possible to work backwards to the genesis block by following the
     * prevBlockHash pointers in the block headers.</p>
     *
     * <p>The genesis blocks for both test and main networks contain the timestamp of when they were created,
     * and a message in the coinbase transaction. It says, <i>"The Times 03/Jan/2009 Chancellor on brink of second
     * bailout for banks"</i>.</p>
     */
    public Block getGenesisBlock() {
        return genesisBlock;
    }

    /** Default TCP port on which to connect to nodes. */
    public int getPort() {
        return port;
    }

    /** The header bytes that identify the start of a packet on this network. */
    public long getPacketMagic() {
        return packetMagic;
    }

    /**
     * First byte of a base58 encoded address. See {@link org.pivxj.core.Address}. This is the same as acceptableAddressCodes[0] and
     * is the one used for "normal" addresses. Other types of address may be encountered with version codes found in
     * the acceptableAddressCodes array.
     */
    public int getAddressHeader() {
        return addressHeader;
    }

    /**
     * First byte of a base58 encoded P2SH address.  P2SH addresses are defined as part of BIP0013.
     */
    public int getP2SHHeader() {
        return p2shHeader;
    }

    /** First byte of a base58 encoded dumped private key. See {@link org.pivxj.core.DumpedPrivateKey}. */
    public int getDumpedPrivateKeyHeader() {
        return dumpedPrivateKeyHeader;
    }

    /**
     * How much time in seconds is supposed to pass between "interval" blocks. If the actual elapsed time is
     * significantly different from this value, the network difficulty formula will produce a different value. Both
     * test and main Bitcoin networks use 2 weeks (1209600 seconds).
     */
    public int getTargetTimespan() {
        return targetTimespan;
    }

    /**
     * The version codes that prefix addresses which are acceptable on this network. Although Satoshi intended these to
     * be used for "versioning", in fact they are today used to discriminate what kind of data is contained in the
     * address and to prevent accidentally sending coins across chains which would destroy them.
     */
    public int[] getAcceptableAddressCodes() {
        return acceptableAddressCodes;
    }

    /**
     * If we are running in testnet-in-a-box mode, we allow connections to nodes with 0 non-genesis blocks.
     */
    public boolean allowEmptyPeerChain() {
        return true;
    }

    /** How many blocks pass between difficulty adjustment periods. Bitcoin standardises this to be 2015. */
    public int getInterval() {
        return interval;
    }

    /** Maximum target represents the easiest allowable proof of work. */
    public BigInteger getMaxTarget() {
        return maxTarget;
    }

    /**
     * The key used to sign {@link org.pivxj.core.AlertMessage}s. You can use {@link org.pivxj.core.ECKey#verify(byte[], byte[], byte[])} to verify
     * signatures using it.
     */
    public byte[] getAlertSigningKey() {
        return alertSigningKey;
    }

    /** Returns the 4 byte header for BIP32 (HD) wallet - public key part. */
    public int getBip32HeaderPub() {
        return bip32HeaderPub;
    }

    /** Returns the 4 byte header for BIP32 (HD) wallet - private key part. */
    public int getBip32HeaderPriv() {
        return bip32HeaderPriv;
    }

    /**
     * Returns the number of coins that will be produced in total, on this
     * network. Where not applicable, a very large number of coins is returned
     * instead (i.e. the main coin issue for Dogecoin).
     */
    public abstract Coin getMaxMoney();

    /**
     * Any standard (ie pay-to-address) output smaller than this value will
     * most likely be rejected by the network.
     */
    public abstract Coin getMinNonDustOutput();

    /**
     * The monetary object for this currency.
     */
    public abstract MonetaryFormat getMonetaryFormat();

    /**
     * Scheme part for URIs, for example "bitcoin".
     */
    public abstract String getUriScheme();

    /**
     * Returns whether this network has a maximum number of coins (finite supply) or
     * not. Always returns true for Bitcoin, but exists to be overriden for other
     * networks.
     */
    public abstract boolean hasMaxMoney();

    /**
     * Return the default serializer for this network. This is a shared serializer.
     * @return 
     */
    public final MessageSerializer getDefaultSerializer() {
        // Construct a default serializer if we don't have one
        if (null == this.defaultSerializer) {
            // Don't grab a lock unless we absolutely need it
            synchronized(this) {
                // Now we have a lock, double check there's still no serializer
                // and create one if so.
                if (null == this.defaultSerializer) {
                    // As the serializers are intended to be immutable, creating
                    // two due to a race condition should not be a problem, however
                    // to be safe we ensure only one exists for each network.
                    this.defaultSerializer = getSerializer(false);
                }
            }
        }
        return defaultSerializer;
    }

    /**
     * Zerocoin started height in blockchain
     * @return
     */
    public long getZerocoinStartedHeight() {
        return zerocoinStartedHeight;
    }

    /**
     * Construct and return a custom serializer.
     */
    public abstract BitcoinSerializer getSerializer(boolean parseRetain);

    /**
     * The number of blocks in the last {@link getMajorityWindow()} blocks
     * at which to trigger a notice to the user to upgrade their client, where
     * the client does not understand those blocks.
     */
    public int getMajorityEnforceBlockUpgrade() {
        return majorityEnforceBlockUpgrade;
    }

    /**
     * The number of blocks in the last {@link getMajorityWindow()} blocks
     * at which to enforce the requirement that all new blocks are of the
     * newer type (i.e. outdated blocks are rejected).
     */
    public int getMajorityRejectBlockOutdated() {
        return majorityRejectBlockOutdated;
    }

    /**
     * The sampling window from which the version numbers of blocks are taken
     * in order to determine if a new block version is now the majority.
     */
    public int getMajorityWindow() {
        return majorityWindow;
    }

    /**
     * The flags indicating which block validation tests should be applied to
     * the given block. Enables support for alternative blockchains which enable
     * tests based on different criteria.
     * 
     * @param block block to determine flags for.
     * @param height height of the block, if known, null otherwise. Returned
     * tests should be a safe subset if block height is unknown.
     */
    public EnumSet<Block.VerifyFlag> getBlockVerificationFlags(final Block block,
            final VersionTally tally, final Integer height) {
        final EnumSet<Block.VerifyFlag> flags = EnumSet.noneOf(Block.VerifyFlag.class);

        if (block.isBIP34()) {
            final Integer count = tally.getCountAtOrAbove(Block.BLOCK_VERSION_BIP34);
            if (null != count && count >= getMajorityEnforceBlockUpgrade()) {
                flags.add(Block.VerifyFlag.HEIGHT_IN_COINBASE);
            }
        }
        return flags;
    }

    /**
     * The flags indicating which script validation tests should be applied to
     * the given transaction. Enables support for alternative blockchains which enable
     * tests based on different criteria.
     *
     * @param block block the transaction belongs to.
     * @param transaction to determine flags for.
     * @param height height of the block, if known, null otherwise. Returned
     * tests should be a safe subset if block height is unknown.
     */
    public EnumSet<Script.VerifyFlag> getTransactionVerificationFlags(final Block block,
            final Transaction transaction, final VersionTally tally, final Integer height) {
        final EnumSet<Script.VerifyFlag> verifyFlags = EnumSet.noneOf(Script.VerifyFlag.class);
        if (block.getTimeSeconds() >= NetworkParameters.BIP16_ENFORCE_TIME)
            verifyFlags.add(Script.VerifyFlag.P2SH);

        // Start enforcing CHECKLOCKTIMEVERIFY, (BIP65) for block.nVersion=4
        // blocks, when 75% of the network has upgraded:
        if (block.getVersion() >= Block.BLOCK_VERSION_BIP65 &&
            tally.getCountAtOrAbove(Block.BLOCK_VERSION_BIP65) > this.getMajorityEnforceBlockUpgrade()) {
            verifyFlags.add(Script.VerifyFlag.CHECKLOCKTIMEVERIFY);
        }

        return verifyFlags;
    }

    public abstract int getProtocolVersionNum(final ProtocolVersion version);

    public static enum ProtocolVersion {
        MINIMUM(CoinDefinition.MIN_PROTOCOL_VERSION),
        PONG(60001),
        BLOOM_FILTER(70000),
        CURRENT(CoinDefinition.PROTOCOL_VERSION);

        private final int bitcoinProtocol;

        ProtocolVersion(final int bitcoinProtocol) {
            this.bitcoinProtocol = bitcoinProtocol;
        }

        public int getBitcoinProtocolVersion() {
            return bitcoinProtocol;
        }
    }
}
