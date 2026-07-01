#!/usr/bin/env python3
# Copyright (c) 2015-2022 Blackcoin Core Developers
# Copyright (c) 2015-2022 Blackcoin More Developers
# Copyright (c) 2015-2022 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP65 (CHECKLOCKTIMEVERIFY).

Test that the CHECKLOCKTIMEVERIFY soft-fork activates.
"""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    TIME_GENESIS_BLOCK,
    create_block,
    create_coinbase,
)
from test_framework.messages import SEQUENCE_FINAL, msg_block
from test_framework.p2p import P2PInterface
from test_framework.script import (
    CScript,
    CScriptNum,
    OP_1NEGATE,
    OP_CHECKLOCKTIMEVERIFY,
    OP_DROP,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
)


# Helper function to modify a transaction by
# 1) prepending a given script to the scriptSig of vin 0 and
# 2) (optionally) modify the nSequence of vin 0 and the tx's nLockTime
def cltv_modify_tx(tx, prepend_scriptsig, nsequence=None, nlocktime=None):
    assert_equal(len(tx.vin), 1)
    if nsequence is not None:
        tx.vin[0].nSequence = nsequence
        tx.nLockTime = nlocktime

    tx.vin[0].scriptSig = CScript(prepend_scriptsig + list(CScript(tx.vin[0].scriptSig)))
    tx.rehash()


def cltv_invalidate(tx, failure_reason):
    # Modify the signature in vin 0 and nSequence/nLockTime of the tx to fail CLTV
    #
    # According to BIP65, OP_CHECKLOCKTIMEVERIFY can fail due the following reasons:
    # 1) the stack is empty
    # 2) the top item on the stack is less than 0
    # 3) the lock-time type (height vs. timestamp) of the top stack item and the
    #    nLockTime field are not the same
    # 4) the top stack item is greater than the transaction's nLockTime field
    # 5) the nSequence field of the txin is 0xffffffff (SEQUENCE_FINAL)
    assert failure_reason in range(5)
    scheme = [
        # | Script to prepend to scriptSig                  | nSequence  | nLockTime    |
        # +-------------------------------------------------+------------+--------------+
        [[OP_CHECKLOCKTIMEVERIFY],                            None,       None],
        [[OP_1NEGATE, OP_CHECKLOCKTIMEVERIFY, OP_DROP],       None,       None],
        [[CScriptNum(100), OP_CHECKLOCKTIMEVERIFY, OP_DROP],  0,          TIME_GENESIS_BLOCK],
        [[CScriptNum(100), OP_CHECKLOCKTIMEVERIFY, OP_DROP],  0,          50],
        [[CScriptNum(50),  OP_CHECKLOCKTIMEVERIFY, OP_DROP],  SEQUENCE_FINAL, 50],
    ][failure_reason]

    cltv_modify_tx(tx, prepend_scriptsig=scheme[0], nsequence=scheme[1], nlocktime=scheme[2])


def cltv_validate(tx, height):
    # Modify the signature in vin 0 and nSequence/nLockTime of the tx to pass CLTV
    scheme = [[CScriptNum(height), OP_CHECKLOCKTIMEVERIFY, OP_DROP], 0, height]

    cltv_modify_tx(tx, prepend_scriptsig=scheme[0], nsequence=scheme[1], nlocktime=scheme[2])


class BIP65Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            '-whitelist=noban@127.0.0.1',
            '-par=1',  # Use only one script thread to get the exact reject reason for testing
            '-acceptnonstdtxn=1',  # cltv_invalidate is nonstandard
        ]]
        self.setup_clean_chain = True
        self.rpc_timeout = 480

    def test_cltv_info(self, *, is_active):
        # Blackcoin: assume that CLTV is always active
        pass

    def run_test(self):
        peer = self.nodes[0].add_p2p_connection(P2PInterface())
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_TRUE)

        self.test_cltv_info(is_active=True)

        self.log.info("Mining mature outputs for always-active CLTV checks")
        self.generate(wallet, max(COINBASE_MATURITY + 10, 60))

        self.log.info("Test that invalid-according-to-CLTV transactions cannot appear in a block")
        tip = int(self.nodes[0].getbestblockhash(), 16)
        block_time = self.nodes[0].getblockheader(f'{tip:064x}')['mediantime'] + 1
        block_height = self.nodes[0].getblockcount() + 1
        block = create_block(tip, create_coinbase(block_height), block_time)

        # create and test one invalid tx per CLTV failure reason (5 in total)
        for i in range(5):
            spendtx = wallet.create_self_transfer()['tx']
            cltv_invalidate(spendtx, i)

            expected_cltv_reject_reason = [
                "mandatory-script-verify-flag-failed (Operation not valid with the current stack size)",
                "mandatory-script-verify-flag-failed (Negative locktime)",
                "mandatory-script-verify-flag-failed (Locktime requirement not satisfied)",
                "mandatory-script-verify-flag-failed (Locktime requirement not satisfied)",
                "mandatory-script-verify-flag-failed (Locktime requirement not satisfied)",
            ][i]
            # First we show that this tx is valid except for CLTV by getting it
            # rejected from the mempool for exactly that reason.
            assert_equal(
                [{
                    'txid': spendtx.hash,
                    'wtxid': spendtx.getwtxid(),
                    'allowed': False,
                    'reject-reason': expected_cltv_reject_reason,
                }],
                self.nodes[0].testmempoolaccept(rawtxs=[spendtx.serialize().hex()], maxfeerate=0),
            )

            # Now we verify that a block with this transaction is also invalid.
            if len(block.vtx) == 1:
                block.vtx.append(spendtx)
            else:
                block.vtx[1] = spendtx
            block.hashMerkleRoot = block.calc_merkle_root()
            block.solve()

            with self.nodes[0].assert_debug_log(expected_msgs=[f'CheckInputScripts on {block.vtx[-1].hash} failed with {expected_cltv_reject_reason}']):
                peer.send_and_ping(msg_block(block))
                assert_equal(int(self.nodes[0].getbestblockhash(), 16), tip)
                peer.sync_with_ping()

        self.log.info("Test that a version 4 block with a valid-according-to-CLTV transaction is accepted")
        cltv_validate(spendtx, block_height - 1)

        block.vtx.pop(1)
        block.vtx.append(spendtx)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()

        self.test_cltv_info(is_active=True)
        peer.send_and_ping(msg_block(block))
        self.test_cltv_info(is_active=True)
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.sha256)


if __name__ == '__main__':
    BIP65Test().main()
