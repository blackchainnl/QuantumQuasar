#!/usr/bin/env python3
# Copyright (c) 2020-2021 Blackcoin Core Developers
# Copyright (c) 2020-2021 Blackcoin More Developers
# Copyright (c) 2020-2021 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test transaction relay behavior during IBD:
- Set fee filters to MAX_MONEY
- Don't request transactions
- Ignore all transaction messages
"""

from decimal import Decimal
import time

from test_framework.messages import (
        CInv,
        COIN,
        COutPoint,
        CTransaction,
        CTxIn,
        CTxOut,
        msg_inv,
        msg_tx,
        MSG_WTX,
)
from test_framework.p2p import (
        NONPREF_PEER_TX_DELAY,
        P2PDataStore,
        P2PInterface,
        p2p_lock
)
from test_framework.test_framework import BitcoinTestFramework

IBD_FEE_FILTER_MIN = Decimal("0.09")
NORMAL_FEE_FILTER = Decimal(100000) / COIN
NORMAL_FEE_FILTER_MIN = Decimal("0.0009")


class P2PIBDTxRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ["-minrelaytxfee={}".format(NORMAL_FEE_FILTER)],
            ["-minrelaytxfee={}".format(NORMAL_FEE_FILTER)],
        ]

    def run_test(self):
        self.log.info("Check that nodes set a high minfilter while still in IBD")
        for node in self.nodes:
            assert node.getblockchaininfo()['initialblockdownload']
            # The exact rounded MAX_MONEY feefilter bucket differs from the
            # inherited Bitcoin value, but it must remain high enough to stop
            # transaction announcements while the node is in IBD.
            self.wait_until(lambda: all(peer['minfeefilter'] >= IBD_FEE_FILTER_MIN for peer in node.getpeerinfo()))

        self.log.info("Check that nodes don't send getdatas for transactions while still in IBD")
        peer_inver = self.nodes[0].add_p2p_connection(P2PDataStore())
        txid = 0xdeadbeef
        peer_inver.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=txid)]))
        # The node should not send a getdata, but if it did, it would first delay 2 seconds
        self.nodes[0].setmocktime(int(time.time() + NONPREF_PEER_TX_DELAY))
        peer_inver.sync_with_ping()
        with p2p_lock:
            assert txid not in peer_inver.getdata_requests
        self.nodes[0].disconnect_p2ps()

        self.log.info("Check that nodes don't process unsolicited transactions while still in IBD")
        # There are no spendable UTXOs yet, but this must be a well-formed
        # Blackcoin transaction so the unsolicited-tx path is exercised.
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(hash=1, n=0))]
        tx.vout = [CTxOut(nValue=1)]
        tx.rehash()
        assert self.nodes[1].decoderawtransaction(tx.serialize().hex()) # returns a dict, should not throw
        peer_txer = self.nodes[0].add_p2p_connection(P2PInterface())
        with self.nodes[0].assert_debug_log(expected_msgs=["received: tx"], unexpected_msgs=["was not accepted"]):
            peer_txer.send_and_ping(msg_tx(tx))
        self.nodes[0].disconnect_p2ps()

        # Come out of IBD by generating a block
        self.generate(self.nodes[0], 1)

        self.log.info("Check that nodes reset minfilter after coming out of IBD")
        for node in self.nodes:
            assert not node.getblockchaininfo()['initialblockdownload']
            self.wait_until(lambda: all(
                NORMAL_FEE_FILTER_MIN <= peer['minfeefilter'] < IBD_FEE_FILTER_MIN
                for peer in node.getpeerinfo()
            ))

        self.log.info("Check that nodes process the same transaction, even when unsolicited, when no longer in IBD")
        peer_txer = self.nodes[0].add_p2p_connection(P2PInterface())
        with self.nodes[0].assert_debug_log(expected_msgs=["was not accepted"]):
            peer_txer.send_and_ping(msg_tx(tx))

if __name__ == '__main__':
    P2PIBDTxRelayTest().main()
