// Copyright (c) 2026 The Blackcoin - Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/quantumguides.h>

#include <QObject>

namespace {

QString CommonGuide()
{
    return QObject::tr(R"HTML(
<hr>
<h2>Core concepts used throughout this wallet</h2>
<p><b>Blackcoin V30</b> keeps the legacy Blackcoin chain usable during the transition while upgraded wallets also track quantum-resistant state. The goal is to let old wallets continue to see ordinary chain activity during the preparation period, while upgraded users can create quantum addresses, receive Gold Rush rewards, migrate funds, and prepare for post-quantum staking.</p>

<h3>There are two value families in the wallet</h3>
<ul>
<li><b>Legacy BLK</b> is controlled by the older Blackcoin address and signature system. These coins are still normal chain coins during the transition. Legacy staking continues to help secure the base network.</li>
<li><b>Quantum BLK</b> is controlled by ML-DSA witness programs. These addresses are intended for Gold Rush rewards, migrated balances, post-quantum sends, and quantum staking workflows.</li>
</ul>
<p>The wallet separates these balances because a user should not have to guess which spend path will be used. If a screen says <b>legacy</b>, it means old-style spend authority. If it says <b>quantum</b>, it means the upgraded ML-DSA path.</p>

<h3>Why Gold Rush uses small legacy-chain control transactions</h3>
<p>Gold Rush participation is visible on the legacy chain through small control transactions. A PoS signal uses a QQSIGNAL record. A PoW claim uses a QQSPROOF record. These are ordinary fee-paying transactions that old nodes can carry, while upgraded nodes understand the extra meaning and credit quantum rewards.</p>
<p>Example: a PoW miner finds a valid Argon2id proof. The wallet spends a small legacy UTXO and includes the proof plus the quantum payout address. A staker includes that transaction in a block. Upgraded nodes then credit the quantum reward to the payout address. Legacy nodes simply see a normal transaction with data.</p>

<h3>What confirmations mean in these screens</h3>
<ul>
<li><b>Unconfirmed</b> means the transaction is in the mempool or known locally but not yet in a block.</li>
<li><b>Confirmed</b> means the transaction is in the active chain. More confirmations reduce reorg risk.</li>
<li><b>Mature</b> means a newly staked or mined output has passed the chain's maturity rule and can be used by the wallet.</li>
</ul>
<p>For everyday testing, wait at least several confirmations before judging a staking, mining, migration, or cold-staking setup. A wallet can display a transaction before it is mature enough to be used again.</p>

<h3>Backups matter more after quantum address creation</h3>
<p>Every new quantum address, operator key, staking address, or delegation address is wallet-backed key material. Back up the wallet after creating those addresses. A backup from before a quantum key was created may not contain the key needed to spend funds sent there.</p>

<h3>How to read transaction names</h3>
<ul>
<li><b>PoS - Quantum Stake</b> means a PoS quantum reward credit was accepted for a quantum payout address.</li>
<li><b>PoW - Quantum Claim</b> means a PoW quantum claim was accepted and credited to a quantum payout address.</li>
<li><b>PoW Claim</b> or <b>PoS Claim</b> is the small control transaction and fee that anchored participation on the legacy-visible chain.</li>
</ul>
<p>Seeing a small negative fee entry next to a quantum reward is expected. The fee is the legacy-chain cost of anchoring participation. The reward is the upgraded quantum credit.</p>
)HTML");
}

QString PosGuide()
{
    return QObject::tr(R"HTML(
<h2>Detailed PoS Gold Rush example</h2>
<p>PoS Gold Rush rewards are designed for wallets that were already meaningful legacy holders at the whitelist snapshot. Eligibility is based on aggregate wallet-address balance at the snapshot, not on one specific 10,000 BLK UTXO.</p>
<ol>
<li>A wallet controls one or more legacy addresses.</li>
<li>At the whitelist snapshot height, the wallet's controlled addresses are checked for aggregate balance.</li>
<li>If the aggregate balance is at least 10,000 BLK, that wallet target can qualify for PoS Gold Rush participation.</li>
<li>During Gold Rush, the wallet still has to actively stake and solve PoS blocks.</li>
<li>When it has a recent qualifying solve, the wallet must be normally unlocked so it can publish the signal transaction.</li>
</ol>
<p><b>Example A:</b> a wallet held 6,000 BLK at one address and 4,500 BLK at another controlled address at the snapshot. The aggregate is 10,500 BLK, so it can qualify.</p>
<p><b>Example B:</b> a wallet held 9,999.999 BLK at the snapshot. It is below the threshold and must not receive PoS Gold Rush rewards from that snapshot.</p>
<p><b>Example C:</b> a wallet receives 20,000 BLK after the snapshot. That may help ordinary staking, but it does not retroactively make the wallet whitelisted for the snapshot-based PoS Gold Rush share.</p>

<h3>Why a normal unlock is needed for PoS Gold Rush</h3>
<p>Legacy staking-only unlock is intentionally narrow. It lets the wallet create ordinary legacy coinstakes without opening the wallet for spending. A Gold Rush signal is not just a legacy coinstake. It is an extra wallet-authenticated control transaction that links the qualifying activity to a quantum payout address. That requires normal signing authority.</p>

<h3>Where PoS rewards go</h3>
<p>Ordinary staking rewards follow the usual legacy staking path. Gold Rush reward credits go to a quantum payout address. In the transaction list, the upgraded credit should be labeled <b>PoS - Quantum Stake</b> and should show the quantum destination so the user can tell which address received the reward.</p>

<h3>What to do if you expected a PoS reward but do not see one</h3>
<ul>
<li>Confirm the current block height is inside the Gold Rush reward window.</li>
<li>Confirm the wallet had at least 10,000 BLK aggregate balance at the whitelist snapshot height.</li>
<li>Confirm the wallet solved a PoS block inside the rolling activity window.</li>
<li>Confirm the wallet was normally unlocked, not only legacy staking-only unlocked, when the signal needed to be created.</li>
<li>Check the Transactions and Account tabs for the quantum payout address and credit.</li>
</ul>
)HTML");
}

QString PowGuide()
{
    return QObject::tr(R"HTML(
<h2>Detailed PoW Gold Rush example</h2>
<p>Gold Rush PoW is not a separate block chain. It creates claim transactions that are included in ordinary PoS blocks. This gives smaller holders a way to compete for part of the Gold Rush reward schedule without needing 10,000 BLK at the PoS whitelist snapshot.</p>
<ol>
<li>The wallet creates or reuses a wallet-backed quantum payout address.</li>
<li>The built-in miner searches for an Argon2id proof that meets the current target.</li>
<li>When it finds a proof, the wallet creates a QQSPROOF transaction.</li>
<li>The QQSPROOF transaction pays a normal small legacy-chain fee.</li>
<li>A staker includes the claim in a PoS block.</li>
<li>Upgraded nodes credit the PoW Gold Rush reward to the quantum payout address.</li>
</ol>
<p><b>CPU example:</b> 1 core at 1 percent is deliberately gentle and should keep the wallet responsive. 4 cores at 50 percent is much more aggressive. The higher setting may find more proofs but will use more battery, heat, and fan.</p>
<p><b>Fee example:</b> if the control transaction is small and the network minimum fee is low, the visible legacy fee can be tiny compared with the quantum reward. The user still needs a small legacy UTXO available so the wallet can anchor the claim.</p>

<h3>Why the payout must be a quantum address</h3>
<p>PoW Gold Rush is intended to pull users onto quantum-resistant keys. Paying the reward to a legacy address would defeat the transition goal. The wallet therefore uses a quantum payout address and asks users to back up the wallet after that address exists.</p>

<h3>Moving PoW rewards once</h3>
<p>A Gold Rush reward should be moved to a fresh quantum address before it is used for ordinary sends, cold-stake delegation, or node bonding. The wallet can perform that move as part of certain staking/delegation workflows so the user does not have to manually understand every intermediate transaction.</p>
)HTML");
}

QString UnlockGuide()
{
    return QObject::tr(R"HTML(
<h2>Unlock modes in practical terms</h2>
<p><b>Locked</b> means the wallet cannot sign transactions. It can display balances and receive funds, but it cannot stake or create claim/migration transactions.</p>
<p><b>Legacy staking-only unlock</b> is the conservative mode for ordinary PoS staking. It is useful when the user wants this node to stake without leaving the wallet able to spend. It does not sign quantum migration, PoW claim, PoS signal, cold-stake setup, or RGB/EUTXO transactions.</p>
<p><b>Quantum and Legacy Staking unlock</b> is a normal unlock. Use it when the wallet needs to sign active transition transactions. This includes Gold Rush PoS signal publication, PoW claim submission, quantum reward movement, migration, cold-stake delegation, node bonding, and demurrage attestations.</p>
<p><b>Rule:</b> if the action changes where coins are spendable, creates a new quantum state, or anchors a claim, it needs normal unlock.</p>
)HTML");
}

QString ColdStakeGuide()
{
    return QObject::tr(R"HTML(
<h2>Cold staking, local staking, and running a node</h2>
<p>Cold staking separates <b>ownership</b> from <b>staking operation</b>. The owner key controls the principal. The staker/node key helps produce blocks. A properly formed cold-stake delegation lets the node stake but not steal the delegated principal.</p>

<h3>Three user roles</h3>
<ul>
<li><b>Stake your own coins:</b> one wallet owns and stakes its own quantum coins. This is simplest for users who keep the node online.</li>
<li><b>Run a node:</b> this wallet creates a fixed 30-day node bond and publishes a staking public key. Delegators can select it after confirmations and registry discovery.</li>
<li><b>Delegate coins:</b> the owner wallet selects a verified node, creates a cold-stake delegation address, and funds it. The owner retains spend authority.</li>
</ul>

<h3>Operator example</h3>
<p>A user wants to operate a staking node. They open Cold Staking, create a node key, fund the 30-day node bond, wait for normal confirmations, and keep the node online. The node then appears in the verified registry. Delegators can select it from a drop-down instead of typing a raw key.</p>

<h3>Delegator example</h3>
<p>A user wants another node to stake for them. They select a verified node from the list, create a delegation deposit address, choose an amount, and click Delegate coins. The wallet signs a transaction that sends the selected quantum value into the cold-stake contract. The selected node can stake it, but the owner wallet remains the spend authority.</p>

<h3>Unstaking example</h3>
<p>If the user stops a delegation, the wallet owner-spends the delegation back to a fresh wallet-backed quantum address when the selected output is spendable. If a bonded output is still in its unbonding period, the wallet explains the unlock height instead of silently failing.</p>

<h3>Gold Rush reward handling inside cold staking</h3>
<p>If the user tries to delegate Gold Rush reward coins that still need the required first move, the wallet should move those rewards to a fresh quantum address first, then continue with the delegation when possible. The user should see both steps in the status text so the process is understandable rather than looking like a failure.</p>
)HTML");
}

QString MigrationGuide()
{
    return QObject::tr(R"HTML(
<h2>Migration and final lockout</h2>
<p>Migration is the process of moving control from legacy spend paths to quantum-resistant witness programs. During the transition, upgraded wallets track both legacy ledger activity and quantum state so users can prepare without abruptly breaking ordinary chain use.</p>
<p><b>Legacy left</b> means value is still controlled by old signatures. <b>Quantum held</b> means value is already controlled by quantum keys. <b>Gold Rush to move</b> means reward outputs were credited but still need the required first movement to a fresh quantum address before normal use.</p>

<h3>Simple migration example</h3>
<ol>
<li>A wallet has 50,000 legacy BLK.</li>
<li>The user clicks Move legacy to quantum.</li>
<li>The wallet creates a fresh quantum address and sends the spendable legacy value there.</li>
<li>After confirmation, the Account tab shows that value under a quantum address.</li>
<li>The user backs up the wallet because the new quantum key matters.</li>
</ol>

<h3>Gold Rush reward example</h3>
<ol>
<li>The wallet receives a PoW or PoS Gold Rush quantum reward.</li>
<li>The transaction list labels it as <b>PoW - Quantum Claim</b> or <b>PoS - Quantum Stake</b>.</li>
<li>The reward must be moved once to a fresh quantum address before ordinary use.</li>
<li>After the move, the wallet can use it for a send, local staking, node bond, or delegation.</li>
</ol>
)HTML");
}

QString DemurrageGuide()
{
    return QObject::tr(R"HTML(
<h2>Demurrage and liveness attestations</h2>
<p>Demurrage is a post-migration inactivity rule for direct quantum outputs. It is not intended to surprise users during Gold Rush. It becomes relevant after the quantum migration schedule has reached the phase where inactive quantum keys need periodic proof of maintenance.</p>
<p>A liveness attestation is a small fee-paying transaction that proves the controlling quantum key is still actively managed. The wallet can create attestations for wallet-backed quantum addresses.</p>
<p><b>Example:</b> a user has a direct quantum output that has not moved for many months. Before it begins to lose effective value, the wallet can send an attestation for that key. The Account tab shows whether outputs are decaying, locked, or protected by a recent attestation.</p>
<p>Cold-stake outputs are treated differently because they are already in an active staking commitment. Treasury and other protected categories follow their own consensus exemptions.</p>
)HTML");
}

QString AssetsGuide()
{
    return QObject::tr(R"HTML(
<h2>RGB and EUTXO state</h2>
<p>RGB and EUTXO features add advanced wallet-visible state beyond ordinary BLK balances.</p>
<ul>
<li><b>RGB</b> tracks client-side asset contracts, assignments, and proofs. The wallet can show known assets, balances, contracts, and assignment counts.</li>
<li><b>EUTXO</b> tracks extended UTXO commitments such as datum and validator data. It is a foundation for contract-like state transitions.</li>
</ul>
<p><b>Important:</b> seeing an RGB asset or EUTXO state in the wallet is not the same thing as completing a transfer. Advanced state transitions need the matching proof/consignment/validator workflow. Until a guided flow says the transfer is accepted and confirmed, treat the table as inspection data.</p>
<p><b>Example:</b> an RGB asset may show a balance and a contract id. The contract id identifies the asset. The assignments show where wallet-known units are anchored. A future guided transfer flow should build and verify the consignment before the sender considers the transfer complete.</p>
)HTML");
}

QString AccountSpecificGuide()
{
    return QObject::tr(R"HTML(
<h2>How to use the Account tab</h2>
<p>The Account tab is a coin-location view. It answers: which addresses does this wallet control, how much value is under each address, what family of spend path does each output use, and which outputs need special attention.</p>
<h3>Reading the tree</h3>
<ul>
<li>Top-level rows are wallet addresses or script groups.</li>
<li>Child rows are individual UTXOs under that address.</li>
<li>The Type column tells you whether the output is legacy, direct quantum, cold-stake, EUTXO, or other.</li>
<li>The Amount column on an address row is the sum of its visible child outputs.</li>
<li>The Confirmations column is the lowest child depth for that address, so it is conservative.</li>
</ul>
<h3>Practical examples</h3>
<p><b>Finding spendable legacy BLK:</b> choose the Legacy filter. These are the coins the wallet can use for ordinary legacy sends, control transaction fees, and legacy staking.</p>
<p><b>Finding quantum reward coins:</b> choose the Quantum filter and look for notes about Gold Rush rewards needing a first move. Move those rewards before using them for delegation, node bonds, or ordinary sends.</p>
<p><b>Checking cold-stake deposits:</b> choose Cold stake. Those rows represent funds in cold-staking contracts. They may be owner-spendable by this wallet, stakable by a selected node, or both, depending on the contract.</p>
<p><b>Auditing advanced assets:</b> use the RGB/EUTXO summary cards and filters to see whether this wallet has contract state attached to specific outputs. Avoid spending protected asset/state outputs as ordinary BLK unless the wallet's guided workflow says that is intended.</p>
)HTML");
}

bool HasAny(const QString& title, std::initializer_list<const char*> needles)
{
    for (const char* needle : needles) {
        if (title.contains(QObject::tr(needle), Qt::CaseInsensitive) ||
            title.contains(QString::fromLatin1(needle), Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

} // namespace

namespace QuantumGuides {

QString DetailedAppendixForTitle(const QString& title)
{
    QString html = CommonGuide();
    if (HasAny(title, {"Proof-of-Stake", "PoS", "Stake"})) html += PosGuide();
    if (HasAny(title, {"Proof-of-Work", "PoW", "payout"})) html += PowGuide();
    if (HasAny(title, {"Unlock"})) html += UnlockGuide();
    if (HasAny(title, {"Cold", "Delegate", "node", "own quantum"})) html += ColdStakeGuide();
    if (HasAny(title, {"migration", "Gold Rush rewards"})) html += MigrationGuide();
    if (HasAny(title, {"Demurrage", "liveness"})) html += DemurrageGuide();
    if (HasAny(title, {"RGB", "EUTXO", "asset"})) html += AssetsGuide();
    return html;
}

QString AccountGuide()
{
    return AccountSpecificGuide() + CommonGuide() + MigrationGuide() + DemurrageGuide() + AssetsGuide();
}

} // namespace QuantumGuides
