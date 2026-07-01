#include <shadow.h>

#include <consensus/params.h>

// Gold Rush schedule heights (mainnet defaults; regtest-overridable, see header).
int SHADOW_WHITELIST_HEIGHT = 5920000;
int SHADOW_REWARD_START_HEIGHT = 5950000;
int SHADOW_GOLD_RUSH_BLOCKS = (180 * 24 * 60 * 60) / 64;
int SHADOW_PHASE1_END_HEIGHT = SHADOW_REWARD_START_HEIGHT + 237599;
int SHADOW_REWARD_END_HEIGHT = SHADOW_REWARD_START_HEIGHT + SHADOW_GOLD_RUSH_BLOCKS - 1;

void SetShadowRegtestSchedule(int whitelist_height, int gold_rush_blocks)
{
    if (whitelist_height < 0) whitelist_height = 0;
    if (gold_rush_blocks < 1) gold_rush_blocks = 1;
    SHADOW_WHITELIST_HEIGHT = whitelist_height;
    SHADOW_REWARD_START_HEIGHT = whitelist_height + 1;
    SHADOW_GOLD_RUSH_BLOCKS = gold_rush_blocks;
    // Keep the whole regtest window in phase 1 (halving schedule) for simplicity.
    SHADOW_PHASE1_END_HEIGHT = SHADOW_REWARD_START_HEIGHT + gold_rush_blocks - 1;
    SHADOW_REWARD_END_HEIGHT = SHADOW_REWARD_START_HEIGHT + gold_rush_blocks - 1;
}

bool IsQuantumWitnessSpendActive(const Consensus::Params& consensus, int64_t nMedianTimePast, int nSpendHeight)
{
    if (consensus.IsQuantumSpendEnforcementActive(nMedianTimePast)) return true;
    return consensus.IsProtocolV4(nMedianTimePast) && nSpendHeight >= SHADOW_REWARD_START_HEIGHT;
}
