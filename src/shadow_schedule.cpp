#include <shadow.h>

#include <consensus/params.h>

#include <algorithm>

// Gold Rush schedule heights (mainnet defaults; regtest-overridable, see header).
int SHADOW_WHITELIST_HEIGHT = 5920000;
int SHADOW_REWARD_START_HEIGHT = 5950000;
int SHADOW_GOLD_RUSH_BLOCKS = (180 * 24 * 60 * 60) / 64;
int SHADOW_PHASE1_END_HEIGHT = SHADOW_REWARD_START_HEIGHT + 237599;
int SHADOW_REWARD_END_HEIGHT = SHADOW_REWARD_START_HEIGHT + SHADOW_GOLD_RUSH_BLOCKS - 1;

void SetShadowTestSchedule(int whitelist_height, int reward_start_height, int gold_rush_blocks)
{
    if (whitelist_height < 0) whitelist_height = 0;
    if (reward_start_height <= whitelist_height) reward_start_height = whitelist_height + 1;
    if (gold_rush_blocks < 1) gold_rush_blocks = 1;
    SHADOW_WHITELIST_HEIGHT = whitelist_height;
    SHADOW_REWARD_START_HEIGHT = reward_start_height;
    SHADOW_GOLD_RUSH_BLOCKS = gold_rush_blocks;
    SHADOW_PHASE1_END_HEIGHT = SHADOW_REWARD_START_HEIGHT + std::min(gold_rush_blocks - 1, 237599);
    SHADOW_REWARD_END_HEIGHT = SHADOW_REWARD_START_HEIGHT + gold_rush_blocks - 1;
}

void SetShadowRegtestSchedule(int whitelist_height, int gold_rush_blocks)
{
    SetShadowTestSchedule(whitelist_height, whitelist_height + 1, gold_rush_blocks);
}

bool IsQuantumWitnessSpendActive(const Consensus::Params& consensus, int64_t nMedianTimePast, int nSpendHeight)
{
    if (consensus.IsQuantumSpendEnforcementActive(nMedianTimePast)) return true;
    return consensus.IsProtocolV4(nMedianTimePast) && nSpendHeight >= SHADOW_REWARD_START_HEIGHT;
}
