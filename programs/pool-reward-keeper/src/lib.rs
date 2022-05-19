use anchor_lang::prelude::*;
use anchor_spl::token::TokenAccount;
use std::convert::Into;

declare_id!("9dfVBXMVk4GmmkVvZuY3z5cqAcWn96N7fwBVuVbhpfJd");

#[program]
mod pool_reward_keeper {
    use super::*;

    pub fn check_releasability(
        ctx: Context<CheckReleasibility>,
        locker: Locker,
        staker_data: StakerData,
    ) -> Result<()> {
        // TODO

        Ok(())
    }
}

#[derive(Accounts)]
pub struct CheckReleasibility<'info> {
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub staker: AccountInfo<'info>,
    pub staker_vault_pool_token: Account<'info, TokenAccount>,
    pub staker_vault_locked_pool_token: Account<'info, TokenAccount>,
}

// Staker Data (Part)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct StakerData {
    pub pool: Pubkey,
    pub beneficiary: Pubkey,
    pub metadata: Pubkey,
    pub staker_vault_pool_token: Pubkey,
    pub staker_vault_locked_pool_token: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize, Default, Debug, Clone, PartialEq)]
pub struct StakerVault {
    pub vault: Pubkey,
    pub vault_staked: Pubkey,
    pub vault_pending_withdrawal: Pubkey,
    pub vault_pool_token: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct Locker {
    pub beneficiary: Pubkey,
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub grantor: Pubkey,
    pub current_balance: u64,
    pub start_balance: u64,
    pub created_ts: i64,
    pub start_ts: i64,
    pub end_ts: i64,
    pub period_count: u64,
    pub whitelist_owned: u64,
    pub nonce: u8,
    pub reward_keeper: Option<PoolRewardKeeper>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct PoolRewardKeeper {
    pub program: Pubkey,
    pub metadata: Pubkey,
}
