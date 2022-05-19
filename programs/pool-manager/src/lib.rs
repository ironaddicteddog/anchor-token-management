use anchor_lang::prelude::*;
use anchor_spl::token::{Token, Mint, TokenAccount};
use std::convert::Into;

declare_id!("4SnEq68n38cyAbyW3RAV6w43ebpJDvmweHfnK5hNrFKV");

#[program]
mod pool_manager {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, _pool_manager_nonce: u64) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn set_locker_manager(
        ctx: Context<Auth>,
        _pool_manager_nonce: u64,
        locker_manager_program: Pubkey,
    ) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn set_authority(ctx: Context<Auth>, _pool_manager_nonce: u64, new_authority: Pubkey) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn create_pool(
        ctx: Context<CreatePool>,
        mint: Pubkey,
        authority: Pubkey,
        nonce: u8,
        withdrawal_timelock: i64,
        stake_rate: u64,
        reward_q_len: u32,
    ) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn update_pool(
        ctx: Context<UpdatePool>,
        new_authority: Option<Pubkey>,
        withdrawal_timelock: Option<i64>,
    ) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn create_staker(ctx: Context<CreateStaker>, nonce: u8) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn update_staker(ctx: Context<UpdateStaker>, metadata: Option<Pubkey>) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn update_staker_vault(ctx: Context<UpdateStakerVault>, nonce: u8) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn update_staker_vault_locked(
        ctx: Context<UpdateStakerVaultLocked>,
        nonce: u8,
    ) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn stake(ctx: Context<Stake>, pool_token_amount: u64) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn start_unstake(ctx: Context<StartUnstake>, pool_token_amount: u64, locked: bool) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn end_unstake(ctx: Context<EndUnstake>) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn drop_reward(
        ctx: Context<DropReward>,
        kind: RewarderKind,
        total: u64,
        expiry_ts: i64,
        expiry_receiver: Pubkey,
        nonce: u8,
    ) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn claim_reward(ctx: Context<ClaimReward>) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn claim_reward_to_locker<'a, 'b, 'c, 'info>(
        ctx: Context<'a, 'b, 'c, 'info, ClaimRewardToLocker<'info>>,
        _pool_manager_nonce: u64,
        nonce: u8,
    ) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn expire_reward(ctx: Context<ExpireReward>) -> Result<()> {
        // TODO

        Ok(())
    }
}

#[account]
pub struct PoolManagerInfo {
    pub authority: Pubkey,
    pub locker_manager_program: Pubkey,
    pub reward_keeper_program: Pubkey,
}

#[derive(Accounts)]
pub struct CreatePool<'info> {
    pool: Box<Account<'info, Pool>>,
    reward_event_q: Box<Account<'info, RewardQueue>>,
    pool_mint: Account<'info, Mint>,
    rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct UpdatePool<'info> {
    pool: Box<Account<'info, Pool>>,
    authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct CreateStaker<'info> {
    pool: Box<Account<'info, Pool>>,
    staker: Box<Account<'info, Staker>>,
    beneficiary: Signer<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    staker_vault_authority: AccountInfo<'info>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct UpdateStakerVault<'info> {
    pool: Box<Account<'info, Pool>>,
    staker: Box<Account<'info, Staker>>,
    staker_vault: StakerVaultAccounts<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    staker_vault_authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UpdateStakerVaultLocked<'info> {
    pool: Box<Account<'info, Pool>>,
    staker: Box<Account<'info, Staker>>,
    staker_vault_locked: StakerVaultAccounts<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    staker_vault_authority: AccountInfo<'info>,
}

#[derive(Accounts, Clone)]
pub struct StakerVaultAccounts<'info> {
    vault: Box<Account<'info, TokenAccount>>,
    vault_staked: Box<Account<'info, TokenAccount>>,
    vault_pending_withdrawal: Box<Account<'info, TokenAccount>>,
    vault_pool_token: Box<Account<'info, TokenAccount>>,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    pub authority: Signer<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub locker_manager_program: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub reward_keeper_program: AccountInfo<'info>,
    pub pool_manager_info: Box<Account<'info, PoolManagerInfo>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Auth<'info> {
    pub authority: Signer<'info>,
    pub pool_manager_info: Box<Account<'info, PoolManagerInfo>>,
}

#[derive(Accounts)]
pub struct UpdateStaker<'info> {
    staker: Box<Account<'info, Staker>>,
    beneficiary: Signer<'info>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    staker: Box<Account<'info, Staker>>,
    beneficiary: Signer<'info>,
    vault: Account<'info, TokenAccount>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    depositor: AccountInfo<'info>,
    depositor_authority: Signer<'info>,
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Stake<'info> {
    pool: Box<Account<'info, Pool>>,
    reward_event_q: Box<Account<'info, RewardQueue>>,
    pool_mint: Box<Account<'info, Mint>>,
    staker: Box<Account<'info, Staker>>,
    beneficiary: Signer<'info>,
    staker_vault: StakerVaultAccounts<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    staker_vault_authority: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pool_mint_authority: AccountInfo<'info>,
    clock: Sysvar<'info, Clock>,
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct StartUnstake<'info> {
    pool: Box<Account<'info, Pool>>,
    reward_event_q: Box<Account<'info, RewardQueue>>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pool_mint: AccountInfo<'info>,
    pending_withdrawal: Box<Account<'info, PendingWithdrawal>>,
    staker: Box<Account<'info, Staker>>,
    beneficiary: Signer<'info>,
    staker_vault: StakerVaultAccounts<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    staker_vault_authority: AccountInfo<'info>,
    token_program: Program<'info, Token>,
    clock: Sysvar<'info, Clock>,
    rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct EndUnstake<'info> {
    pool: Box<Account<'info, Pool>>,
    staker: Box<Account<'info, Staker>>,
    beneficiary: Signer<'info>,
    pending_withdrawal: Box<Account<'info, PendingWithdrawal>>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    vault: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    vault_pending_withdrawal: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    staker_vault_authority: AccountInfo<'info>,
    clock: Sysvar<'info, Clock>,
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pool: Box<Account<'info, Pool>>,
    staker: Box<Account<'info, Staker>>,
    beneficiary: Signer<'info>,
    vault: Account<'info, TokenAccount>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    staker_vault_authority: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    depositor: AccountInfo<'info>,
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct DropReward<'info> {
    pool: Box<Account<'info, Pool>>,
    reward_event_q: Box<Account<'info, RewardQueue>>,
    pool_mint: Account<'info, Mint>,
    rewarder: Box<Account<'info, Rewarder>>,
    rewarder_vault: Account<'info, TokenAccount>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    depositor: AccountInfo<'info>,
    depositor_authority: Signer<'info>,
    token_program: Program<'info, Token>,
    clock: Sysvar<'info, Clock>,
    rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct ClaimReward<'info> {
    common: ClaimRewardCommon<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    to: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ClaimRewardToLocker<'info> {
    common: ClaimRewardCommon<'info>,
    pool_manager_info: Box<Account<'info, PoolManagerInfo>>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    locker_manager_program: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    reward_keeper_program: AccountInfo<'info>,
}

// Accounts common to both claim reward locked/unlocked instructions.
#[derive(Accounts)]
pub struct ClaimRewardCommon<'info> {
    pool: Box<Account<'info, Pool>>,
    staker: Box<Account<'info, Staker>>,
    beneficiary: Signer<'info>,
    staker_vault_pool_token: Account<'info, TokenAccount>,
    staker_vault_locked_pool_token: Account<'info, TokenAccount>,
    rewarder: Box<Account<'info, Rewarder>>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    vault: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    rewarder_vault_authority: AccountInfo<'info>,
    token_program: Program<'info, Token>,
    clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
pub struct ExpireReward<'info> {
    pool: Box<Account<'info, Pool>>,
    rewarder: Box<Account<'info, Rewarder>>,
    vault: Account<'info, TokenAccount>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    rewarder_vault_authority: AccountInfo<'info>,
    expiry_receiver: Signer<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    expiry_receiver_token: AccountInfo<'info>,
    token_program: Program<'info, Token>,
    clock: Sysvar<'info, Clock>,
}

#[account]
pub struct Pool {
    pub authority: Pubkey,
    pub nonce: u8,
    pub withdrawal_timelock: i64,
    pub reward_event_q: Pubkey,
    pub mint: Pubkey,
    pub pool_mint: Pubkey,
    pub stake_rate: u64,
}

#[account]
pub struct Staker {
    pub pool: Pubkey,
    pub beneficiary: Pubkey,
    pub metadata: Pubkey,
    pub staker_vault: StakerVault,
    pub staker_vault_locked: StakerVault,
    pub rewards_cursor: u32,
    pub last_stake_ts: i64,
    pub nonce: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Default, Debug, Clone, PartialEq)]
pub struct StakerVault {
    pub vault: Pubkey,
    pub vault_staked: Pubkey,
    pub vault_pending_withdrawal: Pubkey,
    pub vault_pool_token: Pubkey,
}

#[account]
pub struct PendingWithdrawal {
    pub pool: Pubkey,
    pub staker: Pubkey,
    pub burned: bool,
    pub pool_mint: Pubkey,
    pub start_ts: i64,
    pub end_ts: i64,
    pub amount: u64,
    pub locked: bool,
}

#[account]
pub struct RewardQueue {
    head: u32,
    tail: u32,
    events: Vec<RewardEvent>,
}

#[derive(Default, Clone, Copy, Debug, AnchorSerialize, AnchorDeserialize)]
pub struct RewardEvent {
    rewarder: Pubkey,
    ts: i64,
    locked: bool,
}

#[account]
pub struct Rewarder {
    pub pool: Pubkey,
    pub vault: Pubkey,
    pub mint: Pubkey,
    pub nonce: u8,
    pub pool_token_supply: u64,
    pub reward_event_q_cursor: u32,
    pub start_ts: i64,
    pub expiry_ts: i64,
    pub expiry_receiver: Pubkey,
    pub from: Pubkey,
    pub total: u64,
    pub expired: bool,
    pub kind: RewarderKind,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq)]
pub enum RewarderKind {
    Unlocked,
    Locked {
        start_ts: i64,
        end_ts: i64,
        period_count: u64,
    },
}
