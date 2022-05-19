use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

declare_id!("Dmm6ECKRfM5n1jjjH8ktyBZEnCtg7tSZ321MwqYqxi8C");

#[program]
pub mod locker_manager {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, _locker_manager_nonce: u64) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn set_authority(ctx: Context<Auth>, _locker_manager_nonce: u64, new_authority: Pubkey) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn create_locker(
        ctx: Context<CreateLocker>,
        beneficiary: Pubkey,
        deposit_amount: u64,
        nonce: u8,
        start_ts: i64,
        end_ts: i64,
        period_count: u64,
        reward_kepper: Option<RewardKeeper>,
    ) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // TODO

        Ok(())
    }

    pub fn available_for_withdrawal(ctx: Context<AvailableForWithdrawal>) -> Result<()> {
        // TODO

        Ok(())
    }
}

#[account]
pub struct LockerManagerInfo {
    pub authority: Pubkey,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    pub authority: Signer<'info>,
    pub locker_manager_info: Box<Account<'info, LockerManagerInfo>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Auth<'info> {
    pub authority: Signer<'info>,
    pub locker_manager_info: Box<Account<'info, LockerManagerInfo>>,
}

#[derive(Accounts)]
pub struct CreateLocker<'info> {
    pub locker: Box<Account<'info, Locker>>,
    pub vault: Account<'info, TokenAccount>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub depositor: AccountInfo<'info>,
    pub depositor_authority: Signer<'info>,
    // Misc.
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
    pub clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    locker: Box<Account<'info, Locker>>,
    beneficiary: Signer<'info>,
    vault: Account<'info, TokenAccount>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    locker_vault_authority: AccountInfo<'info>,
    token: Account<'info, TokenAccount>,
    token_program: Program<'info, Token>,
    clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
pub struct AvailableForWithdrawal<'info> {
    locker: Box<Account<'info, Locker>>,
    clock: Sysvar<'info, Clock>,
}

#[account]
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
    pub reward_keeper: Option<RewardKeeper>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct RewardKeeper {
    pub program: Pubkey,
    pub metadata: Pubkey,
}
