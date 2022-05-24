use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount, Transfer, transfer};
use pool_reward_keeper::{PoolRewardKeeper, StakerData, CheckReleasibility, Locker as KeptLocker, cpi as PoolRewardKeeperCPI};
use std::collections::BTreeMap;

mod calculator;

declare_id!("7LGfdonJVsPaB3LzfVvDGE9jwHseFVDkg8ZrJfwhiAzw");

#[program]
pub mod locker_manager {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, _locker_manager_nonce: u64) -> Result<()> {
        ctx.accounts.locker_manager_info.authority = *ctx.accounts.authority.key;

        Ok(())
    }

    #[access_control(authorize(&ctx))]
    pub fn set_authority(ctx: Context<Auth>, _locker_manager_nonce: u64, new_authority: Pubkey) -> Result<()> {
        ctx.accounts.locker_manager_info.authority = new_authority;

        Ok(())
    }

    #[access_control(CreateLocker::accounts(&ctx, nonce))]
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
        if deposit_amount == 0 {
            return Err(ErrorCode::InvalidDepositAmount.into());
        }
        if !is_valid_schedule(start_ts, end_ts, period_count) {
            return Err(ErrorCode::InvalidSchedule.into());
        }
        let locker = &mut ctx.accounts.locker;
        locker.beneficiary = beneficiary;
        locker.mint = ctx.accounts.vault.mint;
        locker.vault = *ctx.accounts.vault.to_account_info().key;
        locker.period_count = period_count;
        locker.start_balance = deposit_amount;
        locker.end_ts = end_ts;
        locker.start_ts = start_ts;
        locker.created_ts = ctx.accounts.clock.unix_timestamp;
        locker.current_balance = deposit_amount;
        locker.whitelist_owned = 0;
        locker.grantor = *ctx.accounts.depositor_authority.key;
        locker.nonce = nonce;
        locker.reward_keeper = reward_kepper;

        transfer(ctx.accounts.into(), deposit_amount)?;

        Ok(())
    }

    #[access_control(check_releasability(&ctx))]
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let available_for_withdrawal = calculator::available_for_withdrawal(
            &ctx.accounts.locker,
            ctx.accounts.clock.unix_timestamp,
        );

        // Has the given amount vested?
        if amount > available_for_withdrawal
        {
            return Err(ErrorCode::InsufficientWithdrawalBalance.into());
        }

        // Transfer funds out.
        let seeds = &[
            ctx.accounts.locker.to_account_info().key.as_ref(),
            &[ctx.accounts.locker.nonce],
        ];
        let signer = &[&seeds[..]];
        let cpi_ctx = CpiContext::from(&*ctx.accounts).with_signer(signer);
        transfer(cpi_ctx, amount)?;

        // Bookeeping.
        let locker = &mut ctx.accounts.locker;
        locker.current_balance -= amount;

        Ok(())
    }

    pub fn available_for_withdrawal(ctx: Context<AvailableForWithdrawal>) -> Result<()> {
        let available = calculator::available_for_withdrawal(
            &ctx.accounts.locker,
            ctx.accounts.clock.unix_timestamp,
        );
        // Log as string so that JS can read as a BN.
        msg!(&format!("{{ \"result\": \"{}\" }}", available));

        Ok(())
    }
}

#[account]
pub struct LockerManagerInfo {
    pub authority: Pubkey,
}

#[derive(Accounts)]
#[instruction(locker_manager_nonce: u64)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        init,
        seeds = [b"locker-manager".as_ref(), &locker_manager_nonce.to_le_bytes()],
        bump,
        payer = authority,
        space = 8 + 32 + 32
    )]
    pub locker_manager_info: Box<Account<'info, LockerManagerInfo>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(locker_manager_nonce: u64)]
pub struct Auth<'info> {
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"locker-manager".as_ref(), &locker_manager_nonce.to_le_bytes()],
        bump
    )]
    pub locker_manager_info: Box<Account<'info, LockerManagerInfo>>,
}

#[derive(Accounts)]
pub struct CreateLocker<'info> {
    #[account(zero)]
    pub locker: Box<Account<'info, Locker>>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub depositor: AccountInfo<'info>,
    pub depositor_authority: Signer<'info>,
    // Misc.
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
    pub clock: Sysvar<'info, Clock>,
}

impl<'info> CreateLocker<'info> {
    fn accounts(ctx: &Context<CreateLocker>, nonce: u8) -> Result<()> {
        let locker_vault_authority = Pubkey::create_program_address(
            &[
                ctx.accounts.locker.to_account_info().key.as_ref(),
                &[nonce],
            ],
            ctx.program_id,
        )
        .map_err(|_| ErrorCode::InvalidProgramAddress)?;
        if ctx.accounts.vault.owner != locker_vault_authority {
            return Err(ErrorCode::InvalidVaultOwner)?;
        }

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = beneficiary, has_one = vault)]
    locker: Box<Account<'info, Locker>>,
    beneficiary: Signer<'info>,
    #[account(mut)]
    vault: Account<'info, TokenAccount>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(seeds = [locker.to_account_info().key.as_ref()], bump = locker.nonce)]
    locker_vault_authority: AccountInfo<'info>,
    #[account(mut)]
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

impl<'a, 'b, 'c, 'info> From<&mut CreateLocker<'info>>
    for CpiContext<'a, 'b, 'c, 'info, Transfer<'info>>
{
    fn from(accounts: &mut CreateLocker<'info>) -> CpiContext<'a, 'b, 'c, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: accounts.depositor.clone(),
            to: accounts.vault.to_account_info(),
            authority: accounts.depositor_authority.to_account_info().clone(),
        };
        let cpi_program = accounts.token_program.to_account_info().clone();
        CpiContext::new(cpi_program, cpi_accounts)
    }
}

impl<'a, 'b, 'c, 'info> From<&Withdraw<'info>> for CpiContext<'a, 'b, 'c, 'info, Transfer<'info>> {
    fn from(accounts: &Withdraw<'info>) -> CpiContext<'a, 'b, 'c, 'info, Transfer<'info>> {
        let cpi_accounts = Transfer {
            from: accounts.vault.to_account_info(),
            to: accounts.token.to_account_info(),
            authority: accounts.locker_vault_authority.to_account_info(),
        };
        let cpi_program = accounts.token_program.to_account_info();
        CpiContext::new(cpi_program, cpi_accounts)
    }
}

pub fn is_valid_schedule(start_ts: i64, end_ts: i64, period_count: u64) -> bool {
    if end_ts <= start_ts {
        return false;
    }
    if period_count > (end_ts - start_ts) as u64 {
        return false;
    }
    if period_count == 0 {
        return false;
    }
    true
}

fn authorize(ctx: &Context<Auth>) -> Result<()> {
    if ctx.accounts.locker_manager_info.authority != *ctx.accounts.authority.key {
        return Err(ErrorCode::Unauthorized.into());
    }
    Ok(())
}

fn check_releasability(ctx: &Context<Withdraw>) -> Result<()> {
    if let Some(reward_keeper) = &ctx.accounts.locker.reward_keeper {
        let cpi_program = {
            let p = ctx.remaining_accounts[0].clone();
            if p.key != &reward_keeper.program {
                return Err(ErrorCode::InvalidLockKeeper.into());
            }
            p
        };
        let registry_program = ctx.remaining_accounts[1].clone();
        // let cpi_accounts = ctx.remaining_accounts.to_vec()[1..].to_vec();
        let mut bumps = BTreeMap::new();
        let cpi_accounts = {
            let accs = CheckReleasibility::try_accounts(
                // cpi_program.key,
                registry_program.key,
                &mut &ctx.remaining_accounts.to_vec()[2..=4],
                &[],
                &mut bumps,
            )?;
            PoolRewardKeeperCPI::accounts::CheckReleasibility {
                staker: accs.staker.to_account_info(),
                staker_vault_pool_token: accs.staker_vault_pool_token.to_account_info(),
                staker_vault_locked_pool_token: accs.staker_vault_locked_pool_token.to_account_info(),
            }
        };
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        let locker_account = (*ctx.accounts.locker).clone();
        let reward_keeper = PoolRewardKeeper {
            program: locker_account.reward_keeper.as_ref().unwrap().program,
            metadata: locker_account.reward_keeper.as_ref().unwrap().metadata,
        };
        let locker = KeptLocker {
            beneficiary: locker_account.beneficiary,
            mint: locker_account.mint,
            vault: locker_account.vault,
            grantor: locker_account.grantor,
            current_balance: locker_account.current_balance,
            start_balance: locker_account.start_balance,
            created_ts: locker_account.created_ts,
            start_ts: locker_account.start_ts,
            end_ts: locker_account.end_ts,
            period_count: locker_account.period_count,
            whitelist_owned: locker_account.whitelist_owned,
            nonce: locker_account.nonce,
            reward_keeper: Some(reward_keeper),
        };

        let staker_data = StakerData {
            pool: ctx.remaining_accounts[5].key(),
            beneficiary: ctx.remaining_accounts[6].key(),
            metadata: ctx.remaining_accounts[7].key(),
            staker_vault_pool_token: ctx.remaining_accounts[8].key(),
            staker_vault_locked_pool_token: ctx.remaining_accounts[9].key(),
        };

        PoolRewardKeeperCPI::check_releasability(cpi_ctx, locker, staker_data)
            .map_err(|_| ErrorCode::UnreleasedLocker)?;
    }
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Locker end must be greater than the current unix timestamp.")]
    InvalidTimestamp,
    #[msg("The number of locker periods must be greater than zero.")]
    InvalidPeriod,
    #[msg("The locker deposit amount must be greater than zero.")]
    InvalidDepositAmount,
    #[msg("The Whitelist entry is not a valid program address.")]
    InvalidWhitelistEntry,
    #[msg("Invalid program address. Did you provide the correct nonce?")]
    InvalidProgramAddress,
    #[msg("Invalid vault owner.")]
    InvalidVaultOwner,
    #[msg("Vault amount must be zero.")]
    InvalidVaultAmount,
    #[msg("Insufficient withdrawal balance.")]
    InsufficientWithdrawalBalance,
    #[msg("Whitelist is full")]
    WhitelistFull,
    #[msg("Whitelist entry already exists")]
    WhitelistEntryAlreadyExists,
    #[msg("Balance must go up when performing a whitelist deposit")]
    InsufficientWhitelistDepositAmount,
    #[msg("Cannot deposit more than withdrawn")]
    WhitelistDepositOverflow,
    #[msg("Tried to withdraw over the specified limit")]
    WhitelistWithdrawLimit,
    #[msg("Whitelist entry not found.")]
    WhitelistEntryNotFound,
    #[msg("You do not have sufficient permissions to perform this action.")]
    Unauthorized,
    #[msg("You are unable to release projected rewards until unstaking.")]
    UnableToWithdrawWhileStaked,
    #[msg("The given lock keeper doesn't match the locker account.")]
    InvalidLockKeeper,
    #[msg("You have not released this locker account.")]
    UnreleasedLocker,
    #[msg("Invalid locker schedule given.")]
    InvalidSchedule,
}
