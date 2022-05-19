use anchor_lang::{
    prelude::*,
    solana_program::{instruction::Instruction, program::invoke_signed},
};
use anchor_spl::token::{Token, TokenAccount, Transfer, transfer};
use pool_reward_keeper::{PoolRewardKeeper, StakerData, CheckReleasibility, Locker as KeptLocker, cpi as PoolRewardKeeperCPI};
use std::collections::BTreeMap;

mod calculator;

declare_id!("7LGfdonJVsPaB3LzfVvDGE9jwHseFVDkg8ZrJfwhiAzw");

#[program]
pub mod locker_manager {
    use super::*;

    pub const WHITELIST_SIZE: usize = 10;

    pub fn initialize(ctx: Context<Initialize>, _locker_manager_nonce: u64) -> Result<()> {
        let mut whitelist = vec![];
        whitelist.resize(WHITELIST_SIZE, Default::default());
        ctx.accounts.locker_manager_info.authority = *ctx.accounts.authority.key;
        ctx.accounts.locker_manager_info.whitelist = whitelist;

        Ok(())
    }

    #[access_control(authorize(&ctx))]
    pub fn add_whitelist(ctx: Context<Auth>, _locker_manager_nonce: u64, entry: WhitelistEntry) -> Result<()> {
        if ctx.accounts.locker_manager_info.whitelist.len() == WHITELIST_SIZE {
            return Err(ErrorCode::WhitelistFull.into());
        }
        if ctx.accounts.locker_manager_info.whitelist.contains(&entry) {
            return Err(ErrorCode::WhitelistEntryAlreadyExists.into());
        }
        ctx.accounts.locker_manager_info.whitelist.push(entry);

        Ok(())
    }

    #[access_control(authorize(&ctx))]
    pub fn remove_whitelist(ctx: Context<Auth>, _locker_manager_nonce: u64, entry: WhitelistEntry) -> Result<()> {
        if !ctx.accounts.locker_manager_info.whitelist.contains(&entry) {
            return Err(ErrorCode::WhitelistEntryNotFound.into());
        }
        ctx.accounts.locker_manager_info.whitelist.retain(|e| e != &entry);

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

    // Sends funds from the locker manager program to a whitelisted program.
    pub fn withdraw_to_whitelist<'a, 'b, 'c, 'info>(
        ctx: Context<'a, 'b, 'c, 'info, WithdrawToWhitelist<'info>>,
        instruction_data: Vec<u8>,
        amount: u64,
    ) -> Result<()> {
        let before_amount = ctx.accounts.transfer.vault.amount;
        whitelist_relay_cpi(
            &ctx.accounts.transfer,
            ctx.remaining_accounts,
            instruction_data,
        )?;
        let after_amount = ctx.accounts.transfer.vault.amount;

        // CPI safety checks.
        let withdraw_amount = before_amount - after_amount;
        if withdraw_amount > amount {
            return Err(ErrorCode::WhitelistWithdrawLimit)?;
        }

        // Bookeeping.
        ctx.accounts.transfer.locker.whitelist_owned += withdraw_amount;

        Ok(())
    }

    // Sends funds from a whitelisted program back to the locker manager program.
    pub fn deposit_from_whitelist<'a, 'b, 'c, 'info>(
        ctx: Context<'a, 'b, 'c, 'info, DepositFromWhitelist<'info>>,
        instruction_data: Vec<u8>,
    ) -> Result<()> {
        let before_amount = ctx.accounts.transfer.vault.amount;
        whitelist_relay_cpi(
            &ctx.accounts.transfer,
            ctx.remaining_accounts,
            instruction_data,
        )?;
        let after_amount = ctx.accounts.transfer.vault.amount;

        // CPI safety checks.
        let deposit_amount = after_amount - before_amount;
        if deposit_amount <= 0 {
            return Err(ErrorCode::InsufficientWhitelistDepositAmount)?;
        }
        if deposit_amount > ctx.accounts.transfer.locker.whitelist_owned {
            return Err(ErrorCode::WhitelistDepositOverflow)?;
        }

        // Bookkeeping.
        ctx.accounts.transfer.locker.whitelist_owned -= deposit_amount;

        Ok(())
    }

    // Convenience function for UI's to calculate the withdrawable amount.
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
    /// The key with the ability to change the whitelist.
    pub authority: Pubkey,
    /// List of programs locked tokens can be sent to. These programs
    /// are completely trusted to maintain the locked property.
    pub whitelist: Vec<WhitelistEntry>,
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
        space = 8 + 32 + 32 * WHITELIST_SIZE + 4
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
    // Locker.
    #[account(zero)]
    pub locker: Box<Account<'info, Locker>>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    // Depositor.
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

// All accounts not included here, i.e., the "remaining accounts" should be
// ordered according to the release interface.
#[derive(Accounts)]
pub struct Withdraw<'info> {
    // Locker.
    #[account(mut, has_one = beneficiary, has_one = vault)]
    locker: Box<Account<'info, Locker>>,
    beneficiary: Signer<'info>,
    #[account(mut)]
    vault: Account<'info, TokenAccount>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(seeds = [locker.to_account_info().key.as_ref()], bump = locker.nonce)]
    locker_vault_authority: AccountInfo<'info>,
    // Withdraw receiving target.
    #[account(mut)]
    token: Account<'info, TokenAccount>,
    // Misc.
    token_program: Program<'info, Token>,
    clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
pub struct WithdrawToWhitelist<'info> {
    transfer: TransferToWhitelist<'info>,
}

#[derive(Accounts)]
pub struct DepositFromWhitelist<'info> {
    transfer: TransferToWhitelist<'info>,
}

#[derive(Accounts)]
#[instruction(locker_manager_nonce: u64)]
pub struct TransferToWhitelist<'info> {
    #[account(
        seeds = [b"locker-manager".as_ref(), &locker_manager_nonce.to_le_bytes()],
        bump
    )]
    locker_manager_info: Box<Account<'info, LockerManagerInfo>>,
    beneficiary: Signer<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    whitelisted_program: AccountInfo<'info>,
    // Whitelist interface.
    #[account(mut, has_one = beneficiary, has_one = vault)]
    locker: Box<Account<'info, Locker>>,
    #[account(mut, constraint = &vault.owner == locker_vault_authority.key)]
    vault: Account<'info, TokenAccount>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(seeds = [locker.to_account_info().key.as_ref()], bump = locker.nonce)]
    locker_vault_authority: AccountInfo<'info>,
    token_program: Program<'info, Token>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    whitelisted_program_vault: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    whitelisted_program_vault_authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct AvailableForWithdrawal<'info> {
    locker: Box<Account<'info, Locker>>,
    clock: Sysvar<'info, Clock>,
}

#[account]
pub struct Locker {
    /// The owner of this Locker account.
    pub beneficiary: Pubkey,
    /// The mint of the SPL token locked up.
    pub mint: Pubkey,
    /// Address of the account's token vault.
    pub vault: Pubkey,
    /// The owner of the token account funding this account.
    pub grantor: Pubkey,
    /// The current balance of this locker account. All
    /// withdrawals will deduct this balance.
    pub current_balance: u64,
    /// The starting balance of this locker account, i.e., how much was
    /// originally deposited.
    pub start_balance: u64,
    /// The unix timestamp at which this locker account was created.
    pub created_ts: i64,
    /// The time at which locker begins.
    pub start_ts: i64,
    /// The time at which all tokens are vested.
    pub end_ts: i64,
    /// The number of times locker will occur. For example, if locker
    /// is once a year over seven years, this will be 7.
    pub period_count: u64,
    /// The amount of tokens in custody of whitelisted programs.
    pub whitelist_owned: u64,
    /// Signer nonce.
    pub nonce: u8,
    /// The program that determines when the locked account is **realeased**.
    /// In addition to the locker schedule, the program provides the ability
    /// for applications to determine when locked tokens are considered earned.
    /// For example, when earning locked tokens via the staking program, one
    /// cannot receive the tokens until unstaking. As a result, if one never
    /// unstakes, one would never actually receive the locked tokens.
    pub reward_keeper: Option<RewardKeeper>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct RewardKeeper {
    /// Program to invoke to check a realization condition. This program must
    /// implement the `ReleaseLock` trait.
    pub program: Pubkey,
    /// Address of an arbitrary piece of metadata interpretable by the realizor
    /// program. For example, when a locker account is allocated, the program
    /// can define its realization condition as a function of some account
    /// state. The metadata is the address of that account.
    ///
    /// In the case of staking, the metadata is a `Member` account address. When
    /// the realization condition is checked, the staking program will check the
    /// `Member` account defined by the `metadata` has no staked tokens.
    pub metadata: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize, PartialEq, Default, Copy, Clone)]
pub struct WhitelistEntry {
    pub program_id: Pubkey,
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

#[access_control(is_whitelisted(transfer))]
pub fn whitelist_relay_cpi<'info>(
    transfer: &TransferToWhitelist<'info>,
    remaining_accounts: &[AccountInfo<'info>],
    instruction_data: Vec<u8>,
) -> Result<()> {
    let mut meta_accounts = vec![
        AccountMeta::new_readonly(*transfer.locker.to_account_info().key, false),
        AccountMeta::new(*transfer.vault.to_account_info().key, false),
        AccountMeta::new_readonly(*transfer.locker_vault_authority.to_account_info().key, true),
        AccountMeta::new_readonly(*transfer.token_program.to_account_info().key, false),
        AccountMeta::new(
            *transfer.whitelisted_program_vault.to_account_info().key,
            false,
        ),
        AccountMeta::new_readonly(
            *transfer
                .whitelisted_program_vault_authority
                .to_account_info()
                .key,
            false,
        ),
    ];
    meta_accounts.extend(remaining_accounts.iter().map(|a| {
        if a.is_writable {
            AccountMeta::new(*a.key, a.is_signer)
        } else {
            AccountMeta::new_readonly(*a.key, a.is_signer)
        }
    }));
    let relay_instruction = Instruction {
        program_id: *transfer.whitelisted_program.to_account_info().key,
        accounts: meta_accounts,
        data: instruction_data.to_vec(),
    };

    let seeds = &[
        transfer.locker.to_account_info().key.as_ref(),
        &[transfer.locker.nonce],
    ];
    let signer = &[&seeds[..]];
    let mut accounts = transfer.to_account_infos();
    accounts.extend_from_slice(&remaining_accounts);
    invoke_signed(&relay_instruction, &accounts, signer).map_err(Into::into)
}

pub fn is_whitelisted<'info>(transfer: &TransferToWhitelist<'info>) -> Result<()> {
    if !transfer.locker_manager_info.whitelist.contains(&WhitelistEntry {
        program_id: *transfer.whitelisted_program.key,
    }) {
        return Err(ErrorCode::WhitelistEntryNotFound.into());
    }
    Ok(())
}

fn authorize(ctx: &Context<Auth>) -> Result<()> {
    if ctx.accounts.locker_manager_info.authority != *ctx.accounts.authority.key {
        return Err(ErrorCode::Unauthorized.into());
    }
    Ok(())
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

// Returns Ok if the locked locker account has been "realeased". Releasing
// is application dependent. For example, in the case of staking, one must first
// unstake before being able to earn locked tokens.
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

/// ReleaseLock defines the interface an external program must implement if
/// they want to define a "releasing condition" on a locked locker account.
/// This condition must be satisfied *even if a locker schedule has
/// completed*. Otherwise the user can never earn the locked funds. For example,
/// in the case of the staking program, one cannot received a locked reward
/// until one has completely unstaked.
#[interface]
pub trait ReleaseLock<'info, T: Accounts<'info>> {
    fn check_releasability(ctx: Context<T>, v: Locker) -> Result<()>;
}
