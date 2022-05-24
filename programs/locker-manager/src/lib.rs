use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount, Transfer, transfer};

mod calculator;

declare_id!("7LGfdonJVsPaB3LzfVvDGE9jwHseFVDkg8ZrJfwhiAzw");

#[program]
pub mod locker_manager {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, _locker_manager_nonce: u64) -> Result<()> {
        ctx.accounts.locker_manager_info.authority = *ctx.accounts.authority.key;

        Ok(())
    }

    pub fn set_authority(ctx: Context<Auth>, _locker_manager_nonce: u64, new_authority: Pubkey) -> Result<()> {
        ctx.accounts.locker_manager_info.authority = new_authority;

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

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let available_for_withdrawal = calculator::available_for_withdrawal(
            &ctx.accounts.locker,
            ctx.accounts.clock.unix_timestamp,
        );

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
