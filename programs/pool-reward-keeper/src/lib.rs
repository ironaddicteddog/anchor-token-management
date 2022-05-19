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
        // Secutiry Check
        assert!(staker_data.staker_vault_pool_token == *ctx.accounts.staker_vault_pool_token.to_account_info().key);
        assert!(
            staker_data.staker_vault_locked_pool_token
                == *ctx.accounts.staker_vault_locked_pool_token.to_account_info().key
        );

        if let Some(reward_keeper) = &locker.reward_keeper {
            if &reward_keeper.metadata != ctx.accounts.staker.to_account_info().key {
                return Err(ErrorCode::InvalidRewardKeeperMetadata.into());
            }
            // assert!(ctx.accounts.staker.beneficiary == v.beneficiary);
            assert!(staker_data.beneficiary == locker.beneficiary);
            let total_staked =
                ctx.accounts.staker_vault_pool_token.amount + ctx.accounts.staker_vault_locked_pool_token.amount;
            if total_staked != 0 {
                return Err(ErrorCode::UnreleasedReward.into());
            }
        }
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
    /// Pool the staker belongs to.
    pub pool: Pubkey,
    /// The effective owner of the Staker account.
    pub beneficiary: Pubkey,
    /// Arbitrary metadata account owned by any program.
    pub metadata: Pubkey,
    /// Sets of balances owned by the Staker.
    pub staker_vault_pool_token: Pubkey,
    /// Locked balances owned by the Staker.
    pub staker_vault_locked_pool_token: Pubkey,
}

// StakerVault defines isolated funds that can only be deposited/withdrawn
// into the program.
//
// Once controlled by the program, the associated `Staker` account's beneficiary
// can send funds to/from any of the accounts within the sandbox, e.g., to
// stake.
#[derive(AnchorSerialize, AnchorDeserialize, Default, Debug, Clone, PartialEq)]
pub struct StakerVault {
    // Free balance (deposit) vaults.
    pub vault: Pubkey,
    // Stake vaults.
    pub vault_staked: Pubkey,
    // Pending withdrawal vaults.
    pub vault_pending_withdrawal: Pubkey,
    // Staking pool token.
    pub vault_pool_token: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
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
    /// The program that determines when the locked account is **releasable**.
    /// In addition to the lockup schedule, the program provides the ability
    /// for applications to determine when locked tokens are considered earned.
    /// For example, when earning locked tokens via the staking program, one
    /// cannot receive the tokens until unstaking. As a result, if one never
    /// unstakes, one would never actually receive the locked tokens.
    pub reward_keeper: Option<PoolRewardKeeper>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct PoolRewardKeeper {
    /// Program to invoke to check a realization condition. This program must
    /// implement the `ReleaseLock` trait.
    pub program: Pubkey,
    /// Address of an arbitrary piece of metadata interpretable by the reward keeper
    /// program. For example, when a locker account is allocated, the program
    /// can define its realization condition as a function of some account
    /// state. The metadata is the address of that account.
    ///
    /// In the case of staking, the metadata is a `Staker` account address. When
    /// the realization condition is checked, the staking program will check the
    /// `Staker` account defined by the `metadata` has no staked tokens.
    pub metadata: Pubkey,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Locked rewards cannot be released until one unstaked all tokens.")]
    UnreleasedReward,
    #[msg("The given staker account does not match the reward keeper metadata.")]
    InvalidRewardKeeperMetadata,
}
