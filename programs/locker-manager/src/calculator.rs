//! Utility functions for calculating unlock schedules for a locker account.

use crate::Locker;

pub fn available_for_withdrawal(locker: &Locker, current_ts: i64) -> u64 {
    std::cmp::min(current_balance_vested(locker, current_ts), balance(locker))
}

// The amount of funds currently in the vault.
fn balance(locker: &Locker) -> u64 {
    locker
        .current_balance
        .checked_sub(locker.whitelist_owned)
        .unwrap()
}

// The amount of current_balance locked tokens vested. Note that these
// tokens might have been transferred to whitelisted programs.
fn current_balance_vested(locker: &Locker, current_ts: i64) -> u64 {
    total_vested(locker, current_ts)
        .checked_sub(withdrawn_amount(locker))
        .unwrap()
}

// Returns the amount withdrawn from this locker account.
fn withdrawn_amount(locker: &Locker) -> u64 {
    locker
        .start_balance
        .checked_sub(locker.current_balance)
        .unwrap()
}

// Returns the total vested amount up to the given ts, assuming zero
// withdrawals and zero funds sent to other programs.
fn total_vested(locker: &Locker, current_ts: i64) -> u64 {
    if current_ts < locker.start_ts {
        0
    } else if current_ts >= locker.end_ts {
        locker.start_balance
    } else {
        linear_unlock(locker, current_ts).unwrap()
    }
}

fn linear_unlock(locker: &Locker, current_ts: i64) -> Option<u64> {
    // Signed division not supported.
    let current_ts = current_ts as u64;
    let start_ts = locker.start_ts as u64;
    let end_ts = locker.end_ts as u64;

    // If we can't perfectly partition the locker window,
    // push the start of the window back so that we can.
    //
    // This has the effect of making the first locker period shorter
    // than the rest.
    let shifted_start_ts =
        start_ts.checked_sub(end_ts.checked_sub(start_ts)? % locker.period_count)?;

    // Similarly, if we can't perfectly divide up the locker rewards
    // then make the first period act as a cliff, earning slightly more than
    // subsequent periods.
    let reward_overflow = locker.start_balance % locker.period_count;

    // Reward per period ignoring the overflow.
    let reward_per_period =
        (locker.start_balance.checked_sub(reward_overflow)?).checked_div(locker.period_count)?;

    // Number of locker periods that have passed.
    let current_period = {
        let period_secs =
            (end_ts.checked_sub(shifted_start_ts)?).checked_div(locker.period_count)?;
        let current_period_count =
            (current_ts.checked_sub(shifted_start_ts)?).checked_div(period_secs)?;
        std::cmp::min(current_period_count, locker.period_count)
    };

    if current_period == 0 {
        return Some(0);
    }

    current_period
        .checked_mul(reward_per_period)?
        .checked_add(reward_overflow)
}
