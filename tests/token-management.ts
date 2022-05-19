import * as anchor from "@project-serum/anchor";
import NodeWallet from "@project-serum/anchor/dist/cjs/nodewallet";
import { IDL as lockerManagerIDL } from "../target/types/locker_manager";
import { IDL as poolManagerIDL } from "../target/types/pool_manager";
import { IDL as rewardKeeperIDL } from "../target/types/pool_reward_keeper";
import {
  PublicKey,
  SystemProgram,
  Keypair,
  Commitment,
  Connection,
} from "@solana/web3.js";
import * as splToken from "@solana/spl-token";
import assert from "assert";
import {
  createBalanceSandbox,
  createMint,
  createMintAndVault,
  createTokenAccount,
  createTokenAccountInstrs,
  sleep,
} from "./utils";
import { SendTxRequest } from "@project-serum/anchor/dist/cjs/provider";
import { TypeDef } from "@project-serum/anchor/dist/cjs/program/namespace/types";

const LOCKER_MANAGER_PROGRAM_ID = new anchor.web3.PublicKey(
  "7LGfdonJVsPaB3LzfVvDGE9jwHseFVDkg8ZrJfwhiAzw"
);
const POOL_MANAGER_PROGRAM_ID = new anchor.web3.PublicKey(
  "362QKmGMs4ZGiSfuQCXCEAcW6gFExy9XmZM2Cki89rWw"
);
const REEARD_KEEPER_PROGRAM_ID = new anchor.web3.PublicKey(
  "9dfVBXMVk4GmmkVvZuY3z5cqAcWn96N7fwBVuVbhpfJd"
);

describe("Locker Manager and Pool Manager", () => {
  const commitment: Commitment = "confirmed";
  const connection = new Connection("https://rpc-mainnet-fork.epochs.studio", {
    commitment,
    wsEndpoint: "wss://rpc-mainnet-fork.epochs.studio/ws",
  });
  const options = anchor.AnchorProvider.defaultOptions();
  const wallet = NodeWallet.local();
  const provider = new anchor.AnchorProvider(connection, wallet, options);

  anchor.setProvider(provider);

  const lockerManager = new anchor.Program(
    lockerManagerIDL,
    LOCKER_MANAGER_PROGRAM_ID,
    provider
  );
  const poolManager = new anchor.Program(
    poolManagerIDL,
    POOL_MANAGER_PROGRAM_ID,
    provider
  );
  const rewardKeeper = new anchor.Program(
    rewardKeeperIDL,
    REEARD_KEEPER_PROGRAM_ID,
    provider
  );

  const WHITELIST_SIZE = 10;

  let lockerManagerInfoAddress = null as PublicKey;
  let _lockerManagerBump = null as number;
  const lockerManagerNonce = new anchor.BN(
    Math.floor(Math.random() * 100000000)
  );

  let mint = null;
  let god = null;

  it("Sets up initial test state", async () => {
    const [_mint, _god] = await createMintAndVault(
      provider as anchor.AnchorProvider,
      new anchor.BN(1000000)
    );
    mint = _mint;
    god = _god;
  });

  it("Is initialized!", async () => {
    [lockerManagerInfoAddress, _lockerManagerBump] =
      await anchor.web3.PublicKey.findProgramAddress(
        [
          Buffer.from(anchor.utils.bytes.utf8.encode("locker-manager")),
          lockerManagerNonce.toBuffer("le", 8),
        ],
        lockerManager.programId
      );

    await lockerManager.methods
      .initialize(lockerManagerNonce)
      .accounts({
        authority: provider.wallet.publicKey,
        lockerManagerInfo: lockerManagerInfoAddress,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const lockerManagerInfo =
      await lockerManager.account.lockerManagerInfo.fetch(
        lockerManagerInfoAddress
      );
    const whitelist = lockerManagerInfo.whitelist as Array<
      TypeDef<
        {
          name: "WhitelistEntry";
          type: {
            kind: "struct";
            fields: [
              {
                name: "programId";
                type: "publicKey";
              }
            ];
          };
        },
        Record<string, anchor.web3.PublicKey>
      >
    >;

    assert.ok(lockerManagerInfo.authority.equals(provider.wallet.publicKey));
    assert.ok(whitelist.length === WHITELIST_SIZE);
    whitelist.forEach((e) => {
      assert.ok(e.programId.equals(anchor.web3.PublicKey.default));
    });
  });

  it("Deletes the default whitelisted addresses", async () => {
    const defaultEntry = { programId: anchor.web3.PublicKey.default };
    await lockerManager.methods
      .removeWhitelist(lockerManagerNonce, defaultEntry)
      .accounts({
        authority: provider.wallet.publicKey,
        lockerManagerInfo: lockerManagerInfoAddress,
      })
      .rpc();
  });

  it("Sets a new authority", async () => {
    const newAuthority = Keypair.generate();
    await lockerManager.methods
      .setAuthority(lockerManagerNonce, newAuthority.publicKey)
      .accounts({
        authority: provider.wallet.publicKey,
        lockerManagerInfo: lockerManagerInfoAddress,
      })
      .rpc();

    let lockerManagerInfo = await lockerManager.account.lockerManagerInfo.fetch(
      lockerManagerInfoAddress
    );
    assert.ok(lockerManagerInfo.authority.equals(newAuthority.publicKey));

    await lockerManager.methods
      .setAuthority(lockerManagerNonce, provider.wallet.publicKey)
      .accounts({
        authority: newAuthority.publicKey,
        lockerManagerInfo: lockerManagerInfoAddress,
      })
      .signers([newAuthority])
      .rpc();

    lockerManagerInfo = await lockerManager.account.lockerManagerInfo.fetch(
      lockerManagerInfoAddress
    );
    assert.ok(lockerManagerInfo.authority.equals(provider.wallet.publicKey));
  });

  const entries = [];

  it("Adds to the whitelist", async () => {
    const generateEntry = async () => {
      let programId = Keypair.generate().publicKey;
      return {
        programId,
      };
    };

    for (let k = 0; k < WHITELIST_SIZE; k += 1) {
      entries.push(await generateEntry());
    }

    const accounts = {
      authority: provider.wallet.publicKey,
      lockerManagerInfo: lockerManagerInfoAddress,
    };

    await lockerManager.methods
      .addWhitelist(lockerManagerNonce, entries[0])
      .accounts(accounts)
      .rpc();

    let lockerManagerInfo = await lockerManager.account.lockerManagerInfo.fetch(
      lockerManagerInfoAddress
    );

    const whitelist = lockerManagerInfo.whitelist as Array<
      TypeDef<
        {
          name: "WhitelistEntry";
          type: {
            kind: "struct";
            fields: [
              {
                name: "programId";
                type: "publicKey";
              }
            ];
          };
        },
        Record<string, anchor.web3.PublicKey>
      >
    >;

    assert.ok(whitelist.length === 1);
    assert.deepEqual(whitelist, [entries[0]]);

    for (let k = 1; k < WHITELIST_SIZE; k += 1) {
      await lockerManager.methods
        .addWhitelist(lockerManagerNonce, entries[k])
        .accounts(accounts)
        .rpc();
    }

    lockerManagerInfo = await lockerManager.account.lockerManagerInfo.fetch(
      lockerManagerInfoAddress
    );

    const whitelist2 = lockerManagerInfo.whitelist as Array<
      TypeDef<
        {
          name: "WhitelistEntry";
          type: {
            kind: "struct";
            fields: [
              {
                name: "programId";
                type: "publicKey";
              }
            ];
          };
        },
        Record<string, anchor.web3.PublicKey>
      >
    >;

    assert.deepEqual(whitelist2, entries);

    await assert.rejects(
      async () => {
        const e = await generateEntry();
        await lockerManager.methods
          .addWhitelist(lockerManagerNonce, e)
          .accounts(accounts)
          .rpc();
      },
      (err: anchor.AnchorError) => {
        assert.equal(err.error.errorCode.code, "WhitelistFull");
        assert.equal(err.error.errorMessage, "Whitelist is full");
        return true;
      }
    );
  });

  it("Removes from the whitelist", async () => {
    await lockerManager.methods
      .removeWhitelist(lockerManagerNonce, entries[0])
      .accounts({
        authority: provider.wallet.publicKey,
        lockerManagerInfo: lockerManagerInfoAddress,
      })
      .rpc();
    let lockerManagerInfo = await lockerManager.account.lockerManagerInfo.fetch(
      lockerManagerInfoAddress
    );
    assert.deepEqual(lockerManagerInfo.whitelist, entries.slice(1));
  });

  const locker = Keypair.generate();
  let lockerAccount = null;
  let lockerVaultAuthority = null as PublicKey;

  it("Creates a locker account", async () => {
    const slot = await connection.getSlot();
    const blocktime = await connection.getBlockTime(slot);
    const startTs = new anchor.BN(blocktime);
    const endTs = new anchor.BN(startTs.toNumber() + 5);
    const periodCount = new anchor.BN(2);
    const beneficiary = provider.wallet.publicKey;
    const depositAmount = new anchor.BN(100);

    const vault = Keypair.generate();
    let [_lockerVaultAuthority, lockerVaultNonce] =
      await anchor.web3.PublicKey.findProgramAddress(
        [locker.publicKey.toBuffer()],
        lockerManager.programId
      );
    lockerVaultAuthority = _lockerVaultAuthority;

    const sig = await lockerManager.methods
      .createLocker(
        beneficiary,
        depositAmount,
        lockerVaultNonce,
        startTs,
        endTs,
        periodCount,
        null // Lock reward keeper is None.
      )
      .accounts({
        locker: locker.publicKey,
        vault: vault.publicKey,
        depositor: god,
        depositorAuthority: provider.wallet.publicKey,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
      })
      .signers([locker, vault])
      .preInstructions([
        await lockerManager.account.locker.createInstruction(locker),
        ...(await createTokenAccountInstrs(
          provider,
          vault.publicKey,
          mint,
          lockerVaultAuthority
        )),
      ])
      .rpc();

    lockerAccount = await lockerManager.account.locker.fetch(locker.publicKey);

    assert.ok(lockerAccount.beneficiary.equals(provider.wallet.publicKey));
    assert.ok(lockerAccount.mint.equals(mint));
    assert.ok(lockerAccount.grantor.equals(provider.wallet.publicKey));
    assert.ok(lockerAccount.currentBalance.eq(depositAmount));
    assert.ok(lockerAccount.startBalance.eq(depositAmount));
    assert.ok(lockerAccount.whitelistOwned.eq(new anchor.BN(0)));
    assert.equal(lockerAccount.nonce, lockerVaultNonce);
    assert.ok(lockerAccount.createdTs.gt(new anchor.BN(0)));
    assert.ok(lockerAccount.startTs.eq(startTs));
    assert.ok(lockerAccount.endTs.eq(endTs));
    assert.ok(lockerAccount.rewardKeeper === null);

    const vaultAccount = await splToken.getAccount(
      provider.connection,
      lockerAccount.vault
    );
  });

  it("Fails to withdraw from a locker account before locker", async () => {
    await assert.rejects(
      async () => {
        await lockerManager.methods
          .withdraw(new anchor.BN(100))
          .accounts({
            locker: locker.publicKey,
            beneficiary: provider.wallet.publicKey,
            token: god,
            vault: lockerAccount.vault,
            lockerVaultAuthority,
            tokenProgram: splToken.TOKEN_PROGRAM_ID,
            clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
          })
          .rpc();
      },
      (err: anchor.AnchorError) => {
        assert.equal(err.error.errorCode.code, "InsufficientWithdrawalBalance");
        assert.equal(
          err.error.errorMessage,
          "Insufficient withdrawal balance."
        );
        return true;
      }
    );
  });

  it("Waits for a locker period to pass", async () => {
    await sleep(10 * 1000);

    const vaultAccount = await splToken.getAccount(
      provider.connection,
      lockerAccount.vault
    );
  });

  it("Withdraws from the locker account", async () => {
    const token = await createTokenAccount(
      provider,
      mint,
      provider.wallet.publicKey
    );

    await lockerManager.methods
      .withdraw(new anchor.BN(100))
      .accounts({
        locker: locker.publicKey,
        beneficiary: provider.wallet.publicKey,
        token,
        vault: lockerAccount.vault,
        lockerVaultAuthority,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
        clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
      })
      .rpc();

    lockerAccount = await lockerManager.account.locker.fetch(locker.publicKey);
    assert.ok(lockerAccount.currentBalance.eq(new anchor.BN(0)));

    const vaultAccount = await splToken.getAccount(
      provider.connection,
      lockerAccount.vault
    );
    assert.ok(
      new anchor.BN(vaultAccount.amount.toString()).eq(new anchor.BN(0))
    );

    const tokenAccount = await splToken.getAccount(provider.connection, token);
    assert.ok(
      new anchor.BN(tokenAccount.amount.toString()).eq(new anchor.BN(100))
    );
  });

  const pool = Keypair.generate();
  const rewardQ = Keypair.generate();
  const withdrawalTimelock = new anchor.BN(4);
  const stakeRate = new anchor.BN(2);
  const rewardQLen = 170;
  let poolAccount = null;
  let poolMintAuthority = null;
  let poolNonce = null;
  let poolMint = null;
  let poolManagerInfoAddress = null as PublicKey;
  let _poolManagerBump = null as number;

  const poolManagerNonce = new anchor.BN(Math.floor(Math.random() * 100000000));

  it("Creates poolManager genesis", async () => {
    [poolManagerInfoAddress, _poolManagerBump] =
      await anchor.web3.PublicKey.findProgramAddress(
        [
          Buffer.from(anchor.utils.bytes.utf8.encode("pool-manager")),
          poolManagerNonce.toBuffer("le", 8),
        ],
        poolManager.programId
      );
  });

  it("Initializes poolManager's global state", async () => {
    let accounts = {
      authority: provider.wallet.publicKey,
      lockerManagerProgram: lockerManager.programId,
      rewardKeeperProgram: rewardKeeper.programId,
      poolManagerInfo: poolManagerInfoAddress,
      systemProgram: SystemProgram.programId,
    };
    await poolManager.methods
      .initialize(poolManagerNonce)
      .accounts(accounts)
      .rpc();

    const poolManagerInfoAccount =
      await poolManager.account.poolManagerInfo.fetch(poolManagerInfoAddress);
    assert.ok(
      poolManagerInfoAccount.lockerManagerProgram.equals(
        lockerManager.programId
      )
    );

    // Should not allow a second initializatoin.
    await assert.rejects(
      async () => {
        await poolManager.methods
          .initialize(poolManagerNonce)
          .accounts(accounts)
          .rpc();
      },
      (err) => {
        return true;
      }
    );
  });

  it("Initializes the pool", async () => {
    const [_poolMintAuthority, _nonce] =
      await anchor.web3.PublicKey.findProgramAddress(
        [pool.publicKey.toBuffer()],
        poolManager.programId
      );
    poolMintAuthority = _poolMintAuthority;
    poolNonce = _nonce;
    poolMint = await createMint(provider, poolMintAuthority);

    await poolManager.methods
      .createPool(
        mint,
        provider.wallet.publicKey,
        poolNonce,
        withdrawalTimelock,
        stakeRate,
        rewardQLen
      )
      .accounts({
        pool: pool.publicKey,
        poolMint,
        rewardEventQ: rewardQ.publicKey,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .signers([pool, rewardQ])
      .preInstructions([
        await poolManager.account.pool.createInstruction(pool),
        await poolManager.account.rewardQueue.createInstruction(rewardQ, 8250),
      ])
      .rpc();

    poolAccount = await poolManager.account.pool.fetch(pool.publicKey);

    assert.ok(poolAccount.authority.equals(provider.wallet.publicKey));
    assert.equal(poolAccount.nonce, poolNonce);
    assert.ok(poolAccount.mint.equals(mint));
    assert.ok(poolAccount.poolMint.equals(poolMint));
    assert.ok(poolAccount.stakeRate.eq(stakeRate));
    assert.ok(poolAccount.rewardEventQ.equals(rewardQ.publicKey));
    assert.ok(poolAccount.withdrawalTimelock.eq(withdrawalTimelock));
  });

  const staker = Keypair.generate();
  let stakerAccount = null;
  let stakerVaultAuthority = null;
  let stakerVault = null;
  let stakerVaultLocked = null;

  it("Creates a staker", async () => {
    const [_stakerVaultAuthority, stakerNonce] =
      await anchor.web3.PublicKey.findProgramAddress(
        [pool.publicKey.toBuffer(), staker.publicKey.toBuffer()],
        poolManager.programId
      );
    stakerVaultAuthority = _stakerVaultAuthority;

    const [mainTx, _stakerVault] = await createBalanceSandbox(
      provider,
      poolAccount,
      stakerVaultAuthority
    );
    const [lockedTx, _stakerVaultLocked] = await createBalanceSandbox(
      provider,
      poolAccount,
      stakerVaultAuthority
    );

    stakerVault = _stakerVault;
    stakerVaultLocked = _stakerVaultLocked;

    const txCreate = await poolManager.methods
      .createStaker(stakerNonce)
      .accounts({
        pool: pool.publicKey,
        staker: staker.publicKey,
        beneficiary: provider.wallet.publicKey,
        stakerVaultAuthority,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .preInstructions([
        await poolManager.account.staker.createInstruction(staker),
      ])
      .transaction();

    const txUpdateBalances = await poolManager.methods
      .updateStakerVault(stakerNonce)
      .accounts({
        pool: pool.publicKey,
        staker: staker.publicKey,
        stakerVaultAuthority,
        stakerVault,
      })
      .transaction();

    const txUpdateBalancesLock = await poolManager.methods
      .updateStakerVaultLocked(stakerNonce)
      .accounts({
        pool: pool.publicKey,
        staker: staker.publicKey,
        stakerVaultAuthority,
        stakerVaultLocked,
      })
      .transaction();

    const wallet = provider.wallet as NodeWallet;

    const signers = [staker, wallet.payer];

    const allTxs: SendTxRequest[] = [
      mainTx as SendTxRequest,
      lockedTx as SendTxRequest,
      { tx: txCreate, signers },
      { tx: txUpdateBalances, signers: [wallet.payer] },
      { tx: txUpdateBalancesLock, signers: [wallet.payer] },
    ];

    await provider.sendAll(allTxs);

    stakerAccount = await poolManager.account.staker.fetch(staker.publicKey);

    assert.ok(stakerAccount.pool.equals(pool.publicKey));
    assert.ok(stakerAccount.beneficiary.equals(provider.wallet.publicKey));
    assert.ok(stakerAccount.metadata.equals(anchor.web3.PublicKey.default));
    assert.equal(
      JSON.stringify(stakerAccount.stakerVault),
      JSON.stringify(stakerVault)
    );
    assert.equal(
      JSON.stringify(stakerAccount.stakerVaultLocked),
      JSON.stringify(stakerVaultLocked)
    );
    assert.ok(stakerAccount.rewardsCursor === 0);
    assert.ok(stakerAccount.lastStakeTs.eq(new anchor.BN(0)));
  });

  it("Deposits (unlocked) to a staker", async () => {
    const depositAmount = new anchor.BN(120);
    await poolManager.methods
      .deposit(depositAmount)
      .accounts({
        depositor: god,
        depositorAuthority: provider.wallet.publicKey,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
        vault: stakerAccount.stakerVault.vault,
        beneficiary: provider.wallet.publicKey,
        staker: staker.publicKey,
      })
      .rpc();

    const stakerVault = await splToken.getAccount(
      provider.connection,
      stakerAccount.stakerVault.vault
    );
    assert.ok(new anchor.BN(stakerVault.amount.toString()).eq(depositAmount));
  });

  it("Stakes to a staker (unlocked)", async () => {
    const stakeAmount = new anchor.BN(10);
    await poolManager.methods
      .stake(stakeAmount)
      .accounts({
        // Stake instance.
        pool: pool.publicKey,
        rewardEventQ: rewardQ.publicKey,
        poolMint,
        // Staker.
        staker: staker.publicKey,
        beneficiary: provider.wallet.publicKey,
        stakerVault,
        // stakerVaultLocked,
        // Program signers.
        stakerVaultAuthority,
        poolMintAuthority,
        // Misc.
        clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
      })
      .rpc();

    const vault = await splToken.getAccount(
      provider.connection,
      stakerAccount.stakerVault.vault
    );
    const vaultStaked = await splToken.getAccount(
      provider.connection,
      stakerAccount.stakerVault.vaultStaked
    );
    const vaultPoolToken = await splToken.getAccount(
      provider.connection,
      stakerAccount.stakerVault.vaultPoolToken
    );

    assert.ok(new anchor.BN(vault.amount.toString()).eq(new anchor.BN(100)));
    assert.ok(
      new anchor.BN(vaultStaked.amount.toString()).eq(new anchor.BN(20))
    );
    assert.ok(
      new anchor.BN(vaultPoolToken.amount.toString()).eq(new anchor.BN(10))
    );
  });

  const unlockedRewarder = Keypair.generate();
  const unlockedRewarderVault = Keypair.generate();
  let unlockedRewarderVaultAuthority = null;

  it("Drops an unlocked reward", async () => {
    const rewardKind = {
      unlocked: {},
    };
    const rewardAmount = new anchor.BN(200);
    const expiry = new anchor.BN(Date.now() / 1000 + 5);
    const [_rewarderVaultAuthority, nonce] =
      await anchor.web3.PublicKey.findProgramAddress(
        [pool.publicKey.toBuffer(), unlockedRewarder.publicKey.toBuffer()],
        poolManager.programId
      );
    unlockedRewarderVaultAuthority = _rewarderVaultAuthority;

    await poolManager.methods
      .dropReward(
        rewardKind,
        rewardAmount,
        expiry,
        provider.wallet.publicKey,
        nonce
      )
      .accounts({
        pool: pool.publicKey,
        rewardEventQ: rewardQ.publicKey,
        poolMint,
        rewarder: unlockedRewarder.publicKey,
        rewarderVault: unlockedRewarderVault.publicKey,
        depositor: god,
        depositorAuthority: provider.wallet.publicKey,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
        clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .signers([unlockedRewarderVault, unlockedRewarder])
      .preInstructions([
        ...(await createTokenAccountInstrs(
          provider,
          unlockedRewarderVault.publicKey,
          mint,
          unlockedRewarderVaultAuthority
        )),
        await poolManager.account.rewarder.createInstruction(unlockedRewarder),
      ])
      .rpc();

    const rewarderAccount = await poolManager.account.rewarder.fetch(
      unlockedRewarder.publicKey
    );

    assert.ok(rewarderAccount.pool.equals(pool.publicKey));
    assert.ok(rewarderAccount.vault.equals(unlockedRewarderVault.publicKey));
    assert.ok(rewarderAccount.nonce === nonce);
    assert.ok(rewarderAccount.poolTokenSupply.eq(new anchor.BN(10)));
    assert.ok(rewarderAccount.expiryTs.eq(expiry));
    assert.ok(rewarderAccount.expiryReceiver.equals(provider.wallet.publicKey));
    assert.ok(rewarderAccount.total.eq(rewardAmount));
    assert.ok(rewarderAccount.expired === false);
    assert.ok(rewarderAccount.rewardEventQCursor === 0);
    assert.deepEqual(rewarderAccount.kind, rewardKind);

    const rewardQAccount = await poolManager.account.rewardQueue.fetch(
      rewardQ.publicKey
    );
    assert.ok(rewardQAccount.head === 1);
    assert.ok(rewardQAccount.tail === 0);
    const e = rewardQAccount.events[0];
    assert.ok(e.rewarder.equals(unlockedRewarder.publicKey));
    assert.equal(e.locked, false);
  });

  it("Collects an unlocked reward", async () => {
    const token = await createTokenAccount(
      provider,
      mint,
      provider.wallet.publicKey
    );
    await poolManager.methods
      .claimReward()
      .accounts({
        to: token,
        common: {
          pool: pool.publicKey,
          staker: staker.publicKey,
          beneficiary: provider.wallet.publicKey,
          stakerVaultPoolToken: stakerVault.vaultPoolToken,
          stakerVaultLockedPoolToken: stakerVaultLocked.vaultPoolToken,
          rewarder: unlockedRewarder.publicKey,
          vault: unlockedRewarderVault.publicKey,
          rewarderVaultAuthority: unlockedRewarderVaultAuthority,
          tokenProgram: splToken.TOKEN_PROGRAM_ID,
          clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
        },
      })
      .rpc();

    let tokenAccount = await splToken.getAccount(provider.connection, token);
    assert.ok(
      new anchor.BN(tokenAccount.amount.toString()).eq(new anchor.BN(200))
    );

    const stakerAccount = await poolManager.account.staker.fetch(
      staker.publicKey
    );
    assert.ok(stakerAccount.rewardsCursor == 1);
  });

  const lockedRewarder = Keypair.generate();
  const lockedRewarderVault = Keypair.generate();
  let lockedRewarderVaultAuthority = null;
  let lockedRewardAmount = null;
  let lockedRewardKind = null;

  it("Drops a locked reward", async () => {
    const slot = await connection.getSlot();
    const blocktime = await connection.getBlockTime(slot);
    const startTs = new anchor.BN(blocktime);
    const endTs = new anchor.BN(startTs.toNumber() + 6);
    lockedRewardKind = {
      locked: {
        startTs,
        endTs,
        periodCount: new anchor.BN(2),
      },
    };
    lockedRewardAmount = new anchor.BN(200);
    const expiry = new anchor.BN(Date.now() / 1000 + 5);
    const [_rewarderVaultAuthority, nonce] =
      await anchor.web3.PublicKey.findProgramAddress(
        [pool.publicKey.toBuffer(), lockedRewarder.publicKey.toBuffer()],
        poolManager.programId
      );
    lockedRewarderVaultAuthority = _rewarderVaultAuthority;

    await poolManager.methods
      .dropReward(
        lockedRewardKind,
        lockedRewardAmount,
        expiry,
        provider.wallet.publicKey,
        nonce
      )
      .accounts({
        pool: pool.publicKey,
        rewardEventQ: rewardQ.publicKey,
        poolMint,
        rewarder: lockedRewarder.publicKey,
        rewarderVault: lockedRewarderVault.publicKey,
        depositor: god,
        depositorAuthority: provider.wallet.publicKey,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
        clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .signers([lockedRewarderVault, lockedRewarder])
      .preInstructions([
        ...(await createTokenAccountInstrs(
          provider,
          lockedRewarderVault.publicKey,
          mint,
          lockedRewarderVaultAuthority
        )),
        await poolManager.account.rewarder.createInstruction(lockedRewarder),
      ])
      .rpc();

    const rewarderAccount = await poolManager.account.rewarder.fetch(
      lockedRewarder.publicKey
    );

    assert.ok(rewarderAccount.pool.equals(pool.publicKey));
    assert.ok(rewarderAccount.vault.equals(lockedRewarderVault.publicKey));
    assert.ok(rewarderAccount.nonce === nonce);
    assert.ok(rewarderAccount.poolTokenSupply.eq(new anchor.BN(10)));
    assert.ok(rewarderAccount.expiryTs.eq(expiry));
    assert.ok(rewarderAccount.expiryReceiver.equals(provider.wallet.publicKey));
    assert.ok(rewarderAccount.total.eq(lockedRewardAmount));
    assert.ok(rewarderAccount.expired === false);
    assert.ok(rewarderAccount.rewardEventQCursor === 1);
    assert.equal(
      JSON.stringify(rewarderAccount.kind),
      JSON.stringify(lockedRewardKind)
    );

    const rewardQAccount = await poolManager.account.rewardQueue.fetch(
      rewardQ.publicKey
    );
    assert.ok(rewardQAccount.head === 2);
    assert.ok(rewardQAccount.tail === 0);
    const e = rewardQAccount.events[1];
    assert.ok(e.rewarder.equals(lockedRewarder.publicKey));
    assert.ok(e.locked === true);
  });

  let rewarderLocker = null;
  let rewarderLockerVault = null;
  let rewarderLockerVaultAuthority = null;

  it("Claims a locked reward", async () => {
    rewarderLocker = Keypair.generate();
    rewarderLockerVault = Keypair.generate();
    let [_rewarderLockerVaultAuthority, nonce] =
      await anchor.web3.PublicKey.findProgramAddress(
        [rewarderLocker.publicKey.toBuffer()],
        lockerManager.programId
      );
    rewarderLockerVaultAuthority = _rewarderLockerVaultAuthority;

    // Make remaining accounts for createLocker ix

    const remainingAccounts = [
      // locker
      {
        pubkey: rewarderLocker.publicKey,
        isWritable: true,
        isSigner: false,
      },
      // vault
      {
        pubkey: rewarderLockerVault.publicKey,
        isWritable: true,
        isSigner: false,
      },
      // depositor
      {
        pubkey: lockedRewarderVault.publicKey,
        isWritable: true,
        isSigner: false,
      },
      // depositorAuthority
      // Note: Change the signer status on the rewarder signer since it's signed by the program, not the client.
      {
        pubkey: lockedRewarderVaultAuthority,
        isWritable: false,
        isSigner: false,
      },
      // tokenProgram
      {
        pubkey: splToken.TOKEN_PROGRAM_ID,
        isWritable: false,
        isSigner: false,
      },
      // rent
      {
        pubkey: anchor.web3.SYSVAR_RENT_PUBKEY,
        isWritable: false,
        isSigner: false,
      },
      // clock
      {
        pubkey: anchor.web3.SYSVAR_CLOCK_PUBKEY,
        isWritable: false,
        isSigner: false,
      },
    ];

    const sig = await poolManager.methods
      .claimRewardToLocker(poolManagerNonce, nonce)
      .accounts({
        poolManagerInfo: poolManagerInfoAddress,
        lockerManagerProgram: lockerManager.programId,
        rewardKeeperProgram: rewardKeeper.programId,
        common: {
          pool: pool.publicKey,
          staker: staker.publicKey,
          beneficiary: provider.wallet.publicKey,
          stakerVaultPoolToken: stakerVault.vaultPoolToken,
          stakerVaultLockedPoolToken: stakerVaultLocked.vaultPoolToken,
          rewarder: lockedRewarder.publicKey,
          vault: lockedRewarderVault.publicKey,
          rewarderVaultAuthority: lockedRewarderVaultAuthority,
          tokenProgram: splToken.TOKEN_PROGRAM_ID,
          clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
        },
      })
      .remainingAccounts(remainingAccounts)
      .signers([rewarderLocker, rewarderLockerVault])
      .preInstructions([
        await lockerManager.account.locker.createInstruction(rewarderLocker),
        ...(await createTokenAccountInstrs(
          provider,
          rewarderLockerVault.publicKey,
          mint,
          rewarderLockerVaultAuthority
        )),
      ])
      .rpc();

    const lockerAccount = await lockerManager.account.locker.fetch(
      rewarderLocker.publicKey
    );

    assert.ok(lockerAccount.beneficiary.equals(provider.wallet.publicKey));
    assert.ok(lockerAccount.mint.equals(mint));
    assert.ok(lockerAccount.vault.equals(rewarderLockerVault.publicKey));
    assert.ok(lockerAccount.currentBalance.eq(lockedRewardAmount));
    assert.ok(lockerAccount.startBalance.eq(lockedRewardAmount));
    assert.ok(lockerAccount.endTs.eq(lockedRewardKind.locked.endTs));
    assert.ok(
      lockerAccount.periodCount.eq(lockedRewardKind.locked.periodCount)
    );
    assert.ok(lockerAccount.whitelistOwned.eq(new anchor.BN(0)));
    assert.ok(
      lockerAccount.rewardKeeper.program.equals(rewardKeeper.programId)
    );
    assert.ok(lockerAccount.rewardKeeper.metadata.equals(staker.publicKey));
  });

  it("Waits for the locker period to pass", async () => {
    await sleep(10 * 1000);
  });

  it("Should fail to unlock an unreleased locker reward", async () => {
    // Get Staker account
    const stakerAccount = await poolManager.account.staker.fetch(
      staker.publicKey
    );

    const token = await createTokenAccount(
      provider,
      mint,
      provider.wallet.publicKey
    );
    await assert.rejects(
      async () => {
        const withdrawAmount = new anchor.BN(10);
        await lockerManager.methods
          .withdraw(withdrawAmount)
          .accounts({
            locker: rewarderLocker.publicKey,
            beneficiary: provider.wallet.publicKey,
            token,
            vault: rewarderLockerVault.publicKey,
            lockerVaultAuthority: rewarderLockerVaultAuthority,
            tokenProgram: splToken.TOKEN_PROGRAM_ID,
            clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
          })
          // TODO: trait methods generated on the client. Until then, we need to manually
          //       specify the account metas here.
          .remainingAccounts([
            {
              pubkey: rewardKeeper.programId,
              isWritable: false,
              isSigner: false,
            },
            {
              pubkey: poolManager.programId,
              isWritable: false,
              isSigner: false,
            },
            // check_releasibility
            { pubkey: staker.publicKey, isWritable: false, isSigner: false },
            {
              pubkey: stakerVault.vaultPoolToken,
              isWritable: false,
              isSigner: false,
            },
            {
              pubkey: stakerVaultLocked.vaultPoolToken,
              isWritable: false,
              isSigner: false,
            },
            // StakerData
            {
              pubkey: stakerAccount.pool,
              isWritable: false,
              isSigner: false,
            },
            {
              pubkey: stakerAccount.beneficiary,
              isWritable: false,
              isSigner: false,
            },
            {
              pubkey: stakerAccount.metadata,
              isWritable: false,
              isSigner: false,
            },
            {
              pubkey: stakerAccount.stakerVault.vaultPoolToken,
              isWritable: false,
              isSigner: false,
            },
            {
              pubkey: stakerAccount.stakerVaultLocked.vaultPoolToken,
              isWritable: false,
              isSigner: false,
            },
          ])
          .rpc();
      },
      (err: anchor.AnchorError) => {
        // Solana doesn't propagate errors across CPI. So we receive the poolManager's error code,
        // not the locker's.
        // const errorCode = "custom program error: 0x65";
        // assert.ok(err.toString().split(errorCode).length === 2);
        assert.equal(err.error.errorCode.code, "UnreleasedReward");
        return true;
      }
    );
  });

  const pendingWithdrawal = Keypair.generate();

  it("Unstakes (unlocked)", async () => {
    const unstakeAmount = new anchor.BN(10);

    await poolManager.methods
      .startUnstake(unstakeAmount, false)
      .accounts({
        pool: pool.publicKey,
        rewardEventQ: rewardQ.publicKey,
        poolMint,
        pendingWithdrawal: pendingWithdrawal.publicKey,
        staker: staker.publicKey,
        beneficiary: provider.wallet.publicKey,
        stakerVault,
        stakerVaultAuthority,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
        clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .signers([pendingWithdrawal])
      .preInstructions([
        await poolManager.account.pendingWithdrawal.createInstruction(
          pendingWithdrawal
        ),
      ])
      .rpc();

    const vaultPendingWithdrawal = await splToken.getAccount(
      provider.connection,
      stakerAccount.stakerVault.vaultPendingWithdrawal
    );
    const vaultStaked = await splToken.getAccount(
      provider.connection,
      stakerAccount.stakerVault.vaultStaked
    );
    const vaultPoolToken = await splToken.getAccount(
      provider.connection,
      stakerAccount.stakerVault.vaultPoolToken
    );

    assert.ok(
      new anchor.BN(vaultPendingWithdrawal.amount.toString()).eq(
        new anchor.BN(20)
      )
    );
    assert.ok(
      new anchor.BN(vaultStaked.amount.toString()).eq(new anchor.BN(0))
    );
    assert.ok(
      new anchor.BN(vaultPoolToken.amount.toString()).eq(new anchor.BN(0))
    );
  });

  it("Fails to end unstaking before timelock", async () => {
    await assert.rejects(
      async () => {
        await poolManager.methods
          .endUnstake()
          .accounts({
            pool: pool.publicKey,
            staker: staker.publicKey,
            beneficiary: provider.wallet.publicKey,
            pendingWithdrawal: pendingWithdrawal.publicKey,
            vault: stakerVault.vault,
            vaultPendingWithdrawal: stakerVault.vaultPendingWithdrawal,
            stakerVaultAuthority,
            clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
            tokenProgram: splToken.TOKEN_PROGRAM_ID,
          })
          .rpc();
      },
      (err: anchor.AnchorError) => {
        assert.equal(err.error.errorCode.code, "UnstakeTimelock");
        assert.equal(
          err.error.errorMessage,
          "The unstake timelock has not yet expired."
        );
        return true;
      }
    );
  });

  it("Waits for the unstake period to end", async () => {
    await sleep(5000);
  });

  it("Unstake finalizes (unlocked)", async () => {
    await poolManager.methods
      .endUnstake()
      .accounts({
        pool: pool.publicKey,
        staker: staker.publicKey,
        beneficiary: provider.wallet.publicKey,
        pendingWithdrawal: pendingWithdrawal.publicKey,
        vault: stakerVault.vault,
        vaultPendingWithdrawal: stakerVault.vaultPendingWithdrawal,
        stakerVaultAuthority,
        clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
      })
      .rpc();

    const vault = await splToken.getAccount(
      provider.connection,
      stakerAccount.stakerVault.vault
    );
    const vaultPendingWithdrawal = await splToken.getAccount(
      provider.connection,
      stakerAccount.stakerVault.vaultPendingWithdrawal
    );

    assert.ok(new anchor.BN(vault.amount.toString()).eq(new anchor.BN(120)));
    assert.ok(
      new anchor.BN(vaultPendingWithdrawal.amount.toString()).eq(
        new anchor.BN(0)
      )
    );
  });

  it("Withdraws deposits (unlocked)", async () => {
    const token = await createTokenAccount(
      provider,
      mint,
      provider.wallet.publicKey
    );
    const withdrawAmount = new anchor.BN(100);
    await poolManager.methods
      .withdraw(withdrawAmount)
      .accounts({
        pool: pool.publicKey,
        staker: staker.publicKey,
        beneficiary: provider.wallet.publicKey,
        vault: stakerAccount.stakerVault.vault,
        stakerVaultAuthority,
        depositor: token,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
      })
      .rpc();

    const tokenAccount = await splToken.getAccount(provider.connection, token);
    assert.ok(new anchor.BN(tokenAccount.amount.toString()).eq(withdrawAmount));
  });

  it("Should succesfully unlock a locked reward after unstaking", async () => {
    // Get Staker account
    const stakerAccount = await poolManager.account.staker.fetch(
      staker.publicKey
    );

    const token = await createTokenAccount(
      provider,
      mint,
      provider.wallet.publicKey
    );

    const withdrawAmount = new anchor.BN(7);
    await lockerManager.methods
      .withdraw(withdrawAmount)
      .accounts({
        locker: rewarderLocker.publicKey,
        beneficiary: provider.wallet.publicKey,
        token,
        vault: rewarderLockerVault.publicKey,
        lockerVaultAuthority: rewarderLockerVaultAuthority,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
        clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
      })
      // TODO: trait methods generated on the client. Until then, we need to manually
      //       specify the account metas here.
      .remainingAccounts([
        {
          pubkey: rewardKeeper.programId,
          isWritable: false,
          isSigner: false,
        },
        { pubkey: poolManager.programId, isWritable: false, isSigner: false },
        // check_releasibility
        { pubkey: staker.publicKey, isWritable: false, isSigner: false },
        {
          pubkey: stakerVault.vaultPoolToken,
          isWritable: false,
          isSigner: false,
        },
        {
          pubkey: stakerVaultLocked.vaultPoolToken,
          isWritable: false,
          isSigner: false,
        },
        // StakerData
        { pubkey: stakerAccount.pool, isWritable: false, isSigner: false },
        {
          pubkey: stakerAccount.beneficiary,
          isWritable: false,
          isSigner: false,
        },
        { pubkey: stakerAccount.metadata, isWritable: false, isSigner: false },
        {
          pubkey: stakerAccount.stakerVault.vaultPoolToken,
          isWritable: false,
          isSigner: false,
        },
        {
          pubkey: stakerAccount.stakerVaultLocked.vaultPoolToken,
          isWritable: false,
          isSigner: false,
        },
      ])
      .rpc();

    const tokenAccount = await splToken.getAccount(provider.connection, token);
    assert.ok(new anchor.BN(tokenAccount.amount.toString()).eq(withdrawAmount));
  });
});
