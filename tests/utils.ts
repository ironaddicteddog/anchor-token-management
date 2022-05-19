import * as anchor from "@project-serum/anchor";
import * as splToken from "@solana/spl-token";
import { Keypair } from "@solana/web3.js";

export async function createBalanceSandbox(provider, r, registrySigner) {
  const spt = Keypair.generate();
  const vault = Keypair.generate();
  const vaultStake = Keypair.generate();
  const vaultPw = Keypair.generate();

  const lamports = await provider.connection.getMinimumBalanceForRentExemption(
    165
  );

  const createSptIx = await createTokenAccountInstrs(
    provider,
    spt.publicKey,
    r.poolMint,
    registrySigner,
    lamports
  );
  const createVaultIx = await createTokenAccountInstrs(
    provider,
    vault.publicKey,
    r.mint,
    registrySigner,
    lamports
  );
  const createVaultStakeIx = await createTokenAccountInstrs(
    provider,
    vaultStake.publicKey,
    r.mint,
    registrySigner,
    lamports
  );
  const createVaultPwIx = await createTokenAccountInstrs(
    provider,
    vaultPw.publicKey,
    r.mint,
    registrySigner,
    lamports
  );
  let tx0 = new anchor.web3.Transaction();
  tx0.add(
    ...createSptIx,
    ...createVaultIx,
    ...createVaultStakeIx,
    ...createVaultPwIx
  );
  let signers0 = [spt, vault, vaultStake, vaultPw];

  const tx = { tx: tx0, signers: signers0 };

  return [
    tx,
    {
      vault: vault.publicKey,
      vaultStaked: vaultStake.publicKey,
      vaultPendingWithdrawal: vaultPw.publicKey,
      vaultPoolToken: spt.publicKey,
    },
  ];
}

// From @project-serum/commmon

export async function createMint(
  provider: anchor.AnchorProvider,
  authority?: anchor.web3.PublicKey,
  decimals?: number
): Promise<anchor.web3.PublicKey> {
  if (authority === undefined) {
    authority = provider.wallet.publicKey;
  }
  const mint = new anchor.web3.Keypair();
  let instructions = [
    anchor.web3.SystemProgram.createAccount({
      fromPubkey: provider.wallet.publicKey,
      newAccountPubkey: mint.publicKey,
      space: 82,
      lamports: await provider.connection.getMinimumBalanceForRentExemption(82),
      programId: splToken.TOKEN_PROGRAM_ID,
    }),
    splToken.createInitializeMintInstruction(
      mint.publicKey,
      decimals ?? 0,
      authority,
      null
    ),
  ];

  const tx = new anchor.web3.Transaction();
  tx.add(...instructions);

  await provider.sendAndConfirm(tx, [mint]);

  return mint.publicKey;
}

export async function createMintAndVault(
  provider: anchor.AnchorProvider,
  amount: anchor.BN,
  owner?: anchor.web3.PublicKey,
  decimals?: number
): Promise<[anchor.web3.PublicKey, anchor.web3.PublicKey]> {
  if (owner === undefined) {
    owner = provider.wallet.publicKey;
  }
  const mint = new anchor.web3.Keypair();
  const vault = new anchor.web3.Keypair();
  const tx = new anchor.web3.Transaction();
  tx.add(
    anchor.web3.SystemProgram.createAccount({
      fromPubkey: provider.wallet.publicKey,
      newAccountPubkey: mint.publicKey,
      space: 82,
      lamports: await provider.connection.getMinimumBalanceForRentExemption(82),
      programId: splToken.TOKEN_PROGRAM_ID,
    }),
    splToken.createInitializeMintInstruction(
      mint.publicKey,
      decimals ?? 0,
      provider.wallet.publicKey,
      null
    ),
    anchor.web3.SystemProgram.createAccount({
      fromPubkey: provider.wallet.publicKey,
      newAccountPubkey: vault.publicKey,
      space: 165,
      lamports: await provider.connection.getMinimumBalanceForRentExemption(
        165
      ),
      programId: splToken.TOKEN_PROGRAM_ID,
    }),
    splToken.createInitializeAccountInstruction(
      vault.publicKey,
      mint.publicKey,
      owner
    ),
    splToken.createMintToInstruction(
      mint.publicKey,
      vault.publicKey,
      provider.wallet.publicKey,
      amount.toNumber()
    )
  );
  await provider.sendAndConfirm(tx, [mint, vault]);
  return [mint.publicKey, vault.publicKey];
}

export async function createTokenAccount(
  provider: anchor.AnchorProvider,
  mint: anchor.web3.PublicKey,
  owner: anchor.web3.PublicKey
): Promise<anchor.web3.PublicKey> {
  const vault = new anchor.web3.Keypair();
  const tx = new anchor.web3.Transaction();
  tx.add(
    ...(await createTokenAccountInstrs(provider, vault.publicKey, mint, owner))
  );
  await provider.sendAndConfirm(tx, [vault]);
  return vault.publicKey;
}

export async function createTokenAccountInstrs(
  provider: anchor.AnchorProvider,
  newAccountPubkey: anchor.web3.PublicKey,
  mint: anchor.web3.PublicKey,
  owner: anchor.web3.PublicKey,
  lamports?: number
): Promise<anchor.web3.TransactionInstruction[]> {
  if (lamports === undefined) {
    lamports = await provider.connection.getMinimumBalanceForRentExemption(165);
  }
  return [
    anchor.web3.SystemProgram.createAccount({
      fromPubkey: provider.wallet.publicKey,
      newAccountPubkey,
      space: 165,
      lamports,
      programId: splToken.TOKEN_PROGRAM_ID,
    }),
    splToken.createInitializeAccountInstruction(newAccountPubkey, mint, owner),
  ];
}

export function sleep(ms: number): Promise<any> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
