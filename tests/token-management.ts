import * as anchor from "@project-serum/anchor";
import NodeWallet from "@project-serum/anchor/dist/cjs/nodewallet";
import { IDL as lockerManagerIDL } from "../target/types/locker_manager";
import { IDL as poolManagerIDL } from "../target/types/pool_manager";
import { IDL as rewardKeeperIDL } from "../target/types/pool_reward_keeper";
import { Commitment, Connection } from "@solana/web3.js";

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

  it("Is initialized!", async () => {
    // Add your test here.
    const tx = await lockerManager.methods.initialize(new anchor.BN(0)).rpc();
    console.log("Your transaction signature", tx);
  });
});
