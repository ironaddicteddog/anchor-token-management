# Deep Dive into Anchor by Implementing Token Management Program

**Author:** [@ironaddicteddog](https://twitter.com/ironaddicteddog), [@emersonliuuu](https://twitter.com/emersonliuuu)

**_[Updated at 2022.5.21]_**

> You can find the full code base [here](https://github.com/ironaddicteddog/anchor-token-management)

## What is Anchor?

There is a comprehensive explanation on the [official website](https://project-serum.github.io/anchor/getting-started/introduction.html). Let me just quote relative paragraphs here:

> Anchor is a framework for Solana's Sealevel runtime providing several convenient developer tools.
>
> If you're familiar with developing in Ethereum's Solidity, Truffle, web3.js, then the experience will be familiar. Although the DSL syntax and semantics are targeted at Solana, the high level flow of writing RPC request handlers, emitting an IDL, and generating clients from IDL is the same.

In short, Anchor gives you the following handy tools for developing Solana programs:

- **Rust crates and eDSL for writing Solana programs**
- **IDL specification**
- **TypeScript package for generating clients from IDL**
- **CLI and workspace management for developing complete applications**

You can watch [this awesome talk](https://youtu.be/cvW8EwGHw8U) given by Armani Ferrante at Breakpoint 2021 to feel the power of Anchor.

### Workflow

![](https://i.imgur.com/jkObSKO.jpg)

1. Develop the **program** (Smart Contract)
2. Build the program and export the **IDL**
3. Generate the **client** representation of program from the IDL to interact with the program

### Why Anchor?

- **Anchor is the new standard**
  - [apr.dev](https://apr.dev)
  - [anchor.so](https://anchor.so)
  - [anchor.projectserum.com](https://anchor.projectserum.com)
- Productivity
  - Make Solana program more intuitive to understand
  - More clear buisness Logic
  - Remove a ton of biolderplate code
- Security
  - Use **discriminator**
    - Discriminator is generated and inserted into the first 8 bytes of account data. Ex: `sha256("account:<MyAccountName>")[..8] || borsh(account_struct)`
    - Used for more secure account validation and function dispatch
    - See [this Twitter thread](https://twitter.com/armaniferrante/status/1411589634228772870) for more details
    - See [here](https://github.com/project-serum/anchor/blob/master/ts/src/program/namespace/index.ts#L53) and [here](https://github.com/project-serum/anchor/blob/master/lang/syn/src/codegen/program/dispatch.rs#L146) for the actual implementation
  - Implement most of the [best practices](https://github.com/project-serum/sealevel-attacks) of secure program

### Where can I learn more about Anchor?

- [Anchor Book](https://project-serum.github.io/anchor/)
- [Anchor Examples](https://github.com/project-serum/anchor/tree/master/tests)
- [`anchor-escrow`](https://book.solmeet.dev/notes/intro-to-anchor)

## Overview of Token Management

**Note: These programs are originated from Serum's [stake program](https://github.com/project-serum/stake) developed by Armani Ferrante.** There are a few things evolved from the original version:

- Upgrade Anchor to latest version (Currently `0.24.2`)
- Optimize some function invocation to avoid stack frame limit
- Rename struct and module to make them better reveal its designed purpose

In short, token management consist of two modules:

- **Locker Manager, which manages the vesting of locked tokens**
- **Pool Manager, which manages the mining of rewarded tokens**

### Vesting and Mining

- **Token vesting and mining are two fundenmental components of DeFi tokenomics**
- There are existed solutions.
  - Bonfida vesting
  - Quarry
  - ...
- `anchor-token-management` intergates vesting and mining modules and has the following features:
  - Written in Anchor
  - Modular and customizable condition of releasing rewards
  - Control funds even if its locked in locker. For example: desposit to pool from locker. (Not covered in this tutorial)

### Architecture

![](https://hackmd.io/_uploads/HJP76GYwc.png)

### Interfaces

|                    Locker                     |
| :-------------------------------------------: |
| ![](https://hackmd.io/_uploads/BJKSJr9D5.png) |
| ![](https://hackmd.io/_uploads/H1G9kS5Pc.png) |

<!-- - linear unlock
  - ![](https://hackmd.io/_uploads/rJuT1B9Pq.png)
 -->

|                Pool (Rewarder)                |
| :-------------------------------------------: |
| ![](https://hackmd.io/_uploads/SkEexr9P5.png) |
| ![](https://hackmd.io/_uploads/SJbObB9Pq.png) |
| ![](https://hackmd.io/_uploads/SkB9WS9D9.png) |
| ![](https://hackmd.io/_uploads/r192Zrqv9.png) |
| ![](https://hackmd.io/_uploads/B1-yGScwq.png) |

|                 Pool (Staker)                 |
| :-------------------------------------------: |
| ![](https://hackmd.io/_uploads/HkA4grcP9.png) |
| ![](https://hackmd.io/_uploads/HyIveS5w9.png) |
| ![](https://hackmd.io/_uploads/By6clBqv5.png) |
| ![](https://hackmd.io/_uploads/BJUaxBqP5.png) |
| ![](https://hackmd.io/_uploads/SJ6l-HcP9.png) |
| ![](https://hackmd.io/_uploads/BJLQ-r9vc.png) |
| ![](https://hackmd.io/_uploads/H1UrWBcw5.png) |

## Implementing Token Management Program in Anchor

### Prerequisites

- Basic layouts of Anchor programs
  - program
  - context
  - state
  - error
  - ...
- Anchor Constraints
  - `[account(mut)]`
  - `[account(init)]`
  - ...
- Token Program
  - Token Account
  - Mint
  - Transfer
  - Burn
- [`anchor-escrow`](https://book.solmeet.dev/notes/intro-to-anchor)

### To Be Covered

- PDA account creation and derivation
- Access control
- CPI usage
- Custimized Error

<!-- - ~~interface?~~
- ~~new ts syntax~~
- ~~invoke and invoke_signed~~
- ~~Identifier vs Discriminator~~
- ~~Remaining accounts~~
- ~~Avoid stack frame limit~~
- ~~account size limit (max len of an array)~~ -->

<!-- ### Setup

```bash
$ anchor init anchor-token-management
```
```bash
$ anchor new locker-manager
```
```bash
$ anchor new pool-manager
```
```bash
$ anchor new pool-reward-locker
```
```bash
$ rm -rf programs/anchor-token-management
```
 -->

### Step 1: Scaffolding

- Checkout to [`step-1`](https://github.com/ironaddicteddog/anchor-token-management/tree/step-1) branch to see the full code
- In this step, we scaffold the programs by following the interfaces explained above:
  - Implement `LockerManager`
  - Implement `PoolManager`
  - Implement `PoolRewardKeeper`

### Part 2: Implementing

- Checkout to [`step-2`](https://github.com/ironaddicteddog/anchor-token-management/tree/step-2) branch to see the full code
- In this step, we implement all the functions, context and states without concerning the security issues:
  - Add all contexts and states
  - Add utils
    - `calculator`
    - `RewardQueue`
  - Add [constraints](https://docs.rs/anchor-lang/0.24.2/anchor_lang/derive.Accounts.html)
    - PDA creation and derivation
    - `has_one`
    - Raw constraints
    - ...

> Tips: you can use `git diff` to see what changes have been made:
>
> ```bash
> $ git checkout step-2
> $ git diff step-1
> ```

### Part 3: Improving Security

- Checkout to [`step-3`](https://github.com/ironaddicteddog/anchor-token-management/tree/step-3) branch to see the full code
- In this step, we improve the security:
  - Implement access control and security check
  - Customize error

> Tips: you can use `git diff` to see what changes have been made:
>
> ```
> $ git checkout step-3
> $ git diff step-2
> ```

## More Advanced Topics

Control funds even if its locked in locker. For example: desposit to pool from locker. See the full [code base](https://github.com/ironaddicteddog/anchor-token-management) for details.

- `withdraw_to_whitelist`
- `deposit_from_locker`
- `withdraw_to_locker`

## Referneces

- https://book.anchor-lang.com
- https://solanacookbook.com
- https://book.solmeet.dev/notes/intro-to-anchor
- https://github.com/project-serum/stake/blob/master/docs/staking.md
- https://docs.rs/anchor-lang/0.24.2/anchor_lang/derive.Accounts.html
