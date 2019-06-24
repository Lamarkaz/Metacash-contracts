# Metacash V2 Contracts (WIP)
This repo contains the solidity smart contracts of Metacash V2 smart wallets.
V2 adds support for abstract meta-transactions to arbitrary contracts to allow for what's known as Ethereum economic abstraction.
The contracts are not yet secure and should not yet be deployed on the mainnet.

## Deployment flow

1. Deploy Relay Registry
2. Add Relay Registry address to Factory source and SmartWallet source
3. Deploy SmartWallet contract
4. Add SmartWallet address to Proxy source
5. Deploy Factory
