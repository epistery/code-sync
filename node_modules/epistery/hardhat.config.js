require('dotenv').config();
require('@nomiclabs/hardhat-ethers');

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.27",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      },
      evmVersion: "paris"  // JOC doesn't support PUSH0 opcode (introduced in shanghai)
    }
  },
  networks: {
    sepolia: {
      url: process.env.CHAIN_RPC_URL || "",
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
      chainId: 11155111
    },
    amoy: {
      url: process.env.CHAIN_RPC_URL || "",
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
      chainId: 80002
    },
    polygon: {
      url: process.env.CHAIN_RPC_URL || "https://polygon-rpc.com",
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
      chainId: 137
    },
    joc: {
      url: process.env.CHAIN_RPC_URL || "https://rpc-2.japanopenchain.org:8545",
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
      chainId: 81
    }
  },
  etherscan: {
    apiKey: {
      sepolia: process.env.ETHERSCAN_API_KEY || "",
      polygon: process.env.POLYGONSCAN_API_KEY || "",
      joc: "no-api-key-needed" // JOC explorer doesn't require API key
    },
    customChains: [
      {
        network: "joc",
        chainId: 81,
        urls: {
          apiURL: "https://explorer.japanopenchain.org/api",
          browserURL: "https://explorer.japanopenchain.org"
        }
      }
    ]
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  }
};
