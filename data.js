window.BENCHMARK_DATA = {
  "lastUpdate": 1748014018825,
  "repoUrl": "https://github.com/lambdaclass/ethrex",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "name": "lambdaclass",
            "username": "lambdaclass"
          },
          "committer": {
            "name": "lambdaclass",
            "username": "lambdaclass"
          },
          "id": "9cabb0961d7d0e5d1ac96306c40ec16ed1620b3a",
          "message": "feat(core): bench workflow",
          "timestamp": "2025-03-12T18:31:00Z",
          "url": "https://github.com/lambdaclass/ethrex/pull/2190/commits/9cabb0961d7d0e5d1ac96306c40ec16ed1620b3a"
        },
        "date": 1741834445313,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 230999121163,
            "range": "± 404755845",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "cd5ddb710bfb077a0cc442437f7250f60e4897d1",
          "message": "feat(core): bench workflow (#2190)\n\n**Motivation**\n\nThis PR adds a CI workflow that runs a criterion benchmark of importing\n1000 blocks with erc20 transfers, and posts the result to gh pages, to\ntrack the performance by commit (so we can easily identify regressions).\nThis workflow runs only on pushes to `main`.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-03-13T17:22:26Z",
          "tree_id": "c1d7f35814a9ea9a64f3a316a370bc1429959c57",
          "url": "https://github.com/lambdaclass/ethrex/commit/cd5ddb710bfb077a0cc442437f7250f60e4897d1"
        },
        "date": 1741890047540,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 222834821209,
            "range": "± 1241048933",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "40bc3df8f055f0e205e41028ea08d4192351546c",
          "message": "fix(core): fix flamegraph reporter workflow (#2221)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-03-13T18:33:10Z",
          "tree_id": "e1ff157c6435c4ebecf71922737365f437f875a8",
          "url": "https://github.com/lambdaclass/ethrex/commit/40bc3df8f055f0e205e41028ea08d4192351546c"
        },
        "date": 1741894305496,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 228890170082,
            "range": "± 2113501115",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ace63e070da474cd4fa1dc2943e8d31c01c1aa7f",
          "message": "fix(core): fix flamegraph reporter checking out github pages (#2223)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-03-13T21:31:49Z",
          "tree_id": "a1f4b7b169da04608770d28c10f639ccb85f89e0",
          "url": "https://github.com/lambdaclass/ethrex/commit/ace63e070da474cd4fa1dc2943e8d31c01c1aa7f"
        },
        "date": 1741904999705,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 223601049448,
            "range": "± 621095801",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "72628438+avilagaston9@users.noreply.github.com",
            "name": "Avila Gastón",
            "username": "avilagaston9"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "db6b5129c648c63b2dc54cc03fd807f18d9a27fd",
          "message": "feat(l2): add P256Verify precompile (#2186)\n\n**Motivation**\n\nWe want to support signature verifications using the “secp256r1”\nelliptic curve.\n\n**Description**\n\nImplements\n[RIP-7212](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md),\nadding a new precompiled contract to levm. The contract is only\nactivated under the \"l2\" feature.\n\nCloses #2148",
          "timestamp": "2025-03-14T00:24:00Z",
          "tree_id": "b0b76c969a46387d059dceee423ec899f9e578b1",
          "url": "https://github.com/lambdaclass/ethrex/commit/db6b5129c648c63b2dc54cc03fd807f18d9a27fd"
        },
        "date": 1741915350936,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 225172082329,
            "range": "± 421731711",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b7badba4ccec20d68f722661084c0dc08d92fa44",
          "message": "fix(l1): add prague timestamps to holesky & sepolia genesis (#2215)\n\n**Motivation**\nHolesky and Sepolia testnets have moved on to Prague but we haven't\nregistered this in their preset chain config, causing us to reject all\nnewPayloadV4 requests as we asume the block to be Cancun instead of\nPrague. This PR fixes this by adding the Prague timestamps for both\nnetworks.\nThe timestamps were taken from\n[geth](https://github.com/ethereum/go-ethereum/blob/f3e4866073d4650a7f461315c517333c6407ab5c/params/config.go#L99)",
          "timestamp": "2025-03-14T13:54:23Z",
          "tree_id": "6ced125528fccd262cdc550d3da13e3a68e1bfdc",
          "url": "https://github.com/lambdaclass/ethrex/commit/b7badba4ccec20d68f722661084c0dc08d92fa44"
        },
        "date": 1741963997637,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 225407839111,
            "range": "± 1011564156",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomas.orsi@lambdaclass.com",
            "name": "Tomas Fabrizio Orsi",
            "username": "lima-limon-inc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "ca4dfc05837084100ae8049ce55b20a71fc34a2e",
          "message": "chore(l1): revert conditional docker building logic (#2196)\n\n**Motivation**\n\n#2175 introduced an additional compilation check regarding L1 client for\nthe hive tests. The check was that to avoid building the `ethrex` docker\nimage if it was not being used.\n\nThe check added additional complexity whilst not providing a lot of\nutility, since the ethrex docker image would have to be built\nregardless; since the only point of using a different L1 Client was to\ncompare against `ethrex`.\n\n**Description**\n\nRemove the if statement that provided the conditional compilation of the\n`ethrex` docker image.\n\nAlso remove an additional `HIVE_LOGLEVEL` that was not present in the\nMakefile before.\n\n---------\n\nSigned-off-by: Tomas Fabrizio Orsi <tomas.orsi@lambdaclass.com>",
          "timestamp": "2025-03-14T16:03:06Z",
          "tree_id": "1fb22211975765b37bd1497dce7fb0c486e2cd20",
          "url": "https://github.com/lambdaclass/ethrex/commit/ca4dfc05837084100ae8049ce55b20a71fc34a2e"
        },
        "date": 1741971664932,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 224507493580,
            "range": "± 468683788",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "892d5adb946de77d2be9586e44225ab702622e99",
          "message": "fix(core): fix slack flamegraphs link (#2228)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-03-14T16:08:02Z",
          "tree_id": "b7717f1f6bff8116efcc079adc9e3f1240c95269",
          "url": "https://github.com/lambdaclass/ethrex/commit/892d5adb946de77d2be9586e44225ab702622e99"
        },
        "date": 1741971968928,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 224225831163,
            "range": "± 1129255460",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "d1655468ef758690587d016a2ecd5477d883e465",
          "message": "fix(core): fix benchmark to use the CI genesis file (#2229)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number\n\nCo-authored-by: Francisco Krause Arnim <56402156+fkrause98@users.noreply.github.com>",
          "timestamp": "2025-03-14T18:34:30Z",
          "tree_id": "6435817883da697960c74920cbe8b6021e87b2fc",
          "url": "https://github.com/lambdaclass/ethrex/commit/d1655468ef758690587d016a2ecd5477d883e465"
        },
        "date": 1741980809693,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 229781371145,
            "range": "± 462190827",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "0e5bd4b7bf369c9a409324e785801b03d6c997e2",
          "message": "feat(l2): add a blobs saver command to store state diffs (#2194)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nWe need a tool to store state diffs blobs offline so the L2 state is\nreconstructable after 2 weeks, when blobs got deleted on L1.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nThis PR adds a command to the L2 CLI (`ethrex_l2 stack blobs-saver`)\nthat runs a service which continuously looks for new Commit events in\nthe `OnChainProposer` contract and downloads its blobs in the local\nfilesystem.\nIt uses a both EL and CL RPCs\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #1196\n\n---------\n\nCo-authored-by: Ivan Litteri <67517699+ilitteri@users.noreply.github.com>",
          "timestamp": "2025-03-14T19:54:25Z",
          "tree_id": "42a295d873e68414c55a2c68d57893933295ee2c",
          "url": "https://github.com/lambdaclass/ethrex/commit/0e5bd4b7bf369c9a409324e785801b03d6c997e2"
        },
        "date": 1741985585803,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 225890114363,
            "range": "± 4382620813",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "567d32c9a623307a3ed0f513667953a467f7fdde",
          "message": "feat(core): add `p2p.enabled` flag (#2230)\n\n**Motivation**\n\nIn most of the L2 use cases we want to disable de P2P network.\n\n**Description**\n\nAdd a `p2p.enabled` flag for users to explicit whether they want to\nenable the P2P in their node.\n\nIt is enabled by default in the L1 and disabled by default for the L2.",
          "timestamp": "2025-03-14T19:55:10Z",
          "tree_id": "cee66b1dc342d7c8999f4bf6d5c4cdef69f3c46c",
          "url": "https://github.com/lambdaclass/ethrex/commit/567d32c9a623307a3ed0f513667953a467f7fdde"
        },
        "date": 1741985648213,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 227042419601,
            "range": "± 1019661927",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "156438142+fborello-lambda@users.noreply.github.com",
            "name": "Federico Borello",
            "username": "fborello-lambda"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9f0148fba23984175609aee1eb4acdb54b09e390",
          "message": "feat(levm): pectra-devnet6 eftests (#1877)\n\n**Motivation**\n\nThe latest test for pectra has been released. [Pectra Devnet 6\n](https://github.com/ethereum/execution-spec-tests/releases/tag/pectra-devnet-6%40v1.0.0)\n\n**Description**\n\n- Download latest tests\n- Add eip7702 latest changes: https://github.com/ethereum/EIPs/pull/9248\n- Add a new CI rule for EF Tests to be 100% from London to Prague forks\n- Fix tests from `set_code_txs_2` and `refunds` belonging to EIP 7702\nand EIP 7623\n\n---------\n\nCo-authored-by: Javier Chatruc <jrchatruc@gmail.com>\nCo-authored-by: Tomás Paradelo <tomas.paradelo@lambdaclass.com>",
          "timestamp": "2025-03-17T14:25:36Z",
          "tree_id": "c2996d7b99e333fabd413e652fa751a2f65d0af0",
          "url": "https://github.com/lambdaclass/ethrex/commit/9f0148fba23984175609aee1eb4acdb54b09e390"
        },
        "date": 1742225078844,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 225391645830,
            "range": "± 1168069964",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "72628438+avilagaston9@users.noreply.github.com",
            "name": "Avila Gastón",
            "username": "avilagaston9"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "35d3462d07ec1e0f224280c3a4dd81097e5de66e",
          "message": "feat(l1): enforce deposit contract address (#2118)\n\n**Motivation**\n\nTo avoid issues mixing the `DepositContractAddress` across different\nnetworks.\n\n**Description**\n\n- Enforce setting `deposit_contract_address` from the genesis files.\n- Remove the `MAINNET_DEPOSIT_CONTRACT_ADDRESS` constant.\n- Update unit tests to use a mock address.\n- Update the `network_params` files to include the\n`deposit_contract_address`.\n- Add the correct `deposit_contract_address` for Holesky.\n\nCloses #2082",
          "timestamp": "2025-03-17T15:08:43Z",
          "tree_id": "879e0564990ee0e55493f7a7dac4b069d21a3cd8",
          "url": "https://github.com/lambdaclass/ethrex/commit/35d3462d07ec1e0f224280c3a4dd81097e5de66e"
        },
        "date": 1742227628303,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 225727773861,
            "range": "± 535842569",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "76d3ee9afa428b5cf8869b00f8a2f4b7d5c119ca",
          "message": "feat(l1): remove deprecated mekong testnet (#2243)\n\n**Motivation**\n\nMekong testnet has been [officially\ndeprecated](https://blog.ethereum.org/en/2025/03/06/mekong-devnet)\n\n**Description**\n\nRemove `mekong` as a preset network option and remove associated data\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-03-17T16:01:55Z",
          "tree_id": "61102444d122a2c8c6e8fdd5c9b40242be72c332",
          "url": "https://github.com/lambdaclass/ethrex/commit/76d3ee9afa428b5cf8869b00f8a2f4b7d5c119ca"
        },
        "date": 1742230945110,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 234091245744,
            "range": "± 2223166116",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "39c8e480507d5a5e6f5d12c61e41eba3f1036462",
          "message": "fix(l2): small fixes and refactors (#2241)\n\n**Motivation**\n\nThis PR makes a few fixes and changes to ethrex l2:\n\n- Moves the block building logic to a separate file/task called\n`block_producer`, more in line with our current vocabulary.\n- Fixes an issue where the prover server in dev mode would wait using\n`thread::sleep` instead of `tokio::time::sleep`, sometimes hanging the\nruntime.\n- Adds a `dev_interval_ms` config option to the prover server to\nconfigure, in dev mode, how often it sends (empty) proofs to the L1.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number\n\n---------\n\nCo-authored-by: Ivan Litteri <67517699+ilitteri@users.noreply.github.com>",
          "timestamp": "2025-03-17T16:26:33Z",
          "tree_id": "181c54b5ba2d5abaf5d00444fad8294bb43290a8",
          "url": "https://github.com/lambdaclass/ethrex/commit/39c8e480507d5a5e6f5d12c61e41eba3f1036462"
        },
        "date": 1742232347655,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 228869982757,
            "range": "± 840452460",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "a07f74ffd7086e94c0cf8da04e5fd9eed6bb2450",
          "message": "ci(l1): refine posting daily reports to slack. (#2170)\n\n**Motivation**\nRemove posting of some reports to L1 channel.",
          "timestamp": "2025-03-17T16:29:02Z",
          "tree_id": "76478a9c0cfb8097bb8a9481b087d3c5ff6f558b",
          "url": "https://github.com/lambdaclass/ethrex/commit/a07f74ffd7086e94c0cf8da04e5fd9eed6bb2450"
        },
        "date": 1742232433382,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 224568254546,
            "range": "± 376027366",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mrugiero@gmail.com",
            "name": "Mario Rugiero",
            "username": "Oppen"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "58443717c6f5dd2b1d434af1c1483ea814f9ef35",
          "message": "refactor(levm): simplify fill_with_zeros (#2226)\n\nReviewing #2186 I noticed we had this helper that returned a `Result`\nfor a logically impossible situation (already covered by an `if` just\nabove it).\nI removed that `Result` and also simplified the logic by just calling\n`resize` in the appropriate case.",
          "timestamp": "2025-03-17T18:56:32Z",
          "tree_id": "8a20738b3cc89eaa2d1dcc8b091ef3315d63b739",
          "url": "https://github.com/lambdaclass/ethrex/commit/58443717c6f5dd2b1d434af1c1483ea814f9ef35"
        },
        "date": 1742241293769,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 226462891870,
            "range": "± 852500902",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "eb0629cb88e754da18dbc279f3b545f6ac0cf047",
          "message": "docs(core): remove milestones and cleanup readme (#2248)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-03-17T18:58:20Z",
          "tree_id": "bdabf9ad88f96c6f410801f6f64b6c70edba2df2",
          "url": "https://github.com/lambdaclass/ethrex/commit/eb0629cb88e754da18dbc279f3b545f6ac0cf047"
        },
        "date": 1742241370039,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 223547007715,
            "range": "± 625519400",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "104ef77ae137b6ee14de6945c6c49d223e735ba6",
          "message": "feat(l2): pico prover (#1922)\n\n**Motivation**\n\nAdds [Pico](https://pico-docs.brevis.network/) as a prover backend. \n\nAlso does a major refactor to remove the need to have multiple zkvm\ndependencies compiling at the same time, this is because Pico doesn't\ncompile while also having Risc0 as dependency; the linker fails with a\n\"duplicated symbols\" error.\n\nAlso removes zkvm dependencies from crates that don't need them by\ndecoupling return types. This is because Pico compiles with nightly only\nand we want to minimize the number of crates that depend on it (now only\n`ethrex-prover` and `zkvm_interface` does)\n\n**Description**\n\n- adds pico as prover backend\n- decouples zkvm dependencies from other L2 crates by doing a major\nrefactor of provers\n- makes it so you can compile the prover client with only one backend at\na time\n- makes the prover client return the proof calldata to send to the L1\nbridge contract instead of the proofs using each custom type of every\nzkvm\n\n---------\n\nCo-authored-by: Mario Rugiero <mrugiero@gmail.com>\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>",
          "timestamp": "2025-03-17T19:18:17Z",
          "tree_id": "0f62ae1a5aeb11269b1501121a2e71fcefa29667",
          "url": "https://github.com/lambdaclass/ethrex/commit/104ef77ae137b6ee14de6945c6c49d223e735ba6"
        },
        "date": 1742242535817,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 227682387813,
            "range": "± 938087967",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "72628438+avilagaston9@users.noreply.github.com",
            "name": "Avila Gastón",
            "username": "avilagaston9"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "1c3cb981e7770e532330133292d13a5fc657ce61",
          "message": "feat(levm): implement simulate_tx (#2232)\n\n**Motivation**\n\nTo implement the remaining RPC endpoints.\n\n**Description**\n\n- Implements `simulate_tx_from_generic` for LEVM.\n- If `gas_price` is not specified, sets `env.base_fee_per_gas =\nU256::zero()` to avoid base fee checks.\n- Moves `ExecutionResult` to `vm/backends` to be used by both REVM and\nLEVM.\n\nWith this PR, only the `rpc/eth_createAccessList` tests are failing.\n\nCloses #2182",
          "timestamp": "2025-03-18T14:17:30Z",
          "tree_id": "56ae1dbf03a0cfff8919bf8bfd6c98bf6b0104aa",
          "url": "https://github.com/lambdaclass/ethrex/commit/1c3cb981e7770e532330133292d13a5fc657ce61"
        },
        "date": 1742310920611,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 231242084441,
            "range": "± 1377277024",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "87fc76a74cda059d2bcf25172d26d69bd9fcd8e8",
          "message": "chore(core): improve double genesis block run error (#2252)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\nIt is not obvious how to mitigate this error for users who find\nthemselves having this error. Having a better better error comment might\nhelp with this.",
          "timestamp": "2025-03-18T16:24:26Z",
          "tree_id": "7189f240dfe1af7133b042b74fdc45bf61230440",
          "url": "https://github.com/lambdaclass/ethrex/commit/87fc76a74cda059d2bcf25172d26d69bd9fcd8e8"
        },
        "date": 1742318437363,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 228403691215,
            "range": "± 1044381859",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "56402156+fkrause98@users.noreply.github.com",
            "name": "Francisco Krause Arnim",
            "username": "fkrause98"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8c363aad60f4af75c1756cac6ad42368475b9a56",
          "message": "ci(l1,l2): always compare with main (#2253)\n\n**Motivation**\n\nThis is useful to always compare changes with main, regardless of the\nbranch.",
          "timestamp": "2025-03-18T18:44:46Z",
          "tree_id": "af8acb1009ed004fadaf3f475b70ea1a6e3f29dd",
          "url": "https://github.com/lambdaclass/ethrex/commit/8c363aad60f4af75c1756cac6ad42368475b9a56"
        },
        "date": 1742326816205,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 228981095719,
            "range": "± 1067523608",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5264f986a96ca89cda8e9436195a008ee50940a9",
          "message": "chore(l2): remove db when restarting (#2257)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n`make restart` should mean \"having initialized the network previously,\nstart over from scratch\".\n\nIn reality, this wasn't happening since both the L1 and L2 databases\nwere not being restarted.\n\n**Description**\n\nRestart L1 and L2 dbs when doing `make restart`.",
          "timestamp": "2025-03-18T23:10:02Z",
          "tree_id": "99d8dee59da3f19c983f3d05c22bfadcf5545dbd",
          "url": "https://github.com/lambdaclass/ethrex/commit/5264f986a96ca89cda8e9436195a008ee50940a9"
        },
        "date": 1742342953217,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 229927631621,
            "range": "± 1713766248",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "0b51b10a9623159780641a0d1e35a4c4a788b952",
          "message": "feat(l2): sponsored transaction endpoints (#2214)\n\n**Motivation**\n\nWe want to add a new rpc endpoint that sponsors eip-7702 and eip-1559\nthat calls to addresses that are delegated to whitelisted contracts.\n\n**Description**\n\n- Add new namespace `ethrex` to rpc crate\n- Add feature \"l2\" rpc crate\n- Add new flag to ethrex cmd to provide a file with addresses for\ncontracts we want to sponsor txs to\n- Add new endpoint `ethrex_SendTransaction` that sponsor txs that are\n  - EIP-7702 tx with access list delegating to a whitelisted contract\n- EIP-1559 tx that call to an address that is delegated (starts with\n0xef0100) and the address that it delegates to is whitelisted\n  - Create transactions (to=0x0) are not allowed\n\n**Resources**\nhttps://ithaca.xyz/updates/exp-0000\nhttps://github.com/ithacaxyz/odyssey\nhttps://eips.ethereum.org/EIPS/eip-7702\n\n---------\n\nCo-authored-by: Ivan Litteri <67517699+ilitteri@users.noreply.github.com>",
          "timestamp": "2025-03-19T15:37:48Z",
          "tree_id": "fd307c9d44d5b6801ac6200f63acb42ff9eb6c27",
          "url": "https://github.com/lambdaclass/ethrex/commit/0b51b10a9623159780641a0d1e35a4c4a788b952"
        },
        "date": 1742402191776,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 229899677477,
            "range": "± 744277514",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "f1693f5490035e9244fac5e365792bf7830daa9c",
          "message": "refactor(core): ethrex cli (#2240)\n\n**Motivation**\n\nTo improve `ethrex`'s CLI readability and extensibility.\n\n**Description**\n\nThis PR refactors de CLI to use clap derive instead of clap builder\napproach. Using the latter suited perfectly for the first version but as\nwe keep adding flags/args and subcommands, using the the first is better\nfor readability and also extensibility.\n\nIn the new design, the CLI is modeled as the struct `CLI` as follows:\n\n```Rust\npub struct CLI {\n    #[clap(flatten)]\n    pub opts: Options,\n    #[cfg(feature = \"based\")]\n    #[clap(flatten)]\n    pub based_opts: BasedOptions,\n    #[command(subcommand)]\n    pub command: Option<Subcommand>,\n}\n```\n\nwhere `opts` are the flags corresponding to `ethrex` common usage,\n`based_opts` are the flags needed when running `ethrex` with the `based`\nfeature, and `command` is an enum containing the subcommands\n(`removedb`, and `import` for now) which is optional.\n\nIf you'd want to add a new subcommand, simply add it to the `Subcommand`\nenum and implement its handler in the `Subcommand::run` `match`.\n\nThe CLI args are contained in `Options` and `BasedOptions`. Adding a new\nflag/arg would mean to add a field on the corresponding struct, and if\nyou want for example to add flags/args for the L2 feature it'd be good\nfor you to create an `L2Options` struct with them. The\n`#[clap(flatten)]` basically \"unpacks\" the struct fields (args and\nflags) for the CLI.\n\nRunning `cargo run --release --bin ethrex -- --help` displays:\n\n```Shell\nUsage: ethrex [OPTIONS] [COMMAND]\n\nCommands:\n  removedb  Remove the database\n  import    Import blocks to the database\n  help      Print this message or the help of the given subcommand(s)\n\nOptions:\n  -h, --help\n          Print help (see a summary with '-h')\n\n  -V, --version\n          Print version\n\nRPC options:\n      --http.addr <ADDRESS>\n          Listening address for the http rpc server.\n\n          [default: localhost]\n\n      --http.port <PORT>\n          Listening port for the http rpc server.\n\n          [default: 8545]\n\n      --authrpc.addr <ADDRESS>\n          Listening address for the authenticated rpc server.\n\n          [default: localhost]\n\n      --authrpc.port <PORT>\n          Listening port for the authenticated rpc server.\n\n          [default: 8551]\n\n      --authrpc.jwtsecret <JWTSECRET_PATH>\n          Receives the jwt secret used for authenticated rpc requests.\n\n          [default: jwt.hex]\n\nNode options:\n      --log.level <LOG_LEVEL>\n          Possible values: info, debug, trace, warn, error\n\n          [default: INFO]\n\n      --network <GENESIS_FILE_PATH>\n          Alternatively, the name of a known network can be provided instead to use its preset genesis file and include its preset bootnodes. The networks currently supported include Holesky, Sepolia and Mekong.\n\n      --datadir <DATABASE_DIRECTORY>\n          If the datadir is the word `memory`, ethrex will use the `InMemory Engine`.\n\n          [default: ethrex]\n\n      --metrics.port <PROMETHEUS_METRICS_PORT>\n\n\n      --dev\n          If set it will be considered as `true`. The Binary has to be built with the `dev` feature enabled.\n\n      --evm <EVM_BACKEND>\n          Has to be `levm` or `revm`\n\n          [default: revm]\n\nP2P options:\n      --p2p.enabled\n\n\n      --p2p.addr <ADDRESS>\n          [default: 0.0.0.0]\n\n      --p2p.port <PORT>\n          [default: 30303]\n\n      --discovery.addr <ADDRESS>\n          UDP address for P2P discovery.\n\n          [default: 0.0.0.0]\n\n      --discovery.port <PORT>\n          UDP port for P2P discovery.\n\n          [default: 30303]\n\n      --bootnodes <BOOTNODE_LIST>...\n          Comma separated enode URLs for P2P discovery bootstrap.\n\n      --syncmode <SYNC_MODE>\n          Can be either \"full\" or \"snap\" with \"full\" as default value.\n\n          [default: full]\n```",
          "timestamp": "2025-03-19T19:11:51Z",
          "tree_id": "26cb3cbe5bc142445ae282bef6c4b2f66bba1f80",
          "url": "https://github.com/lambdaclass/ethrex/commit/f1693f5490035e9244fac5e365792bf7830daa9c"
        },
        "date": 1742414923389,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 226275017717,
            "range": "± 1327541083",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "156438142+fborello-lambda@users.noreply.github.com",
            "name": "Federico Borello",
            "username": "fborello-lambda"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "652ffd357827ba5a390062ef4479f882b1ce4119",
          "message": "chore(l2): fix lint (#2271)\n\n**Motivation**\n\nThe linter was failing\n\n**Description**\n\n- Update the `lint` target\n- Implement the suggestions made by clippy",
          "timestamp": "2025-03-19T19:28:20Z",
          "tree_id": "38a24c5b9957f616967cde9b9c548f6bbf4918e8",
          "url": "https://github.com/lambdaclass/ethrex/commit/652ffd357827ba5a390062ef4479f882b1ce4119"
        },
        "date": 1742415934117,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 227444733037,
            "range": "± 635540582",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "d38ee5932da6c9d667f2267646f81e839b1fe3c3",
          "message": "refactor(l2): add flag for setting sponsor private key (#2281)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\nThe current implementation requires a `.env` file to exist and the\nexecution panics if this file does not exist. Nevertheless, this has a\npurpose of being. As this feature should be used in `l2` it is assumed\nthat there's a `.env` file and that is ok because it should. This PR\nintends to add a second path for setting the sponsor pk without needing\na `.env`.\n\n**Description**\n\nAdd a flag `--sponsor-private-key` as a second option for setting this\nvalue.",
          "timestamp": "2025-03-20T16:48:16Z",
          "tree_id": "d21d99b7d4992673f2d8352fa4c5e49e6c1fd55b",
          "url": "https://github.com/lambdaclass/ethrex/commit/d38ee5932da6c9d667f2267646f81e839b1fe3c3"
        },
        "date": 1742492643359,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 231005160866,
            "range": "± 1266839643",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "d964a2fece5ad19273b02aa5081b6a85609437dc",
          "message": "chore(core): add `rust-toolchain.toml` (#2278)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nWe have a pinned version of Rust in the CI and also in `.tool-versions`\n(for `asdf`) but not for `rustup`. We encountered ourselves running\ndifferent versions of Rust, with different results, specially when\nrunning tools like Clippy\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nAdded a `rust-toolchain.toml` file with the pinned version of Rust so\nit's evaluated by default when using `rustup`. As a side effect, needed\nto change the way Pico CLI is installed in the CI.",
          "timestamp": "2025-03-20T18:21:32Z",
          "tree_id": "bcc88ad5fae1cf708aacd02da9f6c9ae1d647967",
          "url": "https://github.com/lambdaclass/ethrex/commit/d964a2fece5ad19273b02aa5081b6a85609437dc"
        },
        "date": 1742498237074,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 229011647065,
            "range": "± 410351860",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "72628438+avilagaston9@users.noreply.github.com",
            "name": "Avila Gastón",
            "username": "avilagaston9"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "31dd81a4a8a26640c365a1eb58180f98d4f663c2",
          "message": "fix(l1): enable CORS for rpc endpoints (#2275)\n\n**Motivation**\n\nTo be used with different applications\n\n**Description**\n\nAdds a permissive CORS layer using\n[axum](https://docs.rs/axum/latest/axum/middleware/index.html) +\n[tower-http](https://docs.rs/tower-http/0.6.2/tower_http/cors/index.html).\n- All request headers allowed.\n- All methods allowed.\n- All origins allowed.\n- All headers exposed.\n\nCloses None",
          "timestamp": "2025-03-20T18:25:53Z",
          "tree_id": "149791b9bd1e6254a1f0bf5fa7fc5918a624cf0e",
          "url": "https://github.com/lambdaclass/ethrex/commit/31dd81a4a8a26640c365a1eb58180f98d4f663c2"
        },
        "date": 1742498482468,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 225153168984,
            "range": "± 875558649",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4f7024cdd9997138bb88ddb94f5721d0343ad95c",
          "message": "fix(l2): make TCP connection async (#2280)\n\n**Motivation**\n\nThe prover server-client TCP connection uses blocking primitive from the\nstandard library, so whenever one of the processes is expecting a\nconnection they don't yield control to the runtime and all other\nprocesses get blocked (because tokio's scheduler is cooperative).\n\nThis PR replaces these primitives with tokio's async ones.\n\nCloses #1983\nCloses #2019",
          "timestamp": "2025-03-20T19:04:14Z",
          "tree_id": "ccfea38803d446965230600c877f88b69ee4e550",
          "url": "https://github.com/lambdaclass/ethrex/commit/4f7024cdd9997138bb88ddb94f5721d0343ad95c"
        },
        "date": 1742500761736,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 226396001375,
            "range": "± 381946602",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "862fb49e6143e5bdc1f3aa8939a95dff4038e5f2",
          "message": "fix(l1): fix unending storage healer process in snap sync (#2287)\n\n**Motivation**\nThere is currently a bug in snap sync. When a state sync becomes stale,\nthe snap sync cycle is aborted but the storage healer process is left\nhanging instead if signaling it to end and waiting for it to finish. The\nloop condition of the storage healer is also not properly set, keeping\nit alive even after the end signal if it still has paths to heal. This\nPR fixes both of this problems\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Fix loop condition in storage healer\n* End storage healer if state sync aborts due to stale pivot\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-03-21T13:40:23Z",
          "tree_id": "53424afc61727988e153fbb7b02a7f2ddc50c7d0",
          "url": "https://github.com/lambdaclass/ethrex/commit/862fb49e6143e5bdc1f3aa8939a95dff4038e5f2"
        },
        "date": 1742567830515,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 232806520727,
            "range": "± 1000563047",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ab751f0470192a2120b27f9ef207ff5e06c4676f",
          "message": "feat(l1): write multiple account's storage batches in the same db txn (#2270)\n\n**Motivation**\nWhen measuring time taken by each task during snap sync I noticed that a\nlot of time was spent writing the storage ranges obtained from peers to\nthe DB snapshot. It would take anywhere from 3 to over 10 seconds to\nwrite all the ranges to the DB (around 300 storage ranges per request).\nThis PR modifies the insertion logic to write all 300 ranges in the same\nDB transaction, reducing the time taken to write all the ranges to the\nDB to 10 milliseconds or less\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add `write_storage_snapshot_batches` method to `Store`, which can\nwrite multiple batches from different accounts on the same txn\n* Write all storage ranges received from peers in a single DB txn using\nthe method above on the storage fetcher (snap sync)\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses: None, but helps speed up snap sync",
          "timestamp": "2025-03-21T14:54:55Z",
          "tree_id": "8b597efa81f871d126ab9b85f32aa9034fe83bf5",
          "url": "https://github.com/lambdaclass/ethrex/commit/ab751f0470192a2120b27f9ef207ff5e06c4676f"
        },
        "date": 1742572214466,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 227965982892,
            "range": "± 509390539",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d481d7f17c8843b51651e5ba46390f5444498998",
          "message": "feat(l2): `restart-testnet` target (#2293)\n\n**Motivation**\n\nHaving a target for restarting the L2 deployment on a testnet.",
          "timestamp": "2025-03-21T19:42:06Z",
          "tree_id": "fdbd75a5f2efcdeb68d8aa47188d17f89626be61",
          "url": "https://github.com/lambdaclass/ethrex/commit/d481d7f17c8843b51651e5ba46390f5444498998"
        },
        "date": 1742589574979,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 227901888050,
            "range": "± 862870744",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9b0c70f3121eac4dcf86a3fd62220281cfa697cc",
          "message": "feat(l2): add state reconstruction command (#2204)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nWe need a way to reconstruct the chain state in case of a failure or\neven if someone want to _trustlessly_ access the state.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nThis PR introduces a new ethrex_l2 CLI command, `stack reconstruct`,\nthat takes downloaded blobs from L1 and reconstruct the blocks based on\nits info, storing the state in a Libmdbx store. The blobs can be\ndownloaded using the `stack blobs-saver` command.\nAt this stage, the command is able to successfully reconstruct the chain\nstate and continue to produce blocks.\nNote that, as we send state diffs and not transactions to L1, some data\n(i.e., transactions history, receipts) will not be accessible in a\nreconstructed network.\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #1103\n\n---------\n\nCo-authored-by: Avila Gastón <72628438+avilagaston9@users.noreply.github.com>",
          "timestamp": "2025-03-21T20:42:37Z",
          "tree_id": "e5e608acebe033aebc9bcc46324c291a5898ee38",
          "url": "https://github.com/lambdaclass/ethrex/commit/9b0c70f3121eac4dcf86a3fd62220281cfa697cc"
        },
        "date": 1742593156757,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 224024128750,
            "range": "± 455656359",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "92cd758fd30447b82b6fffa13351772b50d6a165",
          "message": "fix(l2): use absolute path for `.env` file (#2295)\n\n**Motivation**\n\nRunning the stack outside of `crates/l2` fails because the `.env` file\npath is set to its relative form.\n\n**Description**\n\nUse the `.env` file absolute path.",
          "timestamp": "2025-03-21T21:09:42Z",
          "tree_id": "2b74de1133b3bb608b8d2f7dbca638d55b6d227d",
          "url": "https://github.com/lambdaclass/ethrex/commit/92cd758fd30447b82b6fffa13351772b50d6a165"
        },
        "date": 1742594648536,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 222976173527,
            "range": "± 1235507741",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7d4b056cd387c0db577b6fabd1485013ad11efeb",
          "message": "refactor(core): do not leak vm specific implementations from vm crate. (#2297)\n\n**Motivation**\nMake progress toward removing abstraction leaks in vm crate. Outside of\nvm, we should not know about revm vs levm.\n\n**Description**\n- Created `internal` feature flag for the crates that still need to\naccess internal apis: state tests and zkvm interfaces. The idea is that\nit will be temporary until we can remove the leaks from those crates.\n- Refactored the code to make the api explicit in `/vm/lib.rs`. Do not\nexpose modules to the outside by default. This is a first step, we're\nstill exposing too much.\n- Encapsulated `SpecId`, which is a internal concept inside vm, from\noutside we use `Fork`\n- Added utility function `create_contract_address` that uses revm. Added\nthat function to vm crate.",
          "timestamp": "2025-03-25T12:49:21Z",
          "tree_id": "80141def374bcf58a68aaa928524962bf375247e",
          "url": "https://github.com/lambdaclass/ethrex/commit/7d4b056cd387c0db577b6fabd1485013ad11efeb"
        },
        "date": 1742910553704,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 230795622445,
            "range": "± 1202144474",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mrugiero@gmail.com",
            "name": "Mario Rugiero",
            "username": "Oppen"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "14406e2d1984a3398945e9db4e29e8948a079995",
          "message": "fix(l2): remove uses of blocking sleeps from async code (#2296)\n\nThere were still some sleeps blocking the runtime. Found mostly in the\nload test, but in other places as well. Changed them by tokio::sleep\ncalls.",
          "timestamp": "2025-03-25T13:10:21Z",
          "tree_id": "48674ee61d71343d1d8f58623ac22b1399d1d511",
          "url": "https://github.com/lambdaclass/ethrex/commit/14406e2d1984a3398945e9db4e29e8948a079995"
        },
        "date": 1742911720109,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 232681672891,
            "range": "± 591152064",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "156438142+fborello-lambda@users.noreply.github.com",
            "name": "Federico Borello",
            "username": "fborello-lambda"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "a8bb355f7fe072474461b29b8e1f68c7bdc75d75",
          "message": "fix(l2): prover_client with SP1 (#2273)\n\n**Motivation**\n\nWhen we bumped the SP1 version to the latest we didn't test the\n`prover_client` on its own.\nAlso, we had some issues when using CUDA with a `ctrl-c` handler set\ninside the `sp1-cuda` crate.\n \n**Description**\n\n- Fix Makefile Target\n- Bump the contract version\n- Start a single SP1's client with `LazyLock` to fix the CUDA issues\ndescribed above.",
          "timestamp": "2025-03-25T18:14:11Z",
          "tree_id": "bf146f62bf307abc955a0c3593207b587fbdc98f",
          "url": "https://github.com/lambdaclass/ethrex/commit/a8bb355f7fe072474461b29b8e1f68c7bdc75d75"
        },
        "date": 1742929926890,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 231323537827,
            "range": "± 840969873",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "55d8bd520e032323a83e780986d23156161d66d3",
          "message": "refactor(l2): rework gas fee bump (#2277)\n\n**Motivation**\n\nThis PR moves all logic related to handling transaction retries and\nbumping gas fees to a single function\n`send_tx_bump_gas_exponential_backoff` (before it was scattered in a few\ndiferent places, hard to follow and with no exponential backoff).\n\nIt also introduces a small randomness to the intervals with which the\nmain processes (l1 commiter, l1 watcher and prover server) execute their\nmain loop, to avoid possible problems related to things running at\ndeterministic intervals.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number\n\n---------\n\nCo-authored-by: ilitteri <ilitteri@fi.uba.ar>",
          "timestamp": "2025-03-25T19:24:45Z",
          "tree_id": "c671a1aa88bd75ff93d79bc553c7cd90c4d6b73f",
          "url": "https://github.com/lambdaclass/ethrex/commit/55d8bd520e032323a83e780986d23156161d66d3"
        },
        "date": 1742934128302,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 227892360916,
            "range": "± 592695565",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "4c002213e1aaf16a64d09de3d93741103e73bd02",
          "message": "feat(l2): add rpc endpoints for based sequencing (#2274)\n\n> [!NOTE]\n> Original PR: https://github.com/lambdaclass/ethrex/pull/2022\n(squeashed because of unsigned commits).\n\n---------\n\nCo-authored-by: Manuel Iñaki Bilbao <bilbaomanuel98@gmail.com>",
          "timestamp": "2025-03-25T21:47:44Z",
          "tree_id": "bd700c81bc0bf69843c8d7d44d57d1a2c8abac6a",
          "url": "https://github.com/lambdaclass/ethrex/commit/4c002213e1aaf16a64d09de3d93741103e73bd02"
        },
        "date": 1742942718069,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 229725052320,
            "range": "± 1338873796",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "76252340+MarcosNicolau@users.noreply.github.com",
            "name": "Marcos Nicolau",
            "username": "MarcosNicolau"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "cdbfbe904b5742dc6fefb48f2a12c18001264b9d",
          "message": "feat(l1): process blocks in batches when syncing and importing (#2174)\n\n**Motivation**\nAccelerate syncing!\n\n**Description**\nThis PR introduces block batching during full sync:\n1. Instead of storing and computing the state root for each block\nindividually, we now maintain a single state tree for the entire batch,\ncommitting it only at the end. This results in one state trie per `n`\nblocks instead of one per block (we'll need less storage also).\n2. The new full sync process:\n    - Request 1024 headers\n    - Request 1024 block bodies and collect them\n- Once all blocks are received, process them in batches using a single\nstate trie, which is attached to the last block.\n3. Blocks are now stored in a single transaction.\n4. State root, receipts root, and request root validation are only\nrequired for the last block in the batch.\n5. The new add_blocks_in_batch function includes a flag,\n`should_commit_intermediate_tries`. When set to true, it stores the\ntries for each block. This functionality is added to make the hive test\npass. Currently, this is handled by verifying if the block is within the\n`STATE_TRIES_TO_KEEP` range. In a real syncing scenario, my intuition is\nthat it would be better to wait until we are fully synced and then we\nwould start storing the state of the new blocks and pruning when we\nreach `STATE_TRIES_TO_KEEP`.\n6. Throughput when syncing is now measured per batches.\n7. A new command was added to import blocks in batch\n\nConsiderations:\n1. ~Optimize account updates: Instead of inserting updates into the\nstate trie after each block execution, batch them at the end, merging\nrepeated accounts to reduce insertions and improve performance (see\n#2216)~ Closes #2216.\n2. Improve transaction handling: Avoid committing storage tries to the\ndatabase separately. Instead, create a single transaction for storing\nreceipts, storage tries, and blocks. This would require additional\nabstractions for transaction management (see #2217).\n3. This isn't working for `levm` backend we need it to cache the\nexecutions state and persist it between them, as we don't store anything\nuntil the final of the batch (see #2218).\n4. In #2210 a new ci is added to run a bench comparing main and `head`\nbranch using `import-in-batch`\n\nCloses None\n\n---------\n\nCo-authored-by: Martin Paulucci <martin.c.paulucci@gmail.com>\nCo-authored-by: fmoletta <99273364+fmoletta@users.noreply.github.com>",
          "timestamp": "2025-03-25T21:48:54Z",
          "tree_id": "5ee3b5d1c38da882ce4394e5df4f01dbe40c43bf",
          "url": "https://github.com/lambdaclass/ethrex/commit/cdbfbe904b5742dc6fefb48f2a12c18001264b9d"
        },
        "date": 1742942819671,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 231706874953,
            "range": "± 1486957612",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mrugiero@gmail.com",
            "name": "Mario Rugiero",
            "username": "Oppen"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "579275c0bc6392b7f7ff25f4cf253579cadb2245",
          "message": "fix(l2): bashism in l2 Makefile (#2301)\n\nThe `[[` builtin is not POSIX, which causes issues in some servers that\ndefault their shell to `sh` (POSIX-compat mode). Specifically, because\nthe builtin does not exist, the L2 always runs in based mode due to the\nerror.\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-03-25T22:20:04Z",
          "tree_id": "4de2af114f2cec936f4ea95e5e169282d4038fb2",
          "url": "https://github.com/lambdaclass/ethrex/commit/579275c0bc6392b7f7ff25f4cf253579cadb2245"
        },
        "date": 1742944672081,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 230469754658,
            "range": "± 700649031",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "65ac1fdd7fbb86a7b56992dbd6a6a822713b8405",
          "message": "ci(core): disable flamegraph report until it is fixed. (#2312)\n\n**Motivation**\nThis job is broken. Disabling it until it gets fixed.",
          "timestamp": "2025-03-26T13:57:20Z",
          "tree_id": "9569055f5bca151e1d6111556907cd23ff096cd2",
          "url": "https://github.com/lambdaclass/ethrex/commit/65ac1fdd7fbb86a7b56992dbd6a6a822713b8405"
        },
        "date": 1743000927874,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 231415392619,
            "range": "± 1028060620",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d1faf8b4658bc3f36c35159717303fa3af384fd2",
          "message": "test(l2): add state reconstruction test to the CI (#2255)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nWe want to check that the state diff reconstruction doesn't break on\nPRs.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nAdded some tests that reconstruct the state from 3 blobs, which include\nbalance and nonce diffs, and an ERC20 contract \"deployment\" with balance\ndiffs.\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\n---------\n\nCo-authored-by: Federico Borello <156438142+fborello-lambda@users.noreply.github.com>\nCo-authored-by: Ivan Litteri <67517699+ilitteri@users.noreply.github.com>\nCo-authored-by: Javier Chatruc <jrchatruc@gmail.com>",
          "timestamp": "2025-03-26T15:11:43Z",
          "tree_id": "79801ab99fd69dda90bb28100f2f5c991cd76480",
          "url": "https://github.com/lambdaclass/ethrex/commit/d1faf8b4658bc3f36c35159717303fa3af384fd2"
        },
        "date": 1743005326164,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 226755411287,
            "range": "± 357419523",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "76252340+MarcosNicolau@users.noreply.github.com",
            "name": "Marcos Nicolau",
            "username": "MarcosNicolau"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f8f9552b9c9c8755e8156752e051a347c1feb169",
          "message": "fix(l1): blocking tokio scheduler while syncing (#2314)\n\n**Motivation**\nSyncing.\n\n**Description**\nExecuting blocks is a CPU-intensive task. During syncing, this process\nwas blocking the Tokio runtime, causing other tasks to stop working. A\nmajor issue was that our node stopped responding to p2p requests,\nleading to abrupt disconnections.\n\nThis fix resolves the problem by spawning the block execution with tokio\n`spawn_blocking`, which runs tasks in a separate thread pool optimized\nfor CPU-heavy operations. This prevents the scheduler from being\nblocked, fixing the networking issue.\n\nCloses None",
          "timestamp": "2025-03-26T15:31:19Z",
          "tree_id": "a1e35a5c8219b0f5d0261788d6f5dfa994803e62",
          "url": "https://github.com/lambdaclass/ethrex/commit/f8f9552b9c9c8755e8156752e051a347c1feb169"
        },
        "date": 1743006649776,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 225655939542,
            "range": "± 664288582",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "206c56e2e02c569b00fd6ce73e3106432e811793",
          "message": "ci(core): remove rust version since it's already specified in toolchain (#2311)\n\n**Motivation**\nYou can see this message in the CI:\n`info: note that the toolchain '1.82.0-x86_64-unknown-linux-gnu' is\ncurrently in use (overridden by\n'/home/runner/work/ethrex/ethrex/rust-toolchain.toml')`",
          "timestamp": "2025-03-26T15:42:13Z",
          "tree_id": "fe462380636577aa82af2df8210b069231cfd8a5",
          "url": "https://github.com/lambdaclass/ethrex/commit/206c56e2e02c569b00fd6ce73e3106432e811793"
        },
        "date": 1743007195511,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 229594303409,
            "range": "± 2536574230",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "4583997f02f572e6587abbd9239994f0c368080b",
          "message": "chore(core): improve ci loc job (#2304)\n\n**Motivation**\nThe job doesn't seem to work well with forks (external contributions).\nThis aims to fix it",
          "timestamp": "2025-03-26T15:43:52Z",
          "tree_id": "4bd3553342079f6567bfb4bf0dc62d9354a54f37",
          "url": "https://github.com/lambdaclass/ethrex/commit/4583997f02f572e6587abbd9239994f0c368080b"
        },
        "date": 1743007281368,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 229822436417,
            "range": "± 575467306",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d03ec50019df7c02dadcf39ba5e08d4c7086a67a",
          "message": "refactor(l2): use levm for sp1 prover using a trait (#2250)\n\n**Motivation**\n\nThis PR exists to use LEVM as the EVM for executing SP1 prover\n\n**Description**\n\n- Implement the trait `LevmDatabase` for the `ExecutionDb`.\n- Now the LEVM backend can execute blocks or transactions on any\ndatabase that implements the `LevmDatabase` trait.\n- Move the `ExecutionDb` to a common place and remove from some of REVM\ndependencies. But, there are some left to be removed in the next PR.\n- Add a feature flag `levm-l2` for choosing whether to execute the\nProver and the ExecutionDb with LEVM or not.\n\n**Status**\n\n- This a second implementation for the same purpose as #2231 . Only one\nshould be maintained.\n- ExecutionDb isn't fully decoupled yet.\n\nLinks to #2225",
          "timestamp": "2025-03-26T18:01:21Z",
          "tree_id": "8bb3c3b10eea3148b2c9cfd302bb1009cf65b2b3",
          "url": "https://github.com/lambdaclass/ethrex/commit/d03ec50019df7c02dadcf39ba5e08d4c7086a67a"
        },
        "date": 1743015552445,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 229831357611,
            "range": "± 477453820",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "956537fb88e932f4bbc629ae82116e05f91ec894",
          "message": "fix(l1, l2): fix load tests (#2323)\n\n**Motivation**\n\nLoad tests were broken for two reasons:\n\n- We were not correctly passing the nonce as an override and thus were\nrelying on the RPC endpoint to get it, which was not correct (since we\nwant to pre-send transactions with higher nonces)\n- We were hardcoding gas fees; this is because when we first wrote the\nload tests, the gas price endpoint on ethrex did not work properly. Now\nthat it does, we can remove the hardcoded values and just rely on the\nendpoint (the default behaviour if you do not pass an `Override` to the\n`build_eip1559_transaction` function).\n\nI also changed the `debug!` log when a mempool transaction failed to be\nexecuted while building a block to be an `error!`, because I noticed\nit's quite a common occurrence when we run load tests due to some nonce\nissue, and I think it's worth investigating (it's the reason why\nsometimes we get empty blocks when running load tests).\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number\n\n---------\n\nCo-authored-by: JereSalo <jeresalo17@gmail.com>",
          "timestamp": "2025-03-26T18:52:46Z",
          "tree_id": "539ef04a6f159f38f5ab44220b15d82d09094181",
          "url": "https://github.com/lambdaclass/ethrex/commit/956537fb88e932f4bbc629ae82116e05f91ec894"
        },
        "date": 1743018680788,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 230749596243,
            "range": "± 1764496588",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "156438142+fborello-lambda@users.noreply.github.com",
            "name": "Federico Borello",
            "username": "fborello-lambda"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9c0b365bef18c5639aa02a94445e4030ce43ba1d",
          "message": "refactor(l2): handle ctrl_c internally and multiple connections (#2294)\n\n**Motivation**\n\nWe should `spawn` a new task every new connection received in the\n`prover_server`.\nAlso, the ctrl_c handler was wired through the TCP layer.\n\n**Description**\n\n- Create a new task per connection\n- Handle the ctrl_c internally with the help of `select!` and a\n`tokio::mpsc`\n- Add a `Semaphore` to cap the amount of concurrent tasks.\n\nCloses #2283\nCloses #2284\n\n---------\n\nCo-authored-by: Mario Rugiero <mrugiero@gmail.com>",
          "timestamp": "2025-03-26T19:48:39Z",
          "tree_id": "fe6e16cbc963211db4c469210bd0a846f1e96361",
          "url": "https://github.com/lambdaclass/ethrex/commit/9c0b365bef18c5639aa02a94445e4030ce43ba1d"
        },
        "date": 1743022012383,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 233358784894,
            "range": "± 475162402",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "156438142+fborello-lambda@users.noreply.github.com",
            "name": "Federico Borello",
            "username": "fborello-lambda"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "dc392087828781e0c0d1d10008fc38543a2f02eb",
          "message": "feat(l2): omit unneeded proofs (#2235)\n\n**Motivation**\n\nWe had to wait for all prover backends' proofs in order to send the\n`verify` transaction and continue with the desired behavior of\n`commitment` &rarr; then `verification`.\n\nNow, we can make use of only one backend.\n\n**Description**\n\n- Check the `Verification` contract address querying the contract\n  - If it is `0xAA` we don't wait for that backend's proof.\n\n---------\n\nCo-authored-by: Estéfano Bargas <estefano.bargas@fing.edu.uy>",
          "timestamp": "2025-03-26T20:50:41Z",
          "tree_id": "368f634d7ae6c24a3d89414dc4b78b0499257299",
          "url": "https://github.com/lambdaclass/ethrex/commit/dc392087828781e0c0d1d10008fc38543a2f02eb"
        },
        "date": 1743025705932,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 230748524994,
            "range": "± 543494546",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "156438142+fborello-lambda@users.noreply.github.com",
            "name": "Federico Borello",
            "username": "fborello-lambda"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "170308afefe78c08b13bcda3111ec5e4158e87a5",
          "message": "refactor(l2): separated configs for prover_client and sequencer (#2269)\n\n**Motivation**\n\nWhen running the prover_client as a standalone component the\n`config.toml` wasn't being parsed.\nIdeally we should parse it before we run the prover_client.\n\n**Description**\n\n- The `ConfigMode` enum is proposed to parse the .toml for the\n`Sequencer` or the `ProverClient`\n- The prover_client parses the `prover_client_config.toml` and creates a\n`.env.prover` file\n- Created new envars to set the:\n  - `CONFIGS_PATH` \n  - `SEQUENCER_CONFIG_FILE`\n  - `PROVER_CLIENT_CONFIG_FILE`\n  - The references were updated in the Makefile\n\nThis change also enables us to change the `SEQUENCER_CONFIG_FILE` easily\nkeeping it in the `configs` dir and switching the `Makefile`'s variable.\n(Useful when testing locally and with a testnet).\n\nCloses #2053\n\n---------\n\nCo-authored-by: Ivan Litteri <67517699+ilitteri@users.noreply.github.com>",
          "timestamp": "2025-03-26T21:12:57Z",
          "tree_id": "031ff061bacfb206344cc64371c74742f0423ba5",
          "url": "https://github.com/lambdaclass/ethrex/commit/170308afefe78c08b13bcda3111ec5e4158e87a5"
        },
        "date": 1743027019113,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 228971430179,
            "range": "± 936604869",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "76252340+MarcosNicolau@users.noreply.github.com",
            "name": "Marcos Nicolau",
            "username": "MarcosNicolau"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "b36a7c603985788c9cc115d123dfa0649eac997b",
          "message": "perf(core): compute tx senders in parallel (#2268)\n\n**Motivation**\nIncrease performance\n\n**Description**\nA big time of `execute_block` in the vm was spent in recovering the\n`address` from the transactions. This pr, parallelizes the computation\nof the address and reduces the time down to almost negligible.\n\nIt also fixes the ci that got broken with the latest changes.\n\nCloses None",
          "timestamp": "2025-03-27T12:35:52Z",
          "tree_id": "061ab79965fa884720b1bac7353c219c7520eba1",
          "url": "https://github.com/lambdaclass/ethrex/commit/b36a7c603985788c9cc115d123dfa0649eac997b"
        },
        "date": 1743082019601,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 184805574099,
            "range": "± 1273678246",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "f13c24d9197d162c64d2f05b26669307a090681b",
          "message": "feat(levm): implement create_access_list (#2244)\n\n**Motivation**\n\nImplement create_access_list for levm\n\n**Description**\n\n- Implement a function that executes a transaction and creates from the\nresulting `accrued_substate` an access list.\n- Add a function to utils that generates the access list\n\n**Observation**\n\nChanges `touched_storage_slots` from `HashSet` to `BTreeSet` to align\nwith the expected output order of the addresses in the Hive tests.\n\n**Hive Tests**\n\nThese hive tests should be fixed with this PR\n```Shell\nmake run-hive EVM_BACKEND=\"levm\" SIMULATION=\"ethereum/rpc-compat\" TEST_PATTERN=\"rpc-compat/eth_createAccessList/\"                          \n```\n\nCloses #2183\n\n---------\n\nCo-authored-by: avilagaston9 <gavila@fi.uba.ar>\nCo-authored-by: Avila Gastón <72628438+avilagaston9@users.noreply.github.com>",
          "timestamp": "2025-03-27T15:46:49Z",
          "tree_id": "2cb5c83041298ea0d404c437c8c0cc55581e155d",
          "url": "https://github.com/lambdaclass/ethrex/commit/f13c24d9197d162c64d2f05b26669307a090681b"
        },
        "date": 1743093450747,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 190274384277,
            "range": "± 857475100",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f0cfaa6cae7e11c6fdc02427654b04554127ee36",
          "message": "refactor(l2): rename proposer config with a more descriptive name (#2341)",
          "timestamp": "2025-03-27T20:40:24Z",
          "tree_id": "a91440aed48af0296e4d4a0df95941c29af4c8f0",
          "url": "https://github.com/lambdaclass/ethrex/commit/f0cfaa6cae7e11c6fdc02427654b04554127ee36"
        },
        "date": 1743110966847,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 184674546450,
            "range": "± 1003660756",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d90a9dc5e6269543a85cc7ae9177dfd23bfb17d3",
          "message": "fix(core): make metrics port flag not optional (#2343)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\nCurrently, the metrics are initiated iif the `--metrics-port` flag is\npassed. This is wrong because the flag is used both to configure the\nlistening port and as a metrics enabler flag.\n\nIf needed, a flag `--metrics.enabled` could be introduced in another PR\nif metrics are unwanted for some reason. IMHO initializing metrics as\ndefault is ok.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\n- Always initialize metrics\n- The `--metrics.port` flag is now not optional and defaults to 9090 as\nthe default value.",
          "timestamp": "2025-03-27T20:58:50Z",
          "tree_id": "45eacb2f732ca8dbb353d790b06ee84795360b48",
          "url": "https://github.com/lambdaclass/ethrex/commit/d90a9dc5e6269543a85cc7ae9177dfd23bfb17d3"
        },
        "date": 1743112138346,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 188848074989,
            "range": "± 1075290354",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "d41018978ddb6684452a48e44872e07071175dc1",
          "message": "refactor(l2): rename prover client config to a more descriptive name (#2345)\n\n- Rename prover client `interval_ms` -> `proving_time_ms`.\n- Remove needless `ProverClientConfig` struct in `toml_parser`.",
          "timestamp": "2025-03-28T00:49:34Z",
          "tree_id": "e0c3e409cb121bf4dd608b77a7b788ef32bd83af",
          "url": "https://github.com/lambdaclass/ethrex/commit/d41018978ddb6684452a48e44872e07071175dc1"
        },
        "date": 1743125929502,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 184651396277,
            "range": "± 644941291",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "14216ab80801c1edf2ac0f2f99c4d091dce64cc4",
          "message": "feat(core): add metrics address config flag (#2344)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\nNowadays, the metrics API address is hardcoded to `0.0.0.0`. This PR\naims to parameterize this.\n\n**Description**\n\n- Adds a `--metrics.addr` flag to the CLI with `0.0.0.0` as the default\nvalue.\n- Implement the wiring necessary to pass the flag value to the metrics\nAPI initialization.\n\n---------\n\nCo-authored-by: fborello-lambda <federicoborello@lambdaclass.com>",
          "timestamp": "2025-03-28T13:08:40Z",
          "tree_id": "f796da1d04454ae694dea1c857792ba51caae4c9",
          "url": "https://github.com/lambdaclass/ethrex/commit/14216ab80801c1edf2ac0f2f99c4d091dce64cc4"
        },
        "date": 1743170262005,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 185323473554,
            "range": "± 645552899",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8a026aa0fdd0e02c2d1bc5c2436e5ab05086cd05",
          "message": "fix(l2): config error handling (#2339)\n\n**Motivation**\n\nIn a previous PR, the configuration file error handling was updated, and\nthe help messages stopped being helpful. This PR aims to make these\nerror messages useful again and improve their handling.\n\nThe current help message does not work:\n\n```Shell\nError parsing the .toml configuration files: Could not find crates/l2/configs/config.toml\nHave you tried copying the provided example? Try:\ncp /Users/ivanlitteri/Repositories/lambdaclass/ethrex/crates/l2/configs/*_example.toml /Users/ivanlitteri/Repositories/lambdaclass/ethrex/crates/l2/configs/*.toml\n\nError: ConfigError(TomlParserError(TomlFileNotFound(\"config.toml\")))\nmake: *** [deploy-l1] Error 1\n➜  l2 git:(main) ✗ cp /Users/ivanlitteri/Repositories/lambdaclass/ethrex/crates/l2/configs/*_example.toml /Users/ivanlitteri/Repositories/lambdaclass/ethrex/crates/l2/configs/*.toml\ncp: /Users/ivanlitteri/Repositories/lambdaclass/ethrex/crates/l2/configs/sequencer_config_example.toml is not a directory\n```\n\n**Description**\n\n- Add a prefix `sequencer_` to the sequencer config file to be\nconsistent with the prover client config file and update its references.\n- Pass `ConfigMode` to the `toml` errors to make the help messages\nhelpful again, and implement `Debug` and `Display` for this on it.\n- Make the `toml` parsing error explicit.",
          "timestamp": "2025-03-28T13:25:33Z",
          "tree_id": "ca573e46b003e3b630b64bdaaad230aa8de55184",
          "url": "https://github.com/lambdaclass/ethrex/commit/8a026aa0fdd0e02c2d1bc5c2436e5ab05086cd05"
        },
        "date": 1743171366371,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 185080725230,
            "range": "± 833080354",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "835045b3fc5b905cb90d64e59b3febef16b960c6",
          "message": "refactor(l2, core): initial iteration for `l2` subcommand (#2324)\n\n**Motivation**\n\nThere are two motivations for this PR:\n1. Decouple L2 logic (initialization, etc) from `ethrex.rs`.\n2. Replace `crates/l2/Makefile` (we'll keep the Makefile for simplicity,\nby replacing I mean to have all the logic in `l2` subcommands such as\n`l2 init` and `l2 removedb` that replace `make init-l2` and `make\nrm-db-l2` logic). In future PRs we'll add more subcommands, making the\nMakefile a shortcut for running `cargo run --release --bin ethrex\n--features l2 -- l2 <some command>`.\n\n**Description**\n\n- Add an `l2.rs` submodule for the L2 subcommand logic.\n- Decouple L2 initialization from `ethrex.rs` file (moved into\nsubcommand handling).\n- Merge `BasedOptions` into `L2Options` (based options are also L2\noptions).\n- Implement `l2 init` and `l2 removedb` commands.\n- Update `crates/l2/Makefile` to use these new commands.\n\n**Test it out**\n\nDoing your regular L2 initialization with the makefile should be enough.\n\nResolves #2246.\nResolver #1987",
          "timestamp": "2025-03-28T14:53:11Z",
          "tree_id": "1bb340b2e037e27a22e0c78206cdbc0cad1d0a82",
          "url": "https://github.com/lambdaclass/ethrex/commit/835045b3fc5b905cb90d64e59b3febef16b960c6"
        },
        "date": 1743176596284,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 187390215232,
            "range": "± 882029235",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "156438142+fborello-lambda@users.noreply.github.com",
            "name": "Federico Borello",
            "username": "fborello-lambda"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9a28ac444e5e7f01effbdbf36a9d5dddb9943d8b",
          "message": "fix(l2): prover_client_config parser (#2348)\n\n**Motivation**\n\nThe previous PR removed the `ProverClientConfig` leaving just the\n`ProverClient` structure. To successfully parse the file, we should\nremove the `prover_client` table header.\n\n**Description**\n\n- Remove header from `prover_client_config_example.toml`",
          "timestamp": "2025-03-28T16:13:55Z",
          "tree_id": "da357e2b19a1d3929c363d656f3dadbcd12cfb0a",
          "url": "https://github.com/lambdaclass/ethrex/commit/9a28ac444e5e7f01effbdbf36a9d5dddb9943d8b"
        },
        "date": 1743181442687,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 188884940955,
            "range": "± 818849675",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "27232155ca4b70ac1658d86e8411a00618e66598",
          "message": "feat (l1): write nodes in batches during storage healing (#2288)\n\n**Motivation**\nIn a similar fashion to #2270, this PR aims to reduce the time spent\nwriting data to the DB by writing data in batches. In this case the\nnodes received during storage healing are written all at once using the\nalready existing `put_batch` method of the TrieDB trait.\nThis could only be done for nodes belonging to the same trie, as it\nwould otherwise involve leaking and constraining the internal\nrepresentation of TrieDB.\nThis has shown to reduce the time spent writing storage nodes in the DB\nfrom around 4 seconds to less than 20 milliseconds\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add `write_node_batch` method for `TrieState` relying on\n`TrieDB::put_batch`\n* Refactor storage healer code to write all nodes for a trie in a single\noperation\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number\n\n---------\n\nCo-authored-by: Rodrigo Oliveri <rodrigooliveri10@gmail.com>",
          "timestamp": "2025-03-28T21:21:38Z",
          "tree_id": "b424781e8fce7d01c22aba84916878998d30b789",
          "url": "https://github.com/lambdaclass/ethrex/commit/27232155ca4b70ac1658d86e8411a00618e66598"
        },
        "date": 1743199849892,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182531092599,
            "range": "± 956807821",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "7cd2ddc67c483fad5bb6de52b4c81a0986118228",
          "message": "feat(l1): add separate queue for large storages during snap sync (#2256)\n\n**Motivation**\nCurrently, large storage tries are handled by the same process that\nhandles smaller storage tries, which can cause the fetcher to stall when\nencountering large storages. This PR aims to fix this by delegating the\nfetching of large storages to a separate queue process\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add a new fetcher process for large storages with its own queue. (One\nwill be spawned for each storage fetcher\n* Delegate fetching of large storages to the large storage fetcher\n* Allow the rebuilder to skip root validations for partial storage tries\nwhen the pivot becomes stale during a large storage trie fetch\n* Other: unify all SendError into one generic mapping for SyncError\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #1965\n\n---------\n\nCo-authored-by: ElFantasma <estebandh@gmail.com>",
          "timestamp": "2025-03-28T21:21:19Z",
          "tree_id": "13e2d1f16201031cc00b2951e185542735ad341d",
          "url": "https://github.com/lambdaclass/ethrex/commit/7cd2ddc67c483fad5bb6de52b4c81a0986118228"
        },
        "date": 1743199877296,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 186577284621,
            "range": "± 700543628",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "72628438+avilagaston9@users.noreply.github.com",
            "name": "Avila Gastón",
            "username": "avilagaston9"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c18d692f640abbc540f73fe288ace5760314e94c",
          "message": "perf(levm): remove repeated `get_account_info` calls in LEVM (#2357)\n\n**Motivation**\n\nNoticed on #2292 that the majority of the time in\n`LEVM::get_state_transitions()` was spent on calls to\n`get_account_info()`. While looking for areas to improve, I found that\nwe were calling `get_account_info()` three times instead of reusing the\nvalue returned in the first call.\n\n**Description**\n\nRemoves the repeated calls to `get_account_info`.\n\nTesting locally shows a `2x` speed improvement in\n`payload_builder::build_payload()` implemented in #2292.\n\nCloses None",
          "timestamp": "2025-03-31T14:24:48Z",
          "tree_id": "914ec1e5c4c92b93dcc44c3cccd62f29a48af3e6",
          "url": "https://github.com/lambdaclass/ethrex/commit/c18d692f640abbc540f73fe288ace5760314e94c"
        },
        "date": 1743434167700,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 192357867237,
            "range": "± 680639721",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "f3063f124020f239617ea2d30de689209ac68e3a",
          "message": "feat(l1): write state nodes in batches during state healing (#2309)\n\n**Motivation**\nIn a similar fashion to #2288, this PR aims to reduce the time spent\nwriting data to the DB by writing data in batches. In this case the\nnodes received during storage healing are written all at once using the\n`write_node_batch` method introduced in #2288\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Refactor state healer code to write all nodes for a trie in a single\noperation\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number\n\n---------\n\nCo-authored-by: Rodrigo Oliveri <rodrigooliveri10@gmail.com>",
          "timestamp": "2025-03-31T14:42:21Z",
          "tree_id": "6182c78c84c86b7b3f8d97ebd099ff2eb007d5bd",
          "url": "https://github.com/lambdaclass/ethrex/commit/f3063f124020f239617ea2d30de689209ac68e3a"
        },
        "date": 1743435097610,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 183532074688,
            "range": "± 572310191",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "56402156+fkrause98@users.noreply.github.com",
            "name": "Francisco Krause Arnim",
            "username": "fkrause98"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "67e1fa89d5ed5f86bfce59d3eaad0f9b4f465890",
          "message": "perf(l1,l2): trie benchmark (#2272)\n\n**Motivation**\n\nWe want to speed-up our trie implementation, for that, we\nwant reproducible benchmarks and a baseline for comparison.\n\n**Description**\n- Add benchmark for Ethrex's Trie, compared against citra.\n- Add UUID dependency to generate random data, a dev-only dep.\n\n\n\nCloses #2262.\n\n---------\n\nCo-authored-by: fmoletta <99273364+fmoletta@users.noreply.github.com>",
          "timestamp": "2025-03-31T16:10:26Z",
          "tree_id": "9f01749764791a04f711a6fb5aced1bf2df1c0da",
          "url": "https://github.com/lambdaclass/ethrex/commit/67e1fa89d5ed5f86bfce59d3eaad0f9b4f465890"
        },
        "date": 1743440458334,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 187077770228,
            "range": "± 727464219",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "156438142+fborello-lambda@users.noreply.github.com",
            "name": "Federico Borello",
            "username": "fborello-lambda"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "b3e3705e7252a3dde1c6edc6da3750ed77b9ac91",
          "message": "chore(l2): remove deprecated EngineApiConfig (#2356)\n\n**Motivation**\n\nThe `EnigneApiConfig` isn't used anymore.\n\n**Description**\n\n- Remove the struct and all the deprecated code related to it.\n\nCloses #2351",
          "timestamp": "2025-03-31T20:57:31Z",
          "tree_id": "0f8781b21c0fad2067f9ee0768d5dd09cc2b6db6",
          "url": "https://github.com/lambdaclass/ethrex/commit/b3e3705e7252a3dde1c6edc6da3750ed77b9ac91"
        },
        "date": 1743457619243,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 184452727576,
            "range": "± 1177277487",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c19b0a046c396f1b6613ce7ed96505c39126c0de",
          "message": "fix(l1, l2): add \"data\" as an alias to the tx input field (#2364)\n\n**Motivation**\n\nOur `GenericTransaction` struct calls the field where calldata goes\n`input`, but some (especially old) eth clients call it `data` instead.\nThis was giving me problems when integrating with some of those clients.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-03-31T21:22:35Z",
          "tree_id": "cd9657709e01fb7305901f1ef55bda58eda676b9",
          "url": "https://github.com/lambdaclass/ethrex/commit/c19b0a046c396f1b6613ce7ed96505c39126c0de"
        },
        "date": 1743459127059,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 184701597004,
            "range": "± 1116702907",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "ab8f5c324b9999994eb8002497ab667bdd1223ff",
          "message": "build(l2): enable exec prover by default. (#2372)\n\n**Motivation**\nRunning `cargo build --workspace` should work by default, without having\nto explicitly set a feature flag. Without this change, it errors because\nno prover backend was selected. Unless we're working on the prover, we\ndon't really care about the backend and we should reduce the friction to\npeople working in the project.\n\n---------\n\nCo-authored-by: fborello-lambda <federicoborello@lambdaclass.com>",
          "timestamp": "2025-04-01T14:51:03Z",
          "tree_id": "67e19d03eb045812a1a615c5cb45f7f36b115d27",
          "url": "https://github.com/lambdaclass/ethrex/commit/ab8f5c324b9999994eb8002497ab667bdd1223ff"
        },
        "date": 1743522107191,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 183601995227,
            "range": "± 513683522",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e9f9112b01dc30f0b4d651a33c8241a46807db39",
          "message": "docs(l2): make simple changes/nits to docs (#2370)\n\n**Motivation**\n- Improve existing docs a little bit with things I'm noticing while\nreading it.\n\n**Description**\n- Avoid saying we are updating storage in a basic transaction; we are\nactually just updating the balances of the accounts.\n- Make some other small and unimportant changes that improve docs\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-01T14:56:29Z",
          "tree_id": "b18489be910f4ac5320cf98188e15bf9ece95fdf",
          "url": "https://github.com/lambdaclass/ethrex/commit/e9f9112b01dc30f0b4d651a33c8241a46807db39"
        },
        "date": 1743522668900,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 188754922429,
            "range": "± 1394860791",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "65383392d24f31f4a478fe585ab240e534b29528",
          "message": "ci(core): skip loc job on repository forks. (#2373)\n\n**Motivation**\nExternal contributors don't have permissions to post comments\nprogramatically. So the LOC doesn't make sense in that case.",
          "timestamp": "2025-04-01T15:59:46Z",
          "tree_id": "72320c5e6c821e08299b664b050b08317ec20222",
          "url": "https://github.com/lambdaclass/ethrex/commit/65383392d24f31f4a478fe585ab240e534b29528"
        },
        "date": 1743526224231,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 186078010011,
            "range": "± 1250780320",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "98899785+mdqst@users.noreply.github.com",
            "name": "Dmitry",
            "username": "mdqst"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5b5a11e135c7d4abd5719d6c69397eed17aa626c",
          "message": "chore(l1): fix JWT secret decoding issue (#2298)\n\n**Motivation**  \nI noticed that `hex::decode(secret).unwrap().into()` could cause a panic\nif decoding fails. Since `generate_jwt_secret()` returns a `String`,\n`hex::decode(secret)` produces a `Result<Vec<u8>, FromHexError>`, which\nwas being unwrapped unsafely. Ensuring safe error handling improves the\nrobustness of the code.\n\n**Description**  \nReplaced the unsafe `.unwrap().into()` with a safer decoding approach:  \n\n```rust\nhex::decode(secret)\n    .map(Bytes::from)\n    .expect(\"Failed to decode generated JWT secret\")\n```\n\nThis ensures that any decoding errors are properly surfaced instead of\ncausing a panic.\n\nCo-authored-by: Martin Paulucci <martin.c.paulucci@gmail.com>",
          "timestamp": "2025-04-01T16:48:43Z",
          "tree_id": "9c7a54eff9e6540b37276ab69db353a676726514",
          "url": "https://github.com/lambdaclass/ethrex/commit/5b5a11e135c7d4abd5719d6c69397eed17aa626c"
        },
        "date": 1743529161926,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 185786068027,
            "range": "± 625343763",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "0c8ae91c53a62d70e8e699ab445e2e89e9d649c6",
          "message": "ci(core): restrict github job permissions by default. (#2389)\n\n**Motivation**\nUse the principle of least privilege and don't grand write permissions\nthat are then forwarded to potentially malicious actions.",
          "timestamp": "2025-04-03T13:06:01Z",
          "tree_id": "c676caacb1b70135bf57d3b629b3a30c9125f864",
          "url": "https://github.com/lambdaclass/ethrex/commit/0c8ae91c53a62d70e8e699ab445e2e89e9d649c6"
        },
        "date": 1743688634472,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 185259852612,
            "range": "± 945855173",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "73d94a2457e3e1277a7a4736b9d534b5d23fd53d",
          "message": "feat(l1): add hoodi testnet configuration (#2387)\n\n**Motivation**\nAdd support for hoodi testnet",
          "timestamp": "2025-04-03T13:05:25Z",
          "tree_id": "89f1db2b9baf7765d8b419f8bbcef6a890453b35",
          "url": "https://github.com/lambdaclass/ethrex/commit/73d94a2457e3e1277a7a4736b9d534b5d23fd53d"
        },
        "date": 1743688681478,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 193600467450,
            "range": "± 1409107936",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c9b0dbbe875497eff4c47f928a1e7de10f83059d",
          "message": "feat(l1): adjust byte code batch size (snap sync parameter) (#2338)\n\n**Motivation**\nPrevious changes have sped up other components of the snap sync process,\nmaking faults in the byte code fetcher more evident. The byte code\nfetcher used the same batch size as storage requests, 300, which is far\nmore than the byte codes normally returned by a peer request, causing\nthe byte code fetcher to keep on fetching the last batches when all\nother fetchers have already finished.\nThis PR reduces the batch size down to 70 so that it coincides with the\namount of byte codes regularly returned by peers\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Rename constant `BATCH_SIZE` -> `STORAGE_BATCH_SIZE`\n* Add constant `BYTECODE_BATCH_SIZE`\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-03T13:28:35Z",
          "tree_id": "166aff3e46e72fb6a5a4d83faedfc765e01c6e93",
          "url": "https://github.com/lambdaclass/ethrex/commit/c9b0dbbe875497eff4c47f928a1e7de10f83059d"
        },
        "date": 1743689921923,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 184410905603,
            "range": "± 1401636606",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "f3576706e2a45bc96e5709693f4b9453fd6db25d",
          "message": "feat(l1): abstract syncer <-> codebase interaction (#2303)\n\n**Motivation**\nThe codebase (mainly rpc) currently interacts with the synced by trying\nto acquire its lock, which works if we only need to know if the synced\nis busy, but no longer works if we need more precise information about\nthe sync such as what is the mode of the current sync. This PR\nintroduces the `SyncSupervisor` who is in charge of storing the latest\nfcu head, starting and restarting sync cycles and informing the current\nsync status at all times\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2282",
          "timestamp": "2025-04-03T13:28:05Z",
          "tree_id": "e2d4bc14288b64cff5ad094313010233d5543046",
          "url": "https://github.com/lambdaclass/ethrex/commit/f3576706e2a45bc96e5709693f4b9453fd6db25d"
        },
        "date": 1743689935033,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 185738763425,
            "range": "± 1374578941",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "065b797d9f2eb422532032d23081b8f61b028fec",
          "message": "ci(l1): add job that makes sure cli is in sync with README. (#2390)\n\n**Motivation**\nAvoid update to the cli code to end up in an outdated README\n\n**Description**\n- Added a job that checks that the help output in the ethrex command\nthat is in the README is in sync with the code.\n\nCloses #2247",
          "timestamp": "2025-04-03T14:19:03Z",
          "tree_id": "94dc2eb9093c38a7e6bd45d594d3a2f7c5115cc7",
          "url": "https://github.com/lambdaclass/ethrex/commit/065b797d9f2eb422532032d23081b8f61b028fec"
        },
        "date": 1743692921453,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 184947992254,
            "range": "± 1037254491",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "99c544092663bb241c9cf09b07158415658bd966",
          "message": "refactor(l2): remove references to vm internal api. (#2299)\n\n**Motivation**\nL2 code was accessing internal apis from the vm crate, specifically\n`revm` constructs. This is attempt to replace those with the public api,\nso that we can easily switch between revm and levm.\n\n**Description**\n- Replaces references to `ethrex_vm::backends::` from the prover\nbackends.\n- Moved `ExecutionDB ` to `vm/db.rs`. It is still somewhat coupled with\nrevm but less than before. It should be totally decoupled.\n\n---------\n\nCo-authored-by: Javier Chatruc <jrchatruc@gmail.com>\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>\nCo-authored-by: Jeremías Salomón <48994069+JereSalo@users.noreply.github.com>\nCo-authored-by: JereSalo <jeresalo17@gmail.com>\nCo-authored-by: fmoletta <99273364+fmoletta@users.noreply.github.com>",
          "timestamp": "2025-04-03T15:31:56Z",
          "tree_id": "e5ee0003621e4a3b89c6d8c759c30963b487504f",
          "url": "https://github.com/lambdaclass/ethrex/commit/99c544092663bb241c9cf09b07158415658bd966"
        },
        "date": 1743697308730,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 186392698099,
            "range": "± 654097985",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "95512809+Himess@users.noreply.github.com",
            "name": "Himess",
            "username": "Himess"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a4cf43126c0b911f2eb3738dde0975720db96ebe",
          "message": "refactor(core): update clap attributes to #[arg(...)] and #[command(...)] (#2238)\n\n**Description**\nThis PR updates deprecated `#[clap(...)]` attributes to their modern\nequivalents in `clap` 4.x.\nThe current codebase still uses outdated syntax that has been deprecated\nsince version 4.0.\nBy making this update, we ensure compatibility with future versions and\nmaintain code quality.\n\nCloses #2237 \n\n**Test**\nI ran cargo check --features clap/deprecated after making the changes,\neverything looks correct and aligned with the latest clap syntax.\n\n\n\n![image](https://github.com/user-attachments/assets/0f2de8f8-9775-4e31-a703-a7ae5e0623f0)\n\nCo-authored-by: Martin Paulucci <martin.c.paulucci@gmail.com>",
          "timestamp": "2025-04-03T15:39:55Z",
          "tree_id": "618d755c4f07612c8755a04b36f550143e00ea1c",
          "url": "https://github.com/lambdaclass/ethrex/commit/a4cf43126c0b911f2eb3738dde0975720db96ebe"
        },
        "date": 1743697846957,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 188094419106,
            "range": "± 766209671",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3f45ff776f570b988d9fab1c51c23fbf38e4ae16",
          "message": "refactor(l1): cleanup the public api of rpc crate (#2319)\n\n**Motivation**\nHaving a clean and explicit `lib.rs` that only exposes necesary\nfunctions to the outside\n\nThe idea is for every crate:\n- To minimize the functions/objects that are exposed\n- To make them explicit in a centralized location (lib.rs)\n\nSome crates from the workspace are already like this, others are in the\nprocess of being refactored.",
          "timestamp": "2025-04-03T16:36:41Z",
          "tree_id": "b640918af09795326754d9934486fd7120171ba5",
          "url": "https://github.com/lambdaclass/ethrex/commit/3f45ff776f570b988d9fab1c51c23fbf38e4ae16"
        },
        "date": 1743701267792,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 185618654746,
            "range": "± 689737321",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "56402156+fkrause98@users.noreply.github.com",
            "name": "Francisco Krause Arnim",
            "username": "fkrause98"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b6841f00000029f0184cd3b5ae8e235a5406ac5d",
          "message": "ci: restore trie benchmark (#2308)\n\n**Motivation**\n\nAdd a CI job to compare the trie speed results.\n\n---------\n\nCo-authored-by: fmoletta <99273364+fmoletta@users.noreply.github.com>",
          "timestamp": "2025-04-03T17:20:37Z",
          "tree_id": "adee21b7d8eb60f8125412d9cd38d611ab1d49c9",
          "url": "https://github.com/lambdaclass/ethrex/commit/b6841f00000029f0184cd3b5ae8e235a5406ac5d"
        },
        "date": 1743703955920,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 188928141075,
            "range": "± 793787747",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b672cd078b2d9112fd6d800ff849d65e9c13b7a6",
          "message": "ci(core): standarize workflow naming. (#2395)\n\n**Motivation**\nBe able to easily see what triggers each workflow\n\n**Description**\n- Standarized naming of workflow files.\n- Restricted some workflows to certain path changes\n- Minor naming changes",
          "timestamp": "2025-04-04T09:23:12Z",
          "tree_id": "16b31ec633d9393d1028df53a82324773c863a12",
          "url": "https://github.com/lambdaclass/ethrex/commit/b672cd078b2d9112fd6d800ff849d65e9c13b7a6"
        },
        "date": 1743761547438,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182442624526,
            "range": "± 2114014788",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mrugiero@gmail.com",
            "name": "Mario Rugiero",
            "username": "Oppen"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "cebab85b71c49ce965fe86b435868ae769625496",
          "message": "feat(l1,l2): make write path APIs async (#2336)\n\n**Motivation**\n\nSome of our sync APIs can produce starving when running on Tokio due to\ntaking a long time to reach the next `await`-point.\nSpecifically, writing to the DB tends to take a long time, which blocks\nother tasks, sometimes the whole runtime due to how the scheduler in\nTokio works.\nThus, we need a way to inform the runtime we're going to be working for\na while, and give it control while we wait for stuff.\n\n**Description**\n\nTake the mutable APIs for the DB and mark them `async`. Then bubble that\nup to their users. Then make the functions non-blocking by using\n`spawn_blocking` to run on the blocking thread, releasing the runtime to\nhandle more work.\nThe DB writing APIs had to change to pass-by-value to satisfy the\nborrow-checker in the blocking task context. I think I can use proper\nlifetime bounds with a helper crate, if that's preferred. The values\nwere already being discarded after passing to the DB, so passing by\nvalue should not be a problem either way.\n\nSpecial considerations:\n- For some work performed before benchmarks and EF tests which are\ninherently synchronous I opted for calling with an ad-hoc runtime\ninstance and `block_on`, as that might reduce the changes needed by\nlocalizing the async work. If desired, that can be changed up to making\na `tokio::main`. The same is true for some setup functions for tests.\n- For the DBs I had to separate the Tokio import. This is because they\nneed to compile with L2, which means provers' custom compilers, and\nthose don't support the networking functions in the stdlib, which Tokio\nwith full features (as the workspace dep declares) brings them in.\n- The InMemoryDB was left untouched other than updating the interfaces,\ngiven hashmap access should be quick enough.\n- I need to comment on [this\nhack](https://github.com/lambdaclass/ethrex/pull/2336/files#diff-264636d3ee6ee67bd6e136b8c98f74152de6a8e2a07f597cfb5f622d4e0d815aR143-R146):\n`and_then` can't be used on futures and everything became a mess without\nthat little helper.\n- I'm unsure about whether or not we also want to cover the read APIs,\nat least for consistency I would think so, but for now I left them out.\n\ncloses #2402",
          "timestamp": "2025-04-04T14:16:33Z",
          "tree_id": "ada0fd5a18b103edb80f5fc4526a26ff6ce89be1",
          "url": "https://github.com/lambdaclass/ethrex/commit/cebab85b71c49ce965fe86b435868ae769625496"
        },
        "date": 1743779204225,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 183372687645,
            "range": "± 745106382",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iamslown@gmail.com",
            "name": "iamslown",
            "username": "iamslown"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "cf6cc6c5e3aeb86dc529751d6130de8eb251ee7e",
          "message": "docs(l2, l1): fixed dead links (#2363)\n\n**Motivation**\n\nDead links negatively impact developer experience and make it harder to\nunderstand architectural decisions.\n\n**Description**\n\nI updated two dead documentation links:\n\n1. In `state_diffs.md`:\n   - Updated zkSync pubdata architecture reference from:\n     `docs/specs/data_availability/pubdata.md`\n     to:\n     `docs/src/specs/data_availability/pubdata.md`\n\n2. In `Network.md` (ref #639 ):\n   - Updated Kademlia table implementation reference from:\n     `crates/net/kademlia.rs`\n     to:\n     `crates/networking/p2p/kademlia.rs`",
          "timestamp": "2025-04-04T14:45:52Z",
          "tree_id": "d6c3c80b9b8def26834312ce8dee120c7536cc96",
          "url": "https://github.com/lambdaclass/ethrex/commit/cf6cc6c5e3aeb86dc529751d6130de8eb251ee7e"
        },
        "date": 1743780940514,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 185862907204,
            "range": "± 942764473",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "6aeb01cb9be8680cc1c2ce80faf76f3c858779a2",
          "message": "fix(l1): move on to the next retry upon failed sends on peer handler requests (#2369)\n\n**Motivation**\nThe PeerHandler contains methods to request all sorts of data from peers\nand ins used both in snap and full sync. It uses a retry system to\nensure that we don't misinterpret a malicious/unsynced peer as the data\nnot being available. If one peer doesn't return the requested data we\nwould try with other peers first before assuming that the data is too\nold or doesn't exist.\nWhen we sent the requests to the peer, we were not respecting the retry\npolicy and returning a None response upon first failure. This led the\nsynced to believe that data had become stale when it was not the case.\nThis, on multiple occasions, caused the storage fetcher to cease\nfetching while the state sync was still alive and fetching accounts,\nleaving a huge backlog of storages to heal after the state sync.\nThis PR solves this by moving on to the next retry upon a send error\ninstead of aborting the request and returning an empty response\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Continue to the next retry instead of returning None upon a failed\n`send` in all `PeerHandler` request methods\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-04T15:15:20Z",
          "tree_id": "35cbff8ec03add8f597089a74c32b88a5ba93157",
          "url": "https://github.com/lambdaclass/ethrex/commit/6aeb01cb9be8680cc1c2ce80faf76f3c858779a2"
        },
        "date": 1743782716073,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 186248964840,
            "range": "± 514055303",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c58d3b2a713761c56a6c2d221c59a878dd8ea21b",
          "message": "fix(l1): correctly account for completed segments when showing state sync progress (#2352)\n\n**Motivation**\nCurrenlty, completed segments show as 0% complete when showing state\nsync progress. This is due to the last_key value used to calculate\nprogress not being updated before marking the segment as finished. This\nPR fixes this issue\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Set last key when marking segment state sync finalization in the state\nsync progress tracker\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number\n\n---------\n\nCo-authored-by: Mario Rugiero <mrugiero@gmail.com>",
          "timestamp": "2025-04-04T16:00:14Z",
          "tree_id": "50dc45a61e6bfe90d6bece14260519defc70bf4c",
          "url": "https://github.com/lambdaclass/ethrex/commit/c58d3b2a713761c56a6c2d221c59a878dd8ea21b"
        },
        "date": 1743785455078,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 190126874748,
            "range": "± 430342626",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ee2369f18ff027a7dc359dcad038e504a76c9e50",
          "message": "refactor(l1,levm): refactor state transtitions for LEVM (#2396)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n- Fix, improve clarity and behavior of `get_state_transitions()` for\nLEVM\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n- Before we were adding unnecessary information to account updates and\nwe were saying some things were updated when they actually stayed the\nsame. We now don't do this.\n- I refactored the function so that it is more simple and clear; it was\nunnecessarily messy.\n- A few more EF State Tests from some old forks pass.\n\nAdditional: Adds `refresh-evm-ef-tests` to levm Makefile. It is\nnecessary because tests get outdated pretty easily.",
          "timestamp": "2025-04-04T20:27:45Z",
          "tree_id": "b0b43b11dd73d322e50f5a411674a44abacd0145",
          "url": "https://github.com/lambdaclass/ethrex/commit/ee2369f18ff027a7dc359dcad038e504a76c9e50"
        },
        "date": 1743801474231,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 183902124093,
            "range": "± 921900689",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "575f7d2f07c2af95ddd420f002781b54e062515a",
          "message": "chore(levm): remove unused levm import (#2394)\n\n**Motivation**\n\nThis was the last remnant of revm on the levm codebase and gluecode for\nethrex\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-07T14:28:36Z",
          "tree_id": "b7de3f5a6e42aee3b6a9ef41ebade2371a2766da",
          "url": "https://github.com/lambdaclass/ethrex/commit/575f7d2f07c2af95ddd420f002781b54e062515a"
        },
        "date": 1744039115643,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 185253654742,
            "range": "± 668661570",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "56402156+fkrause98@users.noreply.github.com",
            "name": "Francisco Krause Arnim",
            "username": "fkrause98"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "50bf2e54c02ed89e18bdb75b95c0a50420eca52a",
          "message": "perf(l1,l2): avoid double RLP encoding. (#2353)\n\n**Description**\nThis PR introduces a change to avoid an unnecessary double-encoding for\nRLP sequences\n\ncloses #2414\n\n---------\n\nCo-authored-by: fmoletta <99273364+fmoletta@users.noreply.github.com>",
          "timestamp": "2025-04-07T15:35:50Z",
          "tree_id": "dffd43609b5b5be6d22e77fe7533a51db57b5820",
          "url": "https://github.com/lambdaclass/ethrex/commit/50bf2e54c02ed89e18bdb75b95c0a50420eca52a"
        },
        "date": 1744043092282,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182632011793,
            "range": "± 689287871",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Io",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "6e5536d5f2231dfeb0dc6025dcfb5e4ccb71cb05",
          "message": "refactor(l1): use non-hardcoded fork name (#2416)\n\n**Motivation**\n\nAvoids hardcoding fork name in the Transactions RPC as mentioned in\n#2185\n\n**Description**\n\nReads the current fork from the queried block instead of hardcoding it.",
          "timestamp": "2025-04-08T13:53:38Z",
          "tree_id": "b973e3a017227e8aeabb034e10399c19adc5b68b",
          "url": "https://github.com/lambdaclass/ethrex/commit/6e5536d5f2231dfeb0dc6025dcfb5e4ccb71cb05"
        },
        "date": 1744123384232,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 184027510509,
            "range": "± 1516770499",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "8be6e86a322bdfd018e0e63f8ec248f65e777aee",
          "message": "feat(l1): persist bad blocks in db. (#2267)\n\n**Motivation**\nDon't have to rely on the global mutex of the Syncer to fetch invalid\nblocks\n\n**Description**\nNot sure if this is the ultimate solution, Im still unsure if it is\nbetter to store invalid ancestors in db or in memoy\n\n---------\n\nCo-authored-by: fmoletta <99273364+fmoletta@users.noreply.github.com>",
          "timestamp": "2025-04-08T14:14:39Z",
          "tree_id": "198b1eebd6cadbd7d6647e1cba166fd15604f77f",
          "url": "https://github.com/lambdaclass/ethrex/commit/8be6e86a322bdfd018e0e63f8ec248f65e777aee"
        },
        "date": 1744124665056,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 185471675947,
            "range": "± 709233683",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9eba126d45bc6bcd68736fbe671431a364d034e9",
          "message": "fix(l1): potential panics in calculations done to show sync progress (#2427)\n\n**Motivation**\nSome of the calculations done to show the sync progress can overflow\nunder certain conditions. This PR solves them by using safer arithmetic\nfunctions and bigger type sizes\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Replace `-` with `saturating_sub` and use `U512` more often when\ncomputing state sync & trie rebuild progress'\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-09T15:09:23Z",
          "tree_id": "62b9a5fb6bb9fcd8845b287dac838b125621a161",
          "url": "https://github.com/lambdaclass/ethrex/commit/9eba126d45bc6bcd68736fbe671431a364d034e9"
        },
        "date": 1744214305536,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181076178159,
            "range": "± 495012675",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "43799596+JulianVentura@users.noreply.github.com",
            "name": "Julian Ventura",
            "username": "JulianVentura"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "0c1dd6dfc5132d187455614d37e8f8c3a14d222c",
          "message": "fix(l1,l2): update test data genesis files with missing contracts (#2418)\n\n**Description**\n\nWe have some genesis files under `test_data` directory which are used on\nunit tests.\n\nThis PR:\n- Fixes the address of the EIP-2935 system contract on some of the\ngenesis files.\n- Adds the EIP-4788, EIP-7002, EIP-7251 and deposits contract to those\nsame genesis files\n\nThese contracts are not being used in the unit tests, so this addition\nis only for consistency.",
          "timestamp": "2025-04-09T15:36:17Z",
          "tree_id": "502dbafe3086181532b6d51b6de28b7284589b4d",
          "url": "https://github.com/lambdaclass/ethrex/commit/0c1dd6dfc5132d187455614d37e8f8c3a14d222c"
        },
        "date": 1744215901370,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182144236573,
            "range": "± 695850480",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "b82d80003cdb2481674adb45a321f920251cca82",
          "message": "fix(l2): reject L2PrivilegedTx from RPC (#2429)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nWe need to reject L2Privileged transactions from the RPC, as it will\nbrake the chain.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-04-09T15:36:36Z",
          "tree_id": "6449b01bd66d12a69af9d4350ca6e3d688e0f7e7",
          "url": "https://github.com/lambdaclass/ethrex/commit/b82d80003cdb2481674adb45a321f920251cca82"
        },
        "date": 1744215941673,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181422253000,
            "range": "± 735467064",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ebffcf9a2f6f1f837e22f1acf7b0dee841b6caa7",
          "message": "fix(core): fix criterion benchmark (#2439)\n\n**Motivation**\n\nOn #2419 the criterion benchmark was broken printing extra lines, which\ncauses the parser to fai.\n\n**Description**\n\nReplaces `println!()` with `info!()` on the non-user-interactive path.",
          "timestamp": "2025-04-11T16:30:14Z",
          "tree_id": "b5cf755daa37c8f847c6ec6530fa05b31505007b",
          "url": "https://github.com/lambdaclass/ethrex/commit/ebffcf9a2f6f1f837e22f1acf7b0dee841b6caa7"
        },
        "date": 1744395130383,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181852194743,
            "range": "± 1130607773",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "03e95cb482bd8766ad1717d27717a471fe6949ad",
          "message": "docs(levm): add docs for database and cache (#2412)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n- Explain `GeneralizedDatabase`, `Database` trait and `CacheDB`\nhopefully in a simple way\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-11T18:13:07Z",
          "tree_id": "d26498d66653e50871aa2d3ab8eee4f8466c39f5",
          "url": "https://github.com/lambdaclass/ethrex/commit/03e95cb482bd8766ad1717d27717a471fe6949ad"
        },
        "date": 1744398742055,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 183085377267,
            "range": "± 686088626",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "d842767031dfb99d4fe315e6a6528fe464ac9417",
          "message": "fix(levm): try fix blockchain tests (#2436)\n\n**Motivation**\n- Fix most blockchain EF Tests with LEVM.\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\nEvery change made here fixes some tests:\n- our gas_used is now like REVM's, no more subtracting gas_used -\nrefunded outside the vm to get gas used.\n- there was a little issue with the system_address when we made a\ngeneric contract call, we were deleting it from cache when in fact we\nshould only delete it if it didn't exist before.\n- I also implemented a backup for the coinbase account to restore it's\nstate when making a generic contract call so that it doesn't change.\n- We had differences in `get_state_transitions` with REVM that did not\nimpact the state but reducing these differences solved some tests. It\nwas simply that we were saying that an EOF had code: None, while with\nREVM we say code: Some(b“”). The error was kind of silly and I could\nhave fixed it outside the `get_state_transitions` but that was the quick\nfix. However, it is always good to return the same as the other\nimplementation because it enables us to debug better!\n- I fixed gas consumption issue in Prague transactions, we had it wrong\nin LEVM. I find it strange that the STF EFTests do not test this. I\nrefactored the whole gas consumption in LEVM's `finalize_execution()`\nbecause it was kinda messy.\n- Fix account removal in LEVM: we were removing the receiver account\nfrom the cache when reverting a transaction. This made sense when we\nused the cache just for executing one transaction because we didn't want\nto modify the receiver, but in any other scenario it was a mistake!\n- Fix blob base fee calculation in opcode `blobbasefee`. We were\ncalculating it in Pectra with Cancun values.\n\nResult: all tests pass except one prague 7702 test and one stack\noverflow test.",
          "timestamp": "2025-04-11T19:45:04Z",
          "tree_id": "d7ebb4c66b90ab18785fba31da9ef171f9298d08",
          "url": "https://github.com/lambdaclass/ethrex/commit/d842767031dfb99d4fe315e6a6528fe464ac9417"
        },
        "date": 1744403801527,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182322649564,
            "range": "± 756927307",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "5c9f45926ce10b0b0fd9564ac0704ca34768eed9",
          "message": "fix(levm): fix last blockchain ef test (#2455)\n\n**Motivation**\n\nHere we fix the last ef test from the blockchain test suite.\n\n**Description**\n\nWhen calling a precompiled contract we were returning an execution\nreport with gas refunded equal to zero. Before Pectra this wasn't a\nproblem because there wasn't a case were a refund could be made.\nBut with de EIP-7702, in the `prepare_execution` hook a refund was\npossible so that behavior had to be changed.\n\nThis branch follows the PR #2436 fixing the test mentioned there.\n\nCloses #2449\n\n---------\n\nCo-authored-by: JereSalo <jeresalo17@gmail.com>",
          "timestamp": "2025-04-14T18:58:15Z",
          "tree_id": "963492ca2b2dc873be94d8fa01c1a75db760d598",
          "url": "https://github.com/lambdaclass/ethrex/commit/5c9f45926ce10b0b0fd9564ac0704ca34768eed9"
        },
        "date": 1744660082517,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180177828782,
            "range": "± 512333073",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5b5c66ca6a7670993734f17a8ce087d636bc03f4",
          "message": "feat(l1, l2): make some store getters async (#2430)\n\n**Motivation**\n\nLike with #2336 the goal is to avoid blocking the current task.\n\n**Description**\n\nMakes store getters not related to tries (and thus the EVM) async, and\npropagates the changes to users of store. They are made async by using\n`spawn_blocking `\n\nMany instances of functional code (`and_then`, `map`) had to be replaced\ndue to bad async support.\n\nCloses #2424",
          "timestamp": "2025-04-15T15:12:25Z",
          "tree_id": "f4bfd48005450cea74206d968d0e16848b16e82d",
          "url": "https://github.com/lambdaclass/ethrex/commit/5b5c66ca6a7670993734f17a8ce087d636bc03f4"
        },
        "date": 1744732961073,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182099820077,
            "range": "± 1160214253",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "72b8edc87a0bf08e4f2bf16caddcdb019bf47a66",
          "message": "feat(l2): make deposits on l2 work as expected (#2332)\n\n**Motivation**\n\nIn this PR we refactor some of the code and add functionality to work as\nexpected. Remove the txs magic hack data #2147\n\n**Description**\n\n* Add a `recipient` field to the privileged transactions.\n* Deposit the value to the recipient instead of the `to` address.\n* Add functionality to call a contract and make a deposit in the same\nprivileged transaction.\n* Remove the signing of the privileged transactions.\n* Remove the checking of the nonce and balance when making the deposit,\nhere we mint the tokens.\n* Add new hook in the L2 to address this new features for the Privileged\nTransactions.\n\nCloses #2147\n\n---------\n\nCo-authored-by: fborello-lambda <federicoborello@lambdaclass.com>\nCo-authored-by: Federico Borello <156438142+fborello-lambda@users.noreply.github.com>\nCo-authored-by: Estéfano Bargas <estefano.bargas@fing.edu.uy>\nCo-authored-by: Javier Chatruc <jrchatruc@gmail.com>\nCo-authored-by: Manuel Iñaki Bilbao <manuel.bilbao@lambdaclass.com>\nCo-authored-by: Tomás Casagrande <53660242+samoht9277@users.noreply.github.com>",
          "timestamp": "2025-04-15T18:57:34Z",
          "tree_id": "443633b23eea8ca5aeeb368d7f2f9dd728a217b6",
          "url": "https://github.com/lambdaclass/ethrex/commit/72b8edc87a0bf08e4f2bf16caddcdb019bf47a66"
        },
        "date": 1744746415715,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 183296746051,
            "range": "± 730727745",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9d0fa850eb3d3f4232a1511c933824556bbc1194",
          "message": "feat(levm): fix gas refund on precompiles on success (#2471)\n\n**Motivation**\n\nIn this PR we fix the missing gas refunded while giving the execution\nreport on a precompile\n\n**Description**\n\nReturn the gas refunded in the environment instead of zero value",
          "timestamp": "2025-04-15T19:20:18Z",
          "tree_id": "b4546f40212ff5dc89b98148794ab01d2a1939de",
          "url": "https://github.com/lambdaclass/ethrex/commit/9d0fa850eb3d3f4232a1511c933824556bbc1194"
        },
        "date": 1744747749288,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180475257584,
            "range": "± 431007686",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "43799596+JulianVentura@users.noreply.github.com",
            "name": "Julian Ventura",
            "username": "JulianVentura"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "62f8887c09c9cf09792e2f2feba202f94ceee373",
          "message": "ci(l1): enable blockchain ef tests to be run with levm (#2440)\n\n**Motivation**\n\nWe want to run the Ethereum Foundation blockchain tests with LEVM.\nCurrently, we are only running them with REVM.\n\n**Description**\n\nThis PR modifies the EF tests runner so it executes the EF tests with\nboth VMs. The implementation combines both executions on the same\ncommand `cargo test`, but could be easily modified to include a feature\nflag to separate both executions if that's desired.",
          "timestamp": "2025-04-15T20:40:51Z",
          "tree_id": "c251efcdd649c8dd819a52a5506c90434cd64f34",
          "url": "https://github.com/lambdaclass/ethrex/commit/62f8887c09c9cf09792e2f2feba202f94ceee373"
        },
        "date": 1744752491715,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179805809394,
            "range": "± 901043701",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "72628438+avilagaston9@users.noreply.github.com",
            "name": "Avila Gastón",
            "username": "avilagaston9"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "3df5a169d87b54cc506209ff45d5474079aecde9",
          "message": "l2(chore): pin solc version to latest (#2460)\n\n**Motivation**\n\nA new version of the Solidity compiler\n([v0.8.29](https://github.com/ethereum/solidity/releases/tag/v0.8.29))\nhas been released. This update modifies the bytecode format, which\ncauses changes in the `genesis-l2.json` file when launching L2 with\n`make init`.\n\n**Description**\n\n- Pin Solidity version `0.8.29` in our contracts.\n- Updates `genesis-l2.json`.\n\n\n\nCloses None",
          "timestamp": "2025-04-16T13:50:42Z",
          "tree_id": "508e55289804bfde4069c037c1a0e3b5e62af9c7",
          "url": "https://github.com/lambdaclass/ethrex/commit/3df5a169d87b54cc506209ff45d5474079aecde9"
        },
        "date": 1744814324640,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182652744348,
            "range": "± 946337281",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "72628438+avilagaston9@users.noreply.github.com",
            "name": "Avila Gastón",
            "username": "avilagaston9"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "febb4dd946d795383b13c3eaa3ab122502d74b79",
          "message": "fix(l2): limit block to blob size (#2292)\n\n**Motivation**\n\nWith our current implementation, if a block state diff exceeds the blob\nsize, we are unable to commit that block.\n\n**Description**\n\nThis PR provides an initial solution by calculating the state diff size\nafter including each transaction in the block. If the size exceeds the\nblob limit, the previous state is restored and transactions continue to\nbe added from the remaining senders in the mempool.\n\n**Observations**\n- `blockchain::build_payload` was \"replicated\" in\n`block_producer/payload_builder.rs` with two key differences:\n    - It doesn't call `blockchain::apply_system_operations`.\n- It uses a custom L2 implementation of `fill_transactions` which adds\nthe logic described above.\n- Some functions in `blockchain` are now public to allow access from\n`payload_builder`.\n- `PayloadBuildContext` now contains am owned `Block` instead of a\nmutable reference of it, as we need to be able to clone the\n`PayloadBuildContext` to restore a previous state.\n- `PayloadBuildContext` is cloned before each transaction execution,\nwhich may impact performance.\n- After each transaction, `vm.get_state_transitions()` is called to\ncompute the state diff size.\n- Since `REVM::vm.get_state_transitions()` mutates the\n`PayloadBuildContext`, we need to clone it to avoid unintended changes.\n- An `accounts_info_cache` is used to prevent calling `get_account_info`\non every tx execution.\n\n> [!WARNING]\n> - **REVM**: Payload building is **10x slower** due to frequent\n`clone()` calls.\n> - **LEVM**: Payload building is **100x slower** because\n`LEVM::get_state_transitions` internally calls `get_account_info`.\n>\n> *These issues will be addressed in future PRs.*",
          "timestamp": "2025-04-16T15:12:01Z",
          "tree_id": "1df649115f10f692d2a6bf2380c43c3ca61f0531",
          "url": "https://github.com/lambdaclass/ethrex/commit/febb4dd946d795383b13c3eaa3ab122502d74b79"
        },
        "date": 1744819205978,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181976763690,
            "range": "± 803942940",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9e9ca0ba6522da60421f7a0497452b42f55b04ef",
          "message": "fix(l1): don't cancel storage healer if state healing ends earlier (#2464)\n\n**Motivation**\nCurrenlty, when state healing finishes, the storage healer is cancelled,\neven if there are still storages to be fetched and the tries are not\nstale yet, which slows down storage healing due to the frequent restarts\nif state healing ends before storage healing. This PR aims to fix this\nby changing the behaviour to not cancel storage healing if state healing\nis complete, but to instead give this information to the storage healer\nvia an AtomicBoo, so that it can decide whether to stop based on if the\nstate has become stale, or if no more paths are left to heal and mo more\nwill be added by the state healer.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add AtomicBool param to `storage_healer` to signal whether state\nhealing has ended\n* Don't cancel storage healing if state healer ended due to state\nhealing being complete\n* End storage healer if there are no more pending storages left & state\nhealing has ended\n* (Misc) Remove outdated comment\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-16T15:48:52Z",
          "tree_id": "861ddf3b5256943e565b14c1c68a2cebd82332ef",
          "url": "https://github.com/lambdaclass/ethrex/commit/9e9ca0ba6522da60421f7a0497452b42f55b04ef"
        },
        "date": 1744821371322,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179960048645,
            "range": "± 542547153",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "3bbb56e09d9b9dd4d7ffeb3f1d086c45c014db44",
          "message": "feat(l1): show healing in progress message at set intervals (#2462)\n\n**Motivation**\nWe are not able to perform estimations on when healing will end, but we\nshould also not stay completely silent while healing takes place, as\nthis is not very user-friendly.\nThis PR aims to add messages to inform wether state and storage healing\nare taking place, at the same pace as we show state sync and rebuild\nprogress. For state sync, pending paths will be shown. These can give an\ninsight on the progress, as the amount of paths will continuously\nincrease as we progress through the trie, but will start gradually\ndecreasing as we near the end of healing. For storages it is a slightly\ndifferent story as we don't have the full number of pending storages\navailable for showing so we only show the storages currently in the\nqueue.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Periodically show amount of paths left during State Healing\n* Periodically show storages in queue during Storage Healing\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-04-16T15:49:55Z",
          "tree_id": "704c72c4ecd616dbd7508e265f6e27c1fced5279",
          "url": "https://github.com/lambdaclass/ethrex/commit/3bbb56e09d9b9dd4d7ffeb3f1d086c45c014db44"
        },
        "date": 1744821480306,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182871455247,
            "range": "± 971409953",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "cfec7f9820dc8148ca3bfdbca61b9627f6b80108",
          "message": "refactor(l1): remove usage of `assert_eq` in frame decoding (rlpx) (#2456)\n\n**Motivation**\nReplaces `assert_eq` usage with proper errors in rlpx frame decoding\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add error variant `RLPXError::InvalidMessageFrame`\n* Remove usage of `assert_eq` in `RLPxCodec::decode` impl\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #1748",
          "timestamp": "2025-04-16T15:51:53Z",
          "tree_id": "a77bb95438ba0f7a3b739013ec6813c160de2d78",
          "url": "https://github.com/lambdaclass/ethrex/commit/cfec7f9820dc8148ca3bfdbca61b9627f6b80108"
        },
        "date": 1744821601079,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 183723113373,
            "range": "± 1046565490",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "5aa86f0cc1eadab93d31b51e3da6810a40a3f483",
          "message": "feat(l1): add mainnet as preset network (#2459)\n\n**Motivation**\nAdds mainnet bootnodes & genesis file so we can connect to mainnet by\npassing `--network mainnet`\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* add mainnet bootnodes & genesis file\n* recognize mainnet as preset network\n* update docs\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nContributes to #72 \n\n**Notes**\nMainnet genesis file is quite large, it is copied from\n[here](https://github.com/eth-clients/mainnet/blob/main/metadata/genesis.json)",
          "timestamp": "2025-04-16T15:51:24Z",
          "tree_id": "33b9b3860027d8e5dbe3b7dfa7e1b8987ffd54b4",
          "url": "https://github.com/lambdaclass/ethrex/commit/5aa86f0cc1eadab93d31b51e3da6810a40a3f483"
        },
        "date": 1744821649238,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 184905153941,
            "range": "± 1620058016",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "43799596+JulianVentura@users.noreply.github.com",
            "name": "Julian Ventura",
            "username": "JulianVentura"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ac268f18df3eb0d5d6018cb8f1ecd8e68d3d8b84",
          "message": "fix(levm): remove logs from transaction revert (#2483)\n\n**Description**\n\nThis PR removes logs from the `ExecutionReport` when a transaction\nreverts.\nWith this fix, LEVM no longer breaks at block 80k while syncing on\nHolesky testnet.",
          "timestamp": "2025-04-16T17:31:45Z",
          "tree_id": "bcf6ebd65344950ec4210b77adfb5026859378b4",
          "url": "https://github.com/lambdaclass/ethrex/commit/ac268f18df3eb0d5d6018cb8f1ecd8e68d3d8b84"
        },
        "date": 1744827647641,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 183126585472,
            "range": "± 688815986",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "onoratomatias@gmail.com",
            "name": "Matías Onorato",
            "username": "mationorato"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "717e3fff8f1dedac3b8305cbe70da9a5b6934023",
          "message": "feat(l2): enviroment variables option for \"l2 init\" command (#2488)\n\n**Motivation**\n\ndevops\n\n**Description**\n\nadd the following enviroment variables to customize the l2 init command.\nSpecially useful for systemd or docker services\n\n```\nETHREX_NETWORK\nETHREX_DATADIR\nETHREX_METRICS_PORT\nETHREX_EVM\nETHREX_HTTP_ADDR\nETHREX_HTTP_PORT\n```",
          "timestamp": "2025-04-16T20:59:59Z",
          "tree_id": "e0eefdaf598a93910cb30be506f19588056376ef",
          "url": "https://github.com/lambdaclass/ethrex/commit/717e3fff8f1dedac3b8305cbe70da9a5b6934023"
        },
        "date": 1744840037946,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180360634406,
            "range": "± 362640567",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "git@edgl.dev",
            "name": "Edgar",
            "username": "edg-l"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b5e339c6642f682d306fc4cd31766c1bf394ee34",
          "message": "perf(core,levm): remove some unnecessary clones and make functions const (#2438)\n\n**Motivation**\n\nIncrease perfomance, improve code.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\nSome methods took Vec by value just to take it's length, requiring a\ncostly clone each time.\n\nSome methods could be made const, if the compiler can make use of this\nit may increase perfomance.\n\nChanged a drain to a into_iter, which is simpler and has better\nperfomance.\n\nAided by the following clippy command:\n```\ncargo clippy --all-features -- -D clippy::perfomance -D clippy::nursery -A clippy::use_self -A clippy::too_long_first_doc_paragraph -A clippy::derive_partial_eq_without_eq -A clippy::option_if_let_else\n```",
          "timestamp": "2025-04-19T09:19:22Z",
          "tree_id": "cd27b1fdd390a4fa1ca676105bb9766c2f41de3f",
          "url": "https://github.com/lambdaclass/ethrex/commit/b5e339c6642f682d306fc4cd31766c1bf394ee34"
        },
        "date": 1745057202144,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180626848933,
            "range": "± 1169250545",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomas.arjovsky@lambdaclass.com",
            "name": "Tomás Arjovsky",
            "username": "Arkenan"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "6ef0ee92fe7139708075b6d99d9a1bcfb44b386e",
          "message": "perf(l1,l2): use the new load test for the CI scripts (#2467)\n\nChanges:\n- Flamegraph Watcher srcript now:\n  - Uses the new load test.\n  - Fails if any line fails (e.g. the load test binary panics).\n- CI:\n  - The flamegraphs are now updated on push to main again.\n- Compilation and running is separated to delete the \"while not\ncompiled\" polling.\n- Reth version is pinned so it does not rely on 2024 features and can be\ncompiled again.\n- Load test:\n  - `make` targets now run in release mode.\n- now waits until all transactions are included before exciting. There's\na flag to set a timeout.\n- All ethrex_l2 references are deleted from CI and the watcher.\n\n\nCloses #2466",
          "timestamp": "2025-04-21T15:09:03Z",
          "tree_id": "5dfce79fcd2149e14c1625ffc07705c61a4d0762",
          "url": "https://github.com/lambdaclass/ethrex/commit/6ef0ee92fe7139708075b6d99d9a1bcfb44b386e"
        },
        "date": 1745251071658,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 184169516668,
            "range": "± 667330299",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomas.arjovsky@lambdaclass.com",
            "name": "Tomás Arjovsky",
            "username": "Arkenan"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "775bc45e1ed11c1ae972060927d895f1f8729be2",
          "message": "Add metrics for execution and storage times per block (#2302)\n\nThis PR adds logs for each imported block:\n- Transaction count\n- ms/Ggas for execution\n- ms/Ggas for storage\n- Percentage between execution and storage in an imported block",
          "timestamp": "2025-04-21T15:13:37Z",
          "tree_id": "af40ae7dd8fb62237eaf2dda9f443d91273f4ea9",
          "url": "https://github.com/lambdaclass/ethrex/commit/775bc45e1ed11c1ae972060927d895f1f8729be2"
        },
        "date": 1745251353422,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 186567021368,
            "range": "± 550643280",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "bc9aafd01f72111d2e45fc46a42e811aaf1916cb",
          "message": "chore(l1): standarize revm/levm behaviour when importing blocks. (#2452)\n\n**Description**\n- standarize revm/levm behaviour when importing blocks\n- Remove fork choice when importing blocks.\n- Move block importing out of blockchain module",
          "timestamp": "2025-04-21T15:27:54Z",
          "tree_id": "a2cadb20fceeeb4d23356a1971ee8c23cbcae128",
          "url": "https://github.com/lambdaclass/ethrex/commit/bc9aafd01f72111d2e45fc46a42e811aaf1916cb"
        },
        "date": 1745252136964,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181810883425,
            "range": "± 1012161046",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "0674de0d2d0b2fda4b4ff27b0656782a300d69c6",
          "message": "chore(core): replace LEVM channel with L1 channel (#2484)\n\n**Motivation**\n\nThe L1 slack channel is now used for LEVM development\n\n**Description**\n\nThis PR replaces the LEVM webhook with the L1 webhook.",
          "timestamp": "2025-04-21T15:30:45Z",
          "tree_id": "bde30ce237de3fc760fdc906aec00a8ff7b96adc",
          "url": "https://github.com/lambdaclass/ethrex/commit/0674de0d2d0b2fda4b4ff27b0656782a300d69c6"
        },
        "date": 1745252325731,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182250042835,
            "range": "± 760924532",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "a6ea3695d81be0da11c476f2b5a706fa3ca3eda7",
          "message": "fix(l1): fix `--dev` mode to work with Prague fork. (#2481)\n\n**Motivation**\nDev mode is currently broken.\n\n**Description**\n- Changed the block producer so use the `v4` methods that are used in\nPrague.\n- Improved error messages\n\nCloses #2376",
          "timestamp": "2025-04-21T15:50:04Z",
          "tree_id": "203e539848ec619eab90723c9e33fa5e271a92a1",
          "url": "https://github.com/lambdaclass/ethrex/commit/a6ea3695d81be0da11c476f2b5a706fa3ca3eda7"
        },
        "date": 1745253470496,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182089076648,
            "range": "± 715840275",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "05c050893b5457dc640d1a9411b3124e54ad7e95",
          "message": "fix(l2): fixes and cleanup of `to_execution_db()` (#2482)\n\n**Motivation**\n\nProver's execution was failing because of wrong data in the ExecutionDB.\nThere were also some cases where data was missing but the current tests\ndidn't catch it.\n\n**Description**\n\n- fixes saving final storage values instead of initial ones.\n- fixes saving only touched storage values, instead of read ones too.\n- removes unused `new_store`\n- simplifies code",
          "timestamp": "2025-04-21T18:08:49Z",
          "tree_id": "5c96fa446b6c39f51c14a0049416cc58fc37c394",
          "url": "https://github.com/lambdaclass/ethrex/commit/05c050893b5457dc640d1a9411b3124e54ad7e95"
        },
        "date": 1745261752849,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180941567477,
            "range": "± 563627713",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "d637bb2f9e383b5e8cf7bcb3e63281026879e166",
          "message": "feat(l1,l2): add ethereum metrics exporter and grafana support (#2434)\n\n**Motivation**\n\nAllows seeing the status of the test network.\n\n**Description**\n\n- Implements a net_peerCount dummy (required to enable several\nethereum-metrics-exporter modules)\n- Enables ethereum-metrics-exporter with a grafana dashboard in for the\nkurtosis localnet\n\nNote: prometheus v3 must be used since the prometheus kurtosis package\nadds fallback_scrape_protocol.\n\nCloses #2317",
          "timestamp": "2025-04-21T18:08:15Z",
          "tree_id": "6d32ef5b08de1a8430227a883b66cfb4e8f430ec",
          "url": "https://github.com/lambdaclass/ethrex/commit/d637bb2f9e383b5e8cf7bcb3e63281026879e166"
        },
        "date": 1745261771875,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182465500438,
            "range": "± 466663760",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "da370653d49f9b1bfcf520b0f7cf5ba2cea089d7",
          "message": "fix(l2): use Prague genesis file to fix prover (#2509)\n\n**Motivation**\nFix prover tests in CI\n\n**Description**\nhttps://github.com/lambdaclass/ethrex/pull/2481 broke the L2 tests since\nthey were using a Cancun genesis, and the block producer has switched to\nPrague",
          "timestamp": "2025-04-21T19:33:53Z",
          "tree_id": "9cadc7a7370a43edbcc5ba0b41fba2699b8a662a",
          "url": "https://github.com/lambdaclass/ethrex/commit/da370653d49f9b1bfcf520b0f7cf5ba2cea089d7"
        },
        "date": 1745266914345,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 183444993601,
            "range": "± 1109833066",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "793227a9066bf4840c75194bd2513034486bd770",
          "message": "chore(l2): report prover integration test failure to slack (#2503)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-21T20:24:23Z",
          "tree_id": "4e5a9a14717ce9b8b647dd579a8d016ac6f34b30",
          "url": "https://github.com/lambdaclass/ethrex/commit/793227a9066bf4840c75194bd2513034486bd770"
        },
        "date": 1745269901870,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182203817085,
            "range": "± 822225260",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "0d08a2f7161918817cdd2de61bb6eaa766b2a3a8",
          "message": "feat(levm): also check cache when querying if account exists (#2489)\n\n**Motivation**\n\nFixes 14 state ef-tests that rely on newly created accounts being\ntreated as existing.\n\n**Description**\n\nInstead of checking directly on the database, the cache is also queried\nwhen determining whether an account exists.",
          "timestamp": "2025-04-21T20:32:51Z",
          "tree_id": "d044cd229c13b8e2eab5e18614cd2c8e4606856c",
          "url": "https://github.com/lambdaclass/ethrex/commit/0d08a2f7161918817cdd2de61bb6eaa766b2a3a8"
        },
        "date": 1745270430403,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182360857225,
            "range": "± 501368925",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e7832a19f14dd87c537cfe35f85a890886fdf5cb",
          "message": "refactor(levm): refactor execution into being non-recursive (#2473)\n\n**Motivation**\n\nIn #2445 a Stack Overflow was found with high call stacks. Turns out\neach level of recursion was adding ~4kB to the stack.\n\nSimply reducing the stack usage would've required extensive stack usage\nand hard to understand code.\n\n**Description**\n\nMakes code execution non-recursive, and instead uses call_stacks to save\nthe call stacks and return_data to save return parameters.\n\nFunctions that took the current frame by parameter now read it with a\nfunction.\n\nCloses #2445\n\n---------\n\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>\nCo-authored-by: Martin Paulucci <martin.c.paulucci@gmail.com>",
          "timestamp": "2025-04-21T21:50:45Z",
          "tree_id": "6f6b4e98135b8bb37b1c408651818ae1108ae2c7",
          "url": "https://github.com/lambdaclass/ethrex/commit/e7832a19f14dd87c537cfe35f85a890886fdf5cb"
        },
        "date": 1745275091792,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180265853102,
            "range": "± 372516910",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "755f7e370fbe465b851e0729d80ecab675893e43",
          "message": "ci(l1): skip flaky snap test. (#2520)\n\n**Motivation**\nSnap test is flaky\n\n**Description**\nIssue created to reenable it:\nhttps://github.com/lambdaclass/ethrex/issues/2521",
          "timestamp": "2025-04-22T15:28:48Z",
          "tree_id": "206df44fbbd56c613281102a2751950433461487",
          "url": "https://github.com/lambdaclass/ethrex/commit/755f7e370fbe465b851e0729d80ecab675893e43"
        },
        "date": 1745338600798,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181904331938,
            "range": "± 814857140",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "10e78b77ae57c69a7a233e3ee100a726568abc79",
          "message": "fix(levm): read chain_id from chain config, not from transaction (#2531)\n\n**Motivation**\n\nAt block 576991 the sync with holesky would fail due to an incorrect\nstate calculation.\n\n**Description**\n\nAs per [EIP-1344](https://eips.ethereum.org/EIPS/eip-1344) the chain ID\nshould be read from the chain configuration and not the transaction.\nThis is because transactions may not have replay protection configured.",
          "timestamp": "2025-04-22T21:03:04Z",
          "tree_id": "7af2cc43bb9e641b34ca6ad3067c047670821fc6",
          "url": "https://github.com/lambdaclass/ethrex/commit/10e78b77ae57c69a7a233e3ee100a726568abc79"
        },
        "date": 1745358713434,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 184484398938,
            "range": "± 1291788460",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "git@edgl.dev",
            "name": "Edgar",
            "username": "edg-l"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "81d0efd6128c97408976748d433ea52b78aec746",
          "message": "perf(core): transform the inline variant of NodeHash to a const sized array (#2516)\n\n**Motivation**\n\nTransforms the inline variant of NodeHash to a fixed size array,\nallowing it to be copy and avoiding expensive Vec clones.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses [#2444](https://github.com/lambdaclass/ethrex/issues/2444)",
          "timestamp": "2025-04-23T10:26:26Z",
          "tree_id": "3074530a72744b5954f9a07cee17e075024e0c72",
          "url": "https://github.com/lambdaclass/ethrex/commit/81d0efd6128c97408976748d433ea52b78aec746"
        },
        "date": 1745406837978,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180950429351,
            "range": "± 867364898",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "aqdrgg19@gmail.com",
            "name": "VolodymyrBg",
            "username": "VolodymyrBg"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "cbcaef7226599de6598fc7d73e9108265468c803",
          "message": "Add --metrics flag to enable/disable metrics collection (#2497)\n\n**Motivation**\n\nCurrently, metrics are always initialized in the application, even if\nthey're not needed. This can cause unnecessary resource usage and\npotential overhead. By making metrics optional through a command-line\nflag, users can have more control over their node's resource consumption\nand behavior.\n\n**Description**\n\nThis PR adds a new --metrics command-line flag that allows users to\nexplicitly enable or disable metrics collection and exposition. When\nmetrics are disabled, the metrics server is not started, saving\nresources.\n\nKey changes:\n- Add a new metrics_enabled boolean flag to the Options struct\n- Update the init_metrics function to check this flag before starting\nthe metrics server\n- Modify both the main ethrex command and the L2 command to\nconditionally initialize metrics\n- Update the L2 Makefile to explicitly enable metrics\n- Update documentation to include information about the new flag",
          "timestamp": "2025-04-23T13:36:34Z",
          "tree_id": "95cd1917af6b0b3367de556fd233325ad03531e7",
          "url": "https://github.com/lambdaclass/ethrex/commit/cbcaef7226599de6598fc7d73e9108265468c803"
        },
        "date": 1745418317227,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182542421832,
            "range": "± 560350561",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "12560266+MauroToscano@users.noreply.github.com",
            "name": "Mauro Toscano",
            "username": "MauroToscano"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "35ca6af05a4bc73a028d5d0a9dfa418e22c3e363",
          "message": "fix(l2): add missing requirements to run the L2 (#2512)\n\n**Motivation**\n\nBuild fails if requirements are not met. In particular, solc versions\nneed to be the requirements\n\n**Description**\n\nThis adds a short description of the requirements\n\n---------\n\nCo-authored-by: Martin Paulucci <martin.c.paulucci@gmail.com>",
          "timestamp": "2025-04-23T13:49:55Z",
          "tree_id": "e79395c6da2328ec5038c3c2148295eef07d2756",
          "url": "https://github.com/lambdaclass/ethrex/commit/35ca6af05a4bc73a028d5d0a9dfa418e22c3e363"
        },
        "date": 1745419073885,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180346542446,
            "range": "± 612174471",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "fbfe149c015ec249dc4e7c11ef3f3582f9e04e54",
          "message": "fix(levm): improve get state transitions LEVM (#2518)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n- Make `get_state_transitions` we use un LEVM return the same as the one\nin REVM.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n- I made changes in the past to make `get_state_transitions` for both\nLEVM and REVM the same for comparison but I missed one aspect. We only\nwant to show the code in an `AccountUpdate` if the code itself has been\nmodified, not just the `AccountInfo`. Before we were returning the code\nin the `AccountUpdate` even if only the nonce of the contract changed\nfor example.\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-23T13:58:35Z",
          "tree_id": "4ad9afc6415e5a389ea6f7b5f00818246856e177",
          "url": "https://github.com/lambdaclass/ethrex/commit/fbfe149c015ec249dc4e7c11ef3f3582f9e04e54"
        },
        "date": 1745419694445,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182754061490,
            "range": "± 538702793",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b9cb992689c85c2c037083d731855e56aac8a2ee",
          "message": "fix(levm): also use config chain_id (#2537)\n\n**Motivation**\n\nIn #2531 only one of the creation methods was fixed to use chain_id from\nthe config\n\n**Description**\n\nThis PR changes it in the other constructor",
          "timestamp": "2025-04-23T14:39:27Z",
          "tree_id": "e40badc4c2f4dbf0ab6d390fe9e95a799ef7ce9f",
          "url": "https://github.com/lambdaclass/ethrex/commit/b9cb992689c85c2c037083d731855e56aac8a2ee"
        },
        "date": 1745422032652,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180822174433,
            "range": "± 819046710",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7c0321931a9d740cde2df4c2985bde12396ad273",
          "message": "fix(l1): validate incoming payloads even when the node is syncing. (#2426)\n\n**Motivation**\nWe should be able to do payload validations even when the node is in a\nsync process (except if it's snap sync).\n\n**Description**\n- Refactored some code to make it flatter\n- Removed early return when the node is syncing\n- minor renames for clarity sake.",
          "timestamp": "2025-04-23T15:12:25Z",
          "tree_id": "26ec7cc923f16129fd1ab25a6edc1bb7f48865a7",
          "url": "https://github.com/lambdaclass/ethrex/commit/7c0321931a9d740cde2df4c2985bde12396ad273"
        },
        "date": 1745423999081,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179706822635,
            "range": "± 903113760",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "125112044+cypherpepe@users.noreply.github.com",
            "name": "Cypher Pepe",
            "username": "cypherpepe"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f4478d799bd295abc4221114e1928c26945b658d",
          "message": "docs(l2): remove `proposer` in README.md (#2470)\n\n**Motivation**\n\nThe `proposer.md` file was renamed to `sequencer.md`, and the old link\nin the docs index became obsolete.\n\n**Description**\n\nHi! I removed the outdated reference to `proposer.md` in\n`crates/l2/docs/README.md` since it's now covered under `sequencer.md`.\nref:\nhttps://github.com/lambdaclass/ethrex/pull/2269/files#diff-95ad85cd4c72b932973f93785a8a1f365b56757d2972fe671ff33221b7bd0546\n\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>",
          "timestamp": "2025-04-23T15:42:54Z",
          "tree_id": "8a30102721c5d479e217e1fa614fdba954934913",
          "url": "https://github.com/lambdaclass/ethrex/commit/f4478d799bd295abc4221114e1928c26945b658d"
        },
        "date": 1745425793708,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178363269347,
            "range": "± 553866422",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "72628438+avilagaston9@users.noreply.github.com",
            "name": "Avila Gastón",
            "username": "avilagaston9"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "1694e0a06911e139edbcef7c7d96c4c641d8c00b",
          "message": "chore(l2): temporarily disable pico job (#2549)\n\n**Motivation**\n\nIn #2397, we are having issues with Pico dependencies. Since we are not\nusing it at the moment, we prefer to temporarily disable the job until\nwe focus on it later.\n\n**Description**\n\n- Disable pico job renaming `pr-main_l2_prover_nightly.yaml` to\n`.github/workflows/pr-main_l2_prover_nightly.yaml.disabled`.\n- Create #2550.\n\nCloses None",
          "timestamp": "2025-04-23T18:20:08Z",
          "tree_id": "cacb973c16a7f2e8442651f7263fe6a233f833fd",
          "url": "https://github.com/lambdaclass/ethrex/commit/1694e0a06911e139edbcef7c7d96c4c641d8c00b"
        },
        "date": 1745435235867,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178477293548,
            "range": "± 717683689",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5a7d7591cf064065d760c757e3de8aa21a45f511",
          "message": "refactor(levm,l1,l2): split block execution and update generation (#2519)\n\n**Motivation**\n\nCurrently during batch processing, the state transitions are calculated\nfor every block and then merged, when it would be more performant to\ncalculate them once at the end.\n\n**Description**\n\nThis PR removes the account updates from the execution result and makes\nevery consumer manually request them.\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2504",
          "timestamp": "2025-04-23T19:20:35Z",
          "tree_id": "625c9224878ee0b6606f300688a2dd88f72a98fd",
          "url": "https://github.com/lambdaclass/ethrex/commit/5a7d7591cf064065d760c757e3de8aa21a45f511"
        },
        "date": 1745438866023,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179314675128,
            "range": "± 863506155",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4e6a960d89fefc07cd33f64e52e9c6c9f4d8d5cc",
          "message": "fix(levm): don't read from parent block when processing withdrawals (#2556)\n\n**Motivation**\nWhen processing withdrawals with levm, accounts that are not cached are\nfetched directly from the `Store` (aka our DB) using the block's parent\nhash instead of using the `StoreWrapper` api that already knows which\nblock's state to read accounts from (as we do for all other DB reads).\nThis works fine when executing one block at a time as the block that the\nStoreWrapper reads from is the block's parent. But when we execute\nblocks in batch, the StoreWrapper reads from the parent of the first\nblock in the batch, as changes from the following blocks will be\nrecorded in the cache, so when processing withdrawals we may not have\nthe state of the current block's parent in the Store.\nThis PR fixes this issue by using the `StoreWrapper` to read uncached\naccounts from the batch's parent block instead of looking for an\naccounts in a parent state that may not exist. It also removes the\nmethod `get_account_info_by_hash` so we don't run into the same issue in\nthe future\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Remove misleading method `get_account_info_by_hash` from levm Database\ntrait (this can lead us to read state from a block that is not the\ndesignated parent block and which's state may not exist leading to\nInconsistent Trie errors)\n* Remove the argument `parent_block_hash` from `process_withdrawals`\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-23T20:59:41Z",
          "tree_id": "0358e2acbf771434f59343540eed21326b65e394",
          "url": "https://github.com/lambdaclass/ethrex/commit/4e6a960d89fefc07cd33f64e52e9c6c9f4d8d5cc"
        },
        "date": 1745444950159,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 183262364831,
            "range": "± 1251079032",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2d049b952259f1e659eabba2859583b79a243188",
          "message": "feat(levm): improve state EF Tests (#2490)\n\n**Motivation**\n\n- Make running and modifying EF Tests a better experience\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n- Remove spinner and just use prints\n- We now can filter the tests we want to run by fork name(we do the\nfiltering in the parsing). Default is all forks.\n- Upgrade tests to more recent version\n- Run some Legacy Tests that we weren't running before. This adds a lot\nof tests more, it is the folder Cancun under LegacyTests. There will be\nrepeated tests with the folder GeneralStateTests, we may want to find a\nsolution for that so that it takes less time to execute.\n- Create docs in `README.md`\n- Implement some nits in the runner, making code easier to understand.\n- Ignore a few tests that take too long to run so that we can check for\nbreaking changes fast.\n- Fix comparison report against LEVM, they weren't working correctly\nmostly because we were mishandling our Cache\n- Tidy the report, now it is much more clear and easier for debugging.\nAlso the code is easier to follow and more concise too!\n- Fix some tests with REVM, basically now using constructor of\n`BlobExcessGasAndPrice` and setting chain id to 1 (as we do in LEVM).\n- Changed `get_state_transitions`\n[here](https://github.com/lambdaclass/ethrex/pull/2518) so that REVM and\nLEVM account updates are mostly the same and the comparison is more\naccurate for the person who is debugging any test.\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-23T22:19:57Z",
          "tree_id": "1506ee48aca41baf76b6efcc4ba14a8efce48863",
          "url": "https://github.com/lambdaclass/ethrex/commit/2d049b952259f1e659eabba2859583b79a243188"
        },
        "date": 1745449736762,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181072202781,
            "range": "± 397962718",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "df4953a92e31bc7f4d5d4d3b630c044bd70a1a6b",
          "message": "fix(l2): uncomment final state check and validate gas in sp1 and exec (#2558)\n\n**Motivation**\n\nThese were commented in #2291 (merged to main), probably for test/dev\npurposes, and left like that",
          "timestamp": "2025-04-23T23:50:12Z",
          "tree_id": "7a78514818bcb29c10a493c7195e3ec00584b9d9",
          "url": "https://github.com/lambdaclass/ethrex/commit/df4953a92e31bc7f4d5d4d3b630c044bd70a1a6b"
        },
        "date": 1745455062971,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179654368637,
            "range": "± 1325691899",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7de4cda33a31a6c1b7f2648e80dc139d59534f89",
          "message": "docs(l1): add quick guide on how to sync with holesky (#2485)\n\n**Motivation**\nAdd instructions on how to set up ethrex along with a consensus node and\nstart syncing with holesky or other testnets\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number\n\n---------\n\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>",
          "timestamp": "2025-04-24T13:46:45Z",
          "tree_id": "f9b23b1153bb8410eddceb7ff2b4209625962f47",
          "url": "https://github.com/lambdaclass/ethrex/commit/7de4cda33a31a6c1b7f2648e80dc139d59534f89"
        },
        "date": 1745505323939,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180817164433,
            "range": "± 916976286",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "5c277318ab9bc576090ad2cda7a15c6f29b0e92a",
          "message": "chore(l2): separete ProverServer and ProofSender (#2478)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nCurrently the ProverServer component have the responsibility for both\nact as a server for the ProverClient (i.e., send blocks to prove and\nreceive proofs) and send proofs to the L1 contract to verify blocks.\nThis tasks can be parallel and decoupled one from the other.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nA new struct `L1ProofSender` is created that periodically checks if\nthere're new proofs to send to the L1, removing that job from the\n`ProverServer`. Also, components were renamed for better clarity.\nNote that the config names were not changed as there's a WIP PR (#2501)\ndoing a full refactor of it\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\n---------\n\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>\nCo-authored-by: Javier Chatruc <jrchatruc@gmail.com>\nCo-authored-by: Ivan Litteri <67517699+ilitteri@users.noreply.github.com>",
          "timestamp": "2025-04-24T14:16:46Z",
          "tree_id": "8aac0de34b34e464d4c735695c6172f469c18226",
          "url": "https://github.com/lambdaclass/ethrex/commit/5c277318ab9bc576090ad2cda7a15c6f29b0e92a"
        },
        "date": 1745507084798,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181778629387,
            "range": "± 1292938979",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "fedacking@gmail.com",
            "name": "fedacking",
            "username": "fedacking"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3226f668d1a9e93b8462bc5eea917efe813ddb1d",
          "message": "fix: Trimming newlines from jwt files (#2560)\n\n**Motivation**\n\njwt.hex files can end in newlines, in particular odometer's test jwt.\nThis change aims to handle that case.\n\n**Description**\n\nThis change executes `trim_end_matches` on the `contents` read from a\njwt.hex file passed to ethrex.",
          "timestamp": "2025-04-24T14:26:38Z",
          "tree_id": "9b12817878c2516cfefaa02630b1f7e04a9b309f",
          "url": "https://github.com/lambdaclass/ethrex/commit/3226f668d1a9e93b8462bc5eea917efe813ddb1d"
        },
        "date": 1745507654049,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181446212274,
            "range": "± 590523106",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "588da6509b115b22090fb99cbaeee28b6ce8fd1f",
          "message": "fix(core): flamegraphs width (#2566)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nThe flamegraphs are displayed half-sized on GH Pages.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nIn the CI, remove the line that cause the problem. Added Zed editor\nconfig directory to `.gitignore` btw.\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-04-24T15:18:39Z",
          "tree_id": "50f1def90f95b2dee9087426bd8d921462fd03cc",
          "url": "https://github.com/lambdaclass/ethrex/commit/588da6509b115b22090fb99cbaeee28b6ce8fd1f"
        },
        "date": 1745510776703,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181436739081,
            "range": "± 1101213285",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "f93e67a0601ebf79bcc80d768aa89aa243584983",
          "message": "ci(l1): comment flaky hive cancun engine test (#2572)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n- Temporarily comment Invalid Missing Ancestor Syncing ReOrg and\nInvlalid P9 and P10. Should be fixed later, the issue is [this\none](https://github.com/lambdaclass/ethrex/issues/2565)\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-24T15:33:48Z",
          "tree_id": "70b85220ffea5a7b71eeeccefe92cd2b0d8e4c39",
          "url": "https://github.com/lambdaclass/ethrex/commit/f93e67a0601ebf79bcc80d768aa89aa243584983"
        },
        "date": 1745511649285,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178439868681,
            "range": "± 1382376837",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "3efa34009a3076f453712844ca568a1230a9f49a",
          "message": "refactor(l2): contracts (#2551)\n\n**Motivation**\n\n- Some variable names are misleading and can confuse the reader.\n- There was no getter method for withdrawal logs merkle roots in\n`CommonBridge`.\n\n**Description**\n\n- Renamed deposit logs related variables in `OnChainProposer` and\n`CommonBridge` and their interfaces with clearer names.\n- Improved some documentation on the above.\n- Renamed some misleading naming in variables such as `commitment` in\n`OnChainProposer` and its interface.",
          "timestamp": "2025-04-24T16:22:26Z",
          "tree_id": "4709ca0a82fd79f54fe982bfe30243d91260a939",
          "url": "https://github.com/lambdaclass/ethrex/commit/3efa34009a3076f453712844ca568a1230a9f49a"
        },
        "date": 1745514604594,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179858713379,
            "range": "± 992177586",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "214e3538a6bedec40d1949abd5e06a30482a1848",
          "message": "fix(levm): change CI check for EFTests because London doesn't pass 100% now (#2568)\n\n**Motivation**\n\n- Fix CI \n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n- London tests don't pass 100% because new tests have been added and it\nseems that there is an edge case we are not currently passing. For now I\nwanted to disable the check that sees if all tests from Prague to London\npassed and set it to look only for Prague to Paris.\n- Added `workflow_dispatch` to this workflow so that we can run it\nmanually.\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-24T18:58:51Z",
          "tree_id": "a39d89520f475a92c876dd4d5be84807e522357f",
          "url": "https://github.com/lambdaclass/ethrex/commit/214e3538a6bedec40d1949abd5e06a30482a1848"
        },
        "date": 1745524097884,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181497989700,
            "range": "± 4677402185",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "francisco.gauna@lambdaclass.com",
            "name": "fedacking",
            "username": "fedacking"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f99ca4d7bb6182e3b1726872934667d1e34a2f4f",
          "message": "fix(core): Made engine_forkchoiceUpdatedV3 second parameter optional (#2575)\n\n**Motivation**\n\nThis PR makes it so that when parsing engine_forkchoiceUpdatedV3 the\nsecond parameter isn't required. This came to light while testing\nodometer #2507, which sent the updates without the second parameter.\nThis change makes it more conforming with the spec.\n\n**Description**\n\nMade it so that the second optional parameter in\nengine_forkchoiceUpdatedV3 ( Payload attributes) isn't required to be\nsent in the post request.\n\nNote: this was already working if the second parameter was sent as a\nnull or had problems.",
          "timestamp": "2025-04-24T20:15:34Z",
          "tree_id": "7a969e5bdf99cc706aff3cf76164bf75a02ac450",
          "url": "https://github.com/lambdaclass/ethrex/commit/f99ca4d7bb6182e3b1726872934667d1e34a2f4f"
        },
        "date": 1745528579439,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180929381801,
            "range": "± 352304824",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "125112044+cypherpepe@users.noreply.github.com",
            "name": "Cypher Pepe",
            "username": "cypherpepe"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7057773bcbf25b9e6df98e99f49c485b22b0165e",
          "message": "docs(l2): fixed broken link in `state_diffs.md` (#2495)\n\n**Motivation**\n\nThe old link to the ZKsync pubdata spec was outdated due to recent file\nrestructuring in the MatterLabs repo.\n\n**Description**\n\nI fixed the link in `crates/l2/docs/state_diffs.md` to point to the new\npath:\nfrom  \n - `docs/src/specs/data_availability/pubdata.md`  \nto  \n-\n`docs/src/specs/contracts/settlement_contracts/data_availability/pubdata.md`\n\nCo-authored-by: Martin Paulucci <martin.c.paulucci@gmail.com>",
          "timestamp": "2025-04-24T20:44:55Z",
          "tree_id": "4384d24baf372d0f215cef5ac27991a01ac6c1a7",
          "url": "https://github.com/lambdaclass/ethrex/commit/7057773bcbf25b9e6df98e99f49c485b22b0165e"
        },
        "date": 1745530353288,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181868933463,
            "range": "± 840939804",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "44068466+SDartayet@users.noreply.github.com",
            "name": "SDartayet",
            "username": "SDartayet"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "0fea11060b7bbf822ce23b2de90958f4d0987c2a",
          "message": "ci(l2): removed matrices and made jobs that used them run sequentially (#2541)\n\n**Description**\n\nRemoved matrices in lint jobs, and made the commands run sequentially\nwith each alternative configuration.\n\nResolves issue [2538](https://github.com/lambdaclass/ethrex/issues/2538)",
          "timestamp": "2025-04-24T21:13:24Z",
          "tree_id": "c9fa1dff9abcb37e14485e804eeee10dc28135fb",
          "url": "https://github.com/lambdaclass/ethrex/commit/0fea11060b7bbf822ce23b2de90958f4d0987c2a"
        },
        "date": 1745532142775,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178540899928,
            "range": "± 756117182",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "44068466+SDartayet@users.noreply.github.com",
            "name": "SDartayet",
            "username": "SDartayet"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "69900a49fbc75b02d340d181db4c7e50b3de6c19",
          "message": "chore(levm): remove unused code (#2585)\n\n**Motivation**\n\nCleaning up the codebase.\n\n**Description**\n\nRemoved functions that weren't part of the interface nor used anywhere\nin the code. Also removed an outdated TODO comment.\n\nCloses issue [2544](https://github.com/lambdaclass/ethrex/issues/2544).",
          "timestamp": "2025-04-25T13:58:51Z",
          "tree_id": "26b99a2690fe8158e8a558774e461fb132ff54d7",
          "url": "https://github.com/lambdaclass/ethrex/commit/69900a49fbc75b02d340d181db4c7e50b3de6c19"
        },
        "date": 1745592371186,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 176117755615,
            "range": "± 570695607",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "dab0e8859bc604399b859acfd9a8f4248ce18546",
          "message": "chore(l2): remove unused revm modules (#2587)\n\n**Motivation**\n\nNow that the L2 has fully defaulted to levm, both for execution and\nproving, these modules became unused.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-25T14:29:55Z",
          "tree_id": "337feed959ee08adf526c1bcb05341646daf6fdf",
          "url": "https://github.com/lambdaclass/ethrex/commit/dab0e8859bc604399b859acfd9a8f4248ce18546"
        },
        "date": 1745594223306,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179871691798,
            "range": "± 442490815",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "09e7db7745d819c253b85bb01b107f9b37e3fd00",
          "message": "feat(l2): add validium mode (#2365)\n\nValidium is a [scaling\nsolution](https://ethereum.org/en/developers/docs/scaling/) that\nenforces integrity of transactions using validity proofs like\n[ZK-rollups](https://ethereum.org/en/developers/docs/scaling/zk-rollups/),\nbut doesn’t store transaction data on the Ethereum Mainnet.\n\n**Description**\n- Replace EIP 4844 transactions for EIP 1559\n- Modify OnChainProposer contract so that it supports validium. It is\nnot the most efficient way of doing it but the simplest.\n- Now the config.toml has a validium field.\n\nNote: I'm not 100% sure about the changes that I made to the\nOnChainProposer, there may be a mistake in the additions that I made. I\nwill review it though but I still consider worth opening this PR.\n\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2313\n\n---------\n\nCo-authored-by: ilitteri <ilitteri@fi.uba.ar>\nCo-authored-by: Ivan Litteri <67517699+ilitteri@users.noreply.github.com>",
          "timestamp": "2025-04-25T15:00:11Z",
          "tree_id": "10f190d348d63ce751ceece38c6bc46c616e082d",
          "url": "https://github.com/lambdaclass/ethrex/commit/09e7db7745d819c253b85bb01b107f9b37e3fd00"
        },
        "date": 1745596037447,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 177697617762,
            "range": "± 1030206806",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "90105443+DiegoCivi@users.noreply.github.com",
            "name": "DiegoC",
            "username": "DiegoCivi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2fc4b21a88a5b9f26c1fc5aeffb4de1afcd15547",
          "message": "chore(l1): update execution spec tests 4.0.0 -> 4.3.0 (#2586)\n\n**Motivation**\n\nA new\n[release](https://github.com/ethereum/execution-spec-tests/releases/tag/v4.3.0)\non the execution spec tests introduces more coverage for Prague EIPs.\n\n**Description**\n\nWhen executing `make tests` now the new 4.3.0 version of the tests is\nused. As more tests where added in this version, some of them failed so\nthey where added to the skipped array.\n\nCloses #2513",
          "timestamp": "2025-04-25T15:10:53Z",
          "tree_id": "03b597d26a9ab28da51eff1570e37d21fac073c9",
          "url": "https://github.com/lambdaclass/ethrex/commit/2fc4b21a88a5b9f26c1fc5aeffb4de1afcd15547"
        },
        "date": 1745596687243,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178920983018,
            "range": "± 1376402875",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "67846b794d5b0a3beaa02e6f54dca7d862a64001",
          "message": "feat(levm): check logs when running ef tests (#2593)\n\n**Motivation**\n\n- We were just checking that the post state root matched. This checks\nthat logs match too.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n- This PR for now just compares the logs root hash with the provided by\nthe `EFTest` but we might also want to compare against REVM's logs so\nthat the log diff is debuggable in a follow up. This has to be added.\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number\n\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>",
          "timestamp": "2025-04-25T15:30:08Z",
          "tree_id": "5c6871e9c3d4a115dfe16d1c9978011528d0218c",
          "url": "https://github.com/lambdaclass/ethrex/commit/67846b794d5b0a3beaa02e6f54dca7d862a64001"
        },
        "date": 1745597845386,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179487683201,
            "range": "± 670448361",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "4ea9264a5131eac6dec15e65a50f7eddfebe7e7f",
          "message": "docs(l2): add prover docs (#2511)\n\n**Motivation**\n\nWe were lacking detailed documentation about how ethrex-prover works.\n\nCloses #2600\n\n---------\n\nCo-authored-by: Javier Chatruc <jrchatruc@gmail.com>",
          "timestamp": "2025-04-25T19:28:19Z",
          "tree_id": "6270cb995644be723635c599c4731069fc8a1335",
          "url": "https://github.com/lambdaclass/ethrex/commit/4ea9264a5131eac6dec15e65a50f7eddfebe7e7f"
        },
        "date": 1745612221797,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179093631965,
            "range": "± 960705176",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7f1cd7165f019cf50c555bd7dd8240a2a79a27a0",
          "message": "ci(core): make sure clippy catches warnings. (#2506)\n\n**Motivation**\nThere has been warnings that slip through the cracks, specifically the\nones that trigger if a specific combination of flags is\nenabled/disabled. This PR aims to catch most of these.",
          "timestamp": "2025-04-25T21:14:41Z",
          "tree_id": "8fdb0bf167f5df9d1c3f84fc161166a97acf99c3",
          "url": "https://github.com/lambdaclass/ethrex/commit/7f1cd7165f019cf50c555bd7dd8240a2a79a27a0"
        },
        "date": 1745618531861,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179968799412,
            "range": "± 934948267",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "7902f16f1bf9bd25d832a811197053961edcce60",
          "message": "feat(l1, l1): make levm the default vm. (#2603)\n\n**Motivation**\nLevm is becoming more mature, and it needed for the L2. Let's set it as\ndefault across the board.",
          "timestamp": "2025-04-25T21:31:17Z",
          "tree_id": "523f551fc6a35f7572117fd202d7e0bd657cd48f",
          "url": "https://github.com/lambdaclass/ethrex/commit/7902f16f1bf9bd25d832a811197053961edcce60"
        },
        "date": 1745619530880,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180504554495,
            "range": "± 730769707",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "521a9b6de6c82177d11268bc2e93d90129f0422d",
          "message": "fix(l1): fcu not triggering sync if snap is enabled + re-enable snap sync hive test (#2605)\n\n**Motivation**\nPR #2426 changed how fork choice & new payload interact with the syncer\nand also introduced a bug. If snap sync is enabled, then fork choice\nupdate will never attempt to trigger a sync, so the sync process never\ngets started.\nThis PR fixes the bug and also refactors the sync manager api to better\nsuit the new use cases\n<!-- Why does this pull request exist? What are its goals? -->\n* Combine commonly used together `SyncManager` methods `set_head` &\n`start_sync` into `sync_to_head`\n* Remove unused `SyncManager` method `status` and associated struct\n* Make sure sync is triggered during fcu when needed even if snap sync\nis enabled\n* Re-enable snap sync hive test suite\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2521",
          "timestamp": "2025-04-25T21:35:13Z",
          "tree_id": "3a6d17f13666e6990e2a51d4b34764f01ced878c",
          "url": "https://github.com/lambdaclass/ethrex/commit/521a9b6de6c82177d11268bc2e93d90129f0422d"
        },
        "date": 1745619765341,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180123755475,
            "range": "± 1237834244",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9c4574bfa540589b0eed7667ec05ca6680fb637f",
          "message": "fix(l1): bug in storage healer (#2468)\n\n**Motivation**\nThere is currently a bug in the storage healer causing fetched paths to\nnot be properly updated. This makes storage healing virtually infinite\nas fetched paths are constantly being added back to the queue.\nThis fix should restore regular storage healing behaviour\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Fix logic error when updating pending paths for the next fetch during\nstorage healing\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n**Other info**\nThis bug was unknowingly introduced by #2288 \n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-25T21:55:22Z",
          "tree_id": "4dd8cb615b7bbb29962acb2657fc60f08e177084",
          "url": "https://github.com/lambdaclass/ethrex/commit/9c4574bfa540589b0eed7667ec05ca6680fb637f"
        },
        "date": 1745620914566,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178501452158,
            "range": "± 373701351",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "64bca8af4b6266c197fe91a78249a1f22272aa3c",
          "message": "refactor(l1): implement code method for RLPxMessage enum and use it for encoding/decoding (#2454)\n\n**Motivation**\nImplements the refactor specified in the linked issues. Adding a single\n`code` method for the RLPxMessage enum was not enough for both encoding\nand decoding (as we would need to create the struct to call the method)\nso an associated constant was also added to support both needs.\nThis solution fulfills the purpose of the issue, to have only one\ninstance of each message code that we can use for encoding/decoding of\nmessages, but its implementation is more complex than what we would have\nliked. If the complexity is not acceptable, we should close both this PR\nand the originating issue.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Implement `code` method for `RLPxMessage`\n* Add `CODE` associated constant to `RLPxEncode` trait\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #1035  (Also #1034)",
          "timestamp": "2025-04-25T21:56:00Z",
          "tree_id": "17efe8b774bb727673048afc9863d3561999a0ce",
          "url": "https://github.com/lambdaclass/ethrex/commit/64bca8af4b6266c197fe91a78249a1f22272aa3c"
        },
        "date": 1745620943011,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178362957327,
            "range": "± 745995947",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "098a15222ac85f6b87c650eeda89b02ef72eab12",
          "message": "feat(l1): improve rebuilding speed during snap sync (#2447)\n\n**Motivation**\nAfter recent changes in main, rebuilding now takes a lot longer than\nstate sync. This PR aims to mitigate this hit by introducing other\nperformance upgrades\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Increase parallelism when rebuilding storages\n* Reduce intermediate hashing when rebuilding state tries\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nThese changes have increased storage rebuild speed to around the same as\nbefore the changes to store, and has reduced time estimates for state\nrebuild, but doesn't manage to make the state rebuild keep up with the\nstate sync. These changes have not affected state sync speed\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-25T21:55:36Z",
          "tree_id": "a737a894a650aeb03062dc2338cf952fc01b33c2",
          "url": "https://github.com/lambdaclass/ethrex/commit/098a15222ac85f6b87c650eeda89b02ef72eab12"
        },
        "date": 1745620965639,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180780280087,
            "range": "± 716073227",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "07399376fc90f6026f1eab5d904bd81325ef71af",
          "message": "refactor(levm): implement cache rollback (#2417)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n- Implement cache rollback for avoiding cloning the cache during the\nexecution of a transaction.\n\n**Description**\n\n- Now callframe has `cache_backup`, that stores the pre-write state of\nthe account that the callframe is trying to mutate. If the context\nreverts that state is restored in the cache. Otherwise, the parent call\nframe inherits the changes of the child of the accounts that only the\nchild has modified, so that if the parent callframe reverts it can\nrevert what the child did.\n- Move some database related functions that don't need backup to\n`GeneralizedDatabase`\n- Move some database related functions that need backup `VM`. Basically\nit accesses the database backup up if there's a callframe available for\ndoing so.\n- Stop popping callframe whenever possible\n\nSome other changes that it makes:\n- Simplify `finalize_execution`. Specifically the reversion of value\ntransfer and removal of check for coinbase transfer of gas fee.\n- Move some things to `utils.rs` and `gen_db.rs` so that `vm.rs` keeps\nmain functionalities.\n\nCloses #issue_number\n\n---------\n\nCo-authored-by: Javier Chatruc <jrchatruc@gmail.com>\nCo-authored-by: Tomás Paradelo <tomas.paradelo@lambdaclass.com>\nCo-authored-by: Julian Ventura <43799596+JulianVentura@users.noreply.github.com>\nCo-authored-by: Avila Gastón <72628438+avilagaston9@users.noreply.github.com>\nCo-authored-by: fmoletta <99273364+fmoletta@users.noreply.github.com>\nCo-authored-by: Matías Onorato <onoratomatias@gmail.com>\nCo-authored-by: Edgar <git@edgl.dev>\nCo-authored-by: Tomás Arjovsky <tomas.arjovsky@lambdaclass.com>\nCo-authored-by: Martin Paulucci <martin.c.paulucci@gmail.com>\nCo-authored-by: Lucas Fiegl <iovoid@users.noreply.github.com>\nCo-authored-by: Estéfano Bargas <estefano.bargas@fing.edu.uy>\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>\nCo-authored-by: VolodymyrBg <aqdrgg19@gmail.com>\nCo-authored-by: Tomás Paradelo <112426153+tomip01@users.noreply.github.com>\nCo-authored-by: Mauro Toscano <12560266+MauroToscano@users.noreply.github.com>\nCo-authored-by: Cypher Pepe <125112044+cypherpepe@users.noreply.github.com>",
          "timestamp": "2025-04-25T22:00:51Z",
          "tree_id": "e4b4d5e4cee78b4bd5642f0cb8691dce93f0897f",
          "url": "https://github.com/lambdaclass/ethrex/commit/07399376fc90f6026f1eab5d904bd81325ef71af"
        },
        "date": 1745621275272,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 177866198277,
            "range": "± 532002286",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "470a3acfd9e7bd2831dd1afc4e09c0db46318e65",
          "message": "refactor(l2): use deposit hash as the tx hash for l2 txs (#2562)\n\n**Motivation**\n\nHere we want to not process the same deposit to the L2 as two different\ntransactions.\n\n**Description**\n\n* Change the transaction hash of the `PrivilegedL2Transaction` to the\ndeposit hash (instead of the hash of the entire tx) . The one that is\nemitted when the deposit is done\n* In the `l1_watcher` skip transactions that are already on the store.\n\nCloses #2552",
          "timestamp": "2025-04-25T22:21:28Z",
          "tree_id": "98a609a09857cd7baedf9485d321f1906f2697cc",
          "url": "https://github.com/lambdaclass/ethrex/commit/470a3acfd9e7bd2831dd1afc4e09c0db46318e65"
        },
        "date": 1745622590892,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 177148559142,
            "range": "± 1230424192",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9d91f1d39ea186cbab6abf1a83dd5196195d0d08",
          "message": "chore(core): add leftover `Cargo.lock` change (#2620)",
          "timestamp": "2025-04-28T14:24:39Z",
          "tree_id": "84cabcfb60f1b2291d5be33ed072a7e8c4211a7f",
          "url": "https://github.com/lambdaclass/ethrex/commit/9d91f1d39ea186cbab6abf1a83dd5196195d0d08"
        },
        "date": 1745853182831,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181402721317,
            "range": "± 1529816863",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "11b1c882f0fcee5de97ea8b3b6249607d4f50616",
          "message": "fix(l2): bad address parsing was forbidding sequencer to start (#2599)\n\n**Motivation**\n\nwhen fetching verifier contract's addresses, the address was not being\nparsed correctly.\n\nthis is at least one reason the SP1 job is failing right now.\n\nwe should also consider alternatives to using the \"0xaa\" address to flag\na verifier as disabled.\n\n---------\n\nCo-authored-by: Javier Chatruc <jrchatruc@gmail.com>\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>",
          "timestamp": "2025-04-28T15:01:45Z",
          "tree_id": "9777163b5adbed02da98d24c2383661d78704ebe",
          "url": "https://github.com/lambdaclass/ethrex/commit/11b1c882f0fcee5de97ea8b3b6249607d4f50616"
        },
        "date": 1745855977857,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 186176726258,
            "range": "± 615341293",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e0d75223b09f3ba9e4700d1ad967439125503f43",
          "message": "ci(core): run sp1 backend integration test on the merge queue (#2607)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-28T15:37:00Z",
          "tree_id": "2eac24c9bc0d9ed0609d33843eca21ed9bada5ef",
          "url": "https://github.com/lambdaclass/ethrex/commit/e0d75223b09f3ba9e4700d1ad967439125503f43"
        },
        "date": 1745858947335,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179478989639,
            "range": "± 929432664",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "56402156+fkrause98@users.noreply.github.com",
            "name": "Francisco Krause Arnim",
            "username": "fkrause98"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7d56f67ba73ef58038d2fa1b43936757478e4819",
          "message": "ci(l1,l2): pause flamegraph ci (#2622)\n\n**Motivation**\n\nThe current state of this job shows the CI check as failing, which is\nnot necessarily true.\n\n**Description**\n- Comment the 'on' condition to run this workflow on merge to main.",
          "timestamp": "2025-04-28T17:31:29Z",
          "tree_id": "021279c9d09a29907524ef5e465b31a9d1de5b54",
          "url": "https://github.com/lambdaclass/ethrex/commit/7d56f67ba73ef58038d2fa1b43936757478e4819"
        },
        "date": 1745865838984,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179360843225,
            "range": "± 760788254",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "72628438+avilagaston9@users.noreply.github.com",
            "name": "Avila Gastón",
            "username": "avilagaston9"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e90d210a130d1fcc2155ea19b28d782ca3745375",
          "message": "fix(core): exclude ethrex-prover-bench on make lint (#2618)\n\n**Motivation**\n\n`make lint` throws an error in main:\n\n```\nerror occurred in cc-rs: failed to find tool \"nvcc\": No such file or directory (os error 2)\n```\n\n**Description**\n\nExclude `ethrex-prover-bench` when running clippy.\n\nCloses None",
          "timestamp": "2025-04-28T18:34:26Z",
          "tree_id": "8901c93a81eb91872c0fd90457a3c62fd3c9aafb",
          "url": "https://github.com/lambdaclass/ethrex/commit/e90d210a130d1fcc2155ea19b28d782ca3745375"
        },
        "date": 1745869726312,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 184135010188,
            "range": "± 888348559",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49721261+cdiielsi@users.noreply.github.com",
            "name": "cdiielsi",
            "username": "cdiielsi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b421c5fbc464658db6307a612539822cbaf655af",
          "message": "fix(l1): blob transaction init for revm ef tests (#2588)\n\n**Motivation**\n\nFixing REVM tests as specified in issue #2491.\n\n**Description**\n\nThis pr changes the `blob_excess_gas_and_price` variable initialization\nin the `prepare_revm_for_tx` function. Now instead of setting gas price\nin 0 I use the `new` function associated to the `BlobExcessGasAndPrice`\nstruct that sets the gas price by itself with a particular function that\ncalculates it.\n\nThis change drops the failing amount of tests from 2009 to 829.\n\nThis pr solves part of the issue #2491.",
          "timestamp": "2025-04-28T21:14:06Z",
          "tree_id": "bb01d9da7a6c7f67923f3fde238e13d8e67f51a8",
          "url": "https://github.com/lambdaclass/ethrex/commit/b421c5fbc464658db6307a612539822cbaf655af"
        },
        "date": 1745879106302,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180214468361,
            "range": "± 691072243",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "72628438+avilagaston9@users.noreply.github.com",
            "name": "Avila Gastón",
            "username": "avilagaston9"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "a8d2ec410a622827e83a29cc84c8d9b3e6ffb008",
          "message": "feat(l2): commit blocks in batches (#2397)\n\n**Motivation**\n\nTo reduce the number of times we go to the L1 to commit/verify blocks.\n\n**Description**\n\n- Modifies `l1_committer` to merge as many blocks as possible into a\nsingle `StateDiff` before committing, limited by the blob size.\n- Modifies `StateDiff` to now contain both the resulting\n`AccountUpdates` from executing all blocks in the batch and the header\nof the last block.\n- Adapts contracts to use `batchNumbers` instead of `blockNumbers`.\n- Adds a new RPC endpoint, `ethrex_getWithdrawalProof`, which returns\nall necessary data to claim an L1 withdrawal for a given L2 withdrawal\ntransaction hash.\n- Implements `apply_account_updates` for the `ExecutionDB` to prepare\nthe db for executing the next block in the batch.\n- Adds a `L2/storage` with the following tables:\n- `block_number` => `batch_number`: Maps block numbers to batches (used\nby the endpoint to locate a withdrawal's batch).\n- `batch_number` => `Vec<block_number>`: Lists all block numbers\nincluded in a given batch.\n- `batch_number` => `withdrawal_hashes`: Stores withdrawal hashes per\nbatch (used to construct merkle proofs).\n\nCloses None\n\nCreated issues:\n- #2563\n- #2578 \n- #2579 \n- #2617\n\n---------\n\nCo-authored-by: Edgar <git@edgl.dev>\nCo-authored-by: VolodymyrBg <aqdrgg19@gmail.com>\nCo-authored-by: Tomás Paradelo <112426153+tomip01@users.noreply.github.com>\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>\nCo-authored-by: Mauro Toscano <12560266+MauroToscano@users.noreply.github.com>\nCo-authored-by: Martin Paulucci <martin.c.paulucci@gmail.com>\nCo-authored-by: Jeremías Salomón <48994069+JereSalo@users.noreply.github.com>\nCo-authored-by: Lucas Fiegl <iovoid@users.noreply.github.com>\nCo-authored-by: Cypher Pepe <125112044+cypherpepe@users.noreply.github.com>",
          "timestamp": "2025-04-29T15:41:21Z",
          "tree_id": "3e27c2af8e7ae0f8f1cb53f03dc105fdbd2699bf",
          "url": "https://github.com/lambdaclass/ethrex/commit/a8d2ec410a622827e83a29cc84c8d9b3e6ffb008"
        },
        "date": 1745945077919,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181565500339,
            "range": "± 786617050",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "git@edgl.dev",
            "name": "Edgar",
            "username": "edg-l"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "991f0e7f3abaa81d58d759ecc3610b3cfb392804",
          "message": "fix(l1): increase max_fee_per_gas to avoid blocks with 0 txs in load test (#2615)\n\n**Motivation**\n\nDue to feeding so many txs, the base fee keeps increasing so when it\ngoes beyond the load test txs max fee per gas, the block will have 0 txs\ndue to them all having the same max fee per gas.\n\nThis pr increasing the load test max fee per has to u64 MAX and lowers\npriority fee per gas to decreasing (realistically removing) the chance\nof 0 block txs in load tests\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2523",
          "timestamp": "2025-04-29T18:14:52Z",
          "tree_id": "235392c8f894223c0ca351173ac65ab318bb73c8",
          "url": "https://github.com/lambdaclass/ethrex/commit/991f0e7f3abaa81d58d759ecc3610b3cfb392804"
        },
        "date": 1745954109447,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181085441711,
            "range": "± 540111676",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "44068466+SDartayet@users.noreply.github.com",
            "name": "SDartayet",
            "username": "SDartayet"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "3a5a0c39cdaf4614978c7e20bc3ad833a8448195",
          "message": "refactor(levm): refactored new funcion to make it more easily readable (#2641)\n\n**Motivation**\n\nMake it easier to distinguish the differences in instantiation between\ncall and create transactions\n\n**Description**\n\nThe PR changes a match statement in the levm new function, moving some\nof the logic outside of it and leaving inside only the things that\nstricly differ between each branch.",
          "timestamp": "2025-04-29T21:20:29Z",
          "tree_id": "dfc678c1c958af4fc52e7a1de15fb744c78e2196",
          "url": "https://github.com/lambdaclass/ethrex/commit/3a5a0c39cdaf4614978c7e20bc3ad833a8448195"
        },
        "date": 1745965298462,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181600192519,
            "range": "± 860795754",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "240886b7de53acfa1b30b6f9ccd8431c9dc5d851",
          "message": "feat(l2): configure hard cap on L2 commit transactions (#2532)\n\n**Motivation**\n\nHere we want to limit the price we are willing to pay for a commitment\ntransaction from the L2 to the L1\n\n**Description**\n\n* Add two values to the `EthClient`, (`max_fee_per_gas` and\n`max_fee_per_blob_gas`), so we can limit if the fees are two high\n* Add checks in the commitment if any of the fees exceeds the limits\nand, if this happens, return an error\n\nCloses #2498\n\n---------\n\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>",
          "timestamp": "2025-04-29T22:08:37Z",
          "tree_id": "028eb199fffa09c39d99c4dc1cb00a4280a2d0ba",
          "url": "https://github.com/lambdaclass/ethrex/commit/240886b7de53acfa1b30b6f9ccd8431c9dc5d851"
        },
        "date": 1745968164415,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 177165030633,
            "range": "± 832278543",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "33e34efcf5f339ff1d344b134d8f60e78d16e8c4",
          "message": "refactor(levm): use ethrex account types in LEVM (#2629)\n\n**Motivation**\n\n- Stop using the Account and AccountInfo types defined in LEVM and start\nusing the ones defined in the L1 client.\n- Biggest changes are that AccountInfo no longer has code, so we can't\nuse it with that purpose and also we don't have our struct StorageSlot\nanymore, so we have to keep track of original values somewhere else.\n\n\n**Description**\n\n- Now we use the structs of the L1 client but they are different from\nthe ones that we used so I had to make changes:\n- `get_account_info` is now `get_account` because we also need the code\nof the account and `AccountInfo` has the `code_hash` only. This makes\nchanges on every structure that implements `LevmDatabase` trait.\n- Now that we don't have `StorageSlot` that had the `current_value` and\n`original_value` of a storage slot (`original_value` being the value\npre-tx) I had to make some changes to logic and store those original\nvalues into an auxiliary `HashMap` on `VM`.\n- Added new function `get_original_storage()` for getting the original\nstorage value.\n- Make some tiny changes in SSTORE, mostly organize it better.\n\nStorage changes deep description:\n- Now every time we want to get the `original_value` we will look up in\nthe original values stored in the VM struct. These intends to store the\nstorage values previous to starting the execution of a particular\ntransaction. For efficiency and performance, we only update this new\nfield when actually getting the original value.\n- Let me clarify: At the beginning of the transaction the `CacheDB`\ncould have a lot of accounts with their storage but the\n`VM.storage_original_values`will start empty on every transaction. When\n`SSTORE` opcode is executed and we actually care for the original value\nof a storage slot we will look at `storage_original_values` and it won’t\nfind it (the first time), so then it will see what the value in the\n`CacheDB` is, and if it’s not there it will finally check on the actual\n`Database`. After retrieving the value, it will be added to\n`storage_original_values` , but ONLY the FIRST time. That means that if\nthe value keeps on changing the `original_value` won’t change because\nonce it’s added it’s not modified.\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-29T22:14:01Z",
          "tree_id": "35cd2b17f6fbab85c2cb6fa6bbba7be2897845b3",
          "url": "https://github.com/lambdaclass/ethrex/commit/33e34efcf5f339ff1d344b134d8f60e78d16e8c4"
        },
        "date": 1745969538182,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180356296640,
            "range": "± 762876067",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "6370ccb392a16099bafbeb040ed28293bd4699cf",
          "message": "fix(l1): extend fetch head timeout for hive sync test (#2648)\n\n**Motivation**\nSnap sync hive test has been flaky lately, after running with debug\noutput on the CI the problem seems to be a timeout when fetching the\nlatest block. A [PR](https://github.com/lambdaclass/hive/pull/22) was\nadded to our hive fork to extend this timeout so the test doesn't fail.\nThe timeout for the whole sync process has been left unchanged\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Extends the timeout for fetching the latest block on the sync hive\ntest suite\n* Update Hive ref\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-30T13:27:44Z",
          "tree_id": "f9a1349acabcf56bf4b2d23926d0033601dbf27b",
          "url": "https://github.com/lambdaclass/ethrex/commit/6370ccb392a16099bafbeb040ed28293bd4699cf"
        },
        "date": 1746023348699,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180070126380,
            "range": "± 727239469",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "git@edgl.dev",
            "name": "Edgar",
            "username": "edg-l"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "20437d61973ac9be9e45939312f81754e8c425dc",
          "message": "perf(core): make TrieDb use NodeHash as key (#2517)\n\n**Motivation**\n\nFollowup on #2516 using the fact that NodeHash is Copy to use it as the\nkey for the trie db instead of a Vec\n\n**Description**\n\nChanges the trait TrieDb to use a NodeHash as key instead of a generic\nvec, allowing less expensive clones when passing around keys since\nNodeHash is copy and doesn't do any allocation.",
          "timestamp": "2025-04-30T13:40:51Z",
          "tree_id": "7e0926194380b511b10f9a5ae6ce5917d0fa1df9",
          "url": "https://github.com/lambdaclass/ethrex/commit/20437d61973ac9be9e45939312f81754e8c425dc"
        },
        "date": 1746024738514,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180431429933,
            "range": "± 1283379438",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "6f4ce055fdb6ab8e7fd57e11c047fdfebd3afbef",
          "message": "docs(l2): add quick handsOn on bridging assets between L1 and L2  (#2589)\n\n**Motivation**\n\nThis PR tries to show some basic walkthrough on moving assets between\nthe two chains in the docs\n\n**Description**\n\n* Add an example of how to deposit and how to withdraw funds in L2 and\nL1.\n* Explain the deposit functions from the CommonBridge contract in the L1\n\nCloses #2524\n\n---------\n\nCo-authored-by: Ivan Litteri <67517699+ilitteri@users.noreply.github.com>\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>",
          "timestamp": "2025-04-30T14:05:51Z",
          "tree_id": "fac44e75b2437357cdc85b9ec449d72efd78e07b",
          "url": "https://github.com/lambdaclass/ethrex/commit/6f4ce055fdb6ab8e7fd57e11c047fdfebd3afbef"
        },
        "date": 1746026007524,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180813110848,
            "range": "± 494505008",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7c5ff95e815b60f8e274e097f58fc3c574a0995e",
          "message": "feat(core): allow setting syncmode from `run-hive` Makefile targets (#2597)\n\n**Motivation**\nAllow running hive tests with snap sync using the available Makefile\ntargets and passing the optional SYNCMODE=snap argument\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add `SYNCOMDE` variable to Makefile with default value \"full\"\n* Set `syncmode` ethrex flag on hive Makefile targets according to above\nvariable\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-04-30T14:34:08Z",
          "tree_id": "2a17e532d1176e354d9a687c9d66c413eaf4df91",
          "url": "https://github.com/lambdaclass/ethrex/commit/7c5ff95e815b60f8e274e097f58fc3c574a0995e"
        },
        "date": 1746027386628,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181546202431,
            "range": "± 514808196",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "aa3c41b8da043ff5cd1ad699ce882c41edefc460",
          "message": "docs(l2): clarify config parameters (#2582)\n\n**Motivation**\n\nThis pull request updates the `crates/l2/docs/sequencer.md`\ndocumentation to improve clarity and provide more detailed descriptions\nof configuration parameters.\n\n**Description**\n\n* Renamed \"Prover Server\" to \"Proof Coordinator\".\n* Expanded descriptions of configuration parameters under `[deployer]`,\n`[watcher]`, `[proposer]`, and `[committer]` sections.\n\nCloses #2525\n\n---------\n\nCo-authored-by: Ivan Litteri <67517699+ilitteri@users.noreply.github.com>",
          "timestamp": "2025-04-30T15:03:29Z",
          "tree_id": "51715d4610ff7e85a825ccbfb67783cc65d38879",
          "url": "https://github.com/lambdaclass/ethrex/commit/aa3c41b8da043ff5cd1ad699ce882c41edefc460"
        },
        "date": 1746029008493,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179526474703,
            "range": "± 479733581",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "30327624+mechanix97@users.noreply.github.com",
            "name": "Mechardo",
            "username": "mechanix97"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "084204cefafef055a22c6a2f049cad0fe8f2b3d2",
          "message": "feat(l1): properly format client version (#2564)\n\n**Motivation**\n\nThe client version was hardcoded in the rpc crate\n\nIt was used in the client RPC msg, in the admin_info RPC msg and in the\nhelloMsg in P2P\n\n**Description**\n\nAdded vergen crate to include more environment variables at build time\nin the ethrex main package.\n\nIt can be tested using the following cast commands\n```shell\n cast client --rpc-url localhost:8545\n cast rpc admin_nodeInfo --rpc-url http://localhost:8545\n```\n\nModified the `P2PContext` struct to include the client_info\nAlso added it in the struct `RLPxConnection` to pass it to the\nhelloMessage struct when doing the handshake\n\nModified the test to use the functions with a dummy client_info\n\nThe version can now be retrieved by using ethrex --version\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2548",
          "timestamp": "2025-04-30T22:07:02Z",
          "tree_id": "6d22c7c9ad3dc884dc3cc1f879310ad381811bcf",
          "url": "https://github.com/lambdaclass/ethrex/commit/084204cefafef055a22c6a2f049cad0fe8f2b3d2"
        },
        "date": 1746054363470,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178408173083,
            "range": "± 969233794",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "bb8ceced97ae73df71ee4e8574676e18a3d6fda9",
          "message": "refactor(levm,l2): hooks (#2508)\n\n**Motivation**\n\n- Remove duplicated code between `DefaultHook` and `L2Hook`\nimplementations.\n- Use the `L2Hook` for every tx (regular ETH txs and L2's privilege txs)\nwhen running the L2.\n\n**Description**\n\nThis PR:\n- Generates abstractions to be used in `DefaultHook` and `L2Hook` to\nremove repeated code.\n- Adds the `is_privilege` field to LEVM's `Environment` only compiled\nunder the `l2` feature flag.\n- `L2Hook` now supports executing every tx (before only privileged).\n\n---------\n\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>",
          "timestamp": "2025-04-30T22:07:19Z",
          "tree_id": "01a65027b768009340536e6ddfa8adadb7dd7449",
          "url": "https://github.com/lambdaclass/ethrex/commit/bb8ceced97ae73df71ee4e8574676e18a3d6fda9"
        },
        "date": 1746055682531,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181502123198,
            "range": "± 7469040500",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "3f006c1aaa0e3aded73fdfb69d08361a11699554",
          "message": "chore(l2): bump sp1 version to 4.1.7 (#2610)\n\nAlso update some docs\n\n---------\n\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>",
          "timestamp": "2025-05-05T15:02:57Z",
          "tree_id": "3c5eddbd6ad70766696d5e4a7cdc1d64d8b12409",
          "url": "https://github.com/lambdaclass/ethrex/commit/3f006c1aaa0e3aded73fdfb69d08361a11699554"
        },
        "date": 1746461024491,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 177577802410,
            "range": "± 451229834",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "72628438+avilagaston9@users.noreply.github.com",
            "name": "Avila Gastón",
            "username": "avilagaston9"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b817a9a73511343006a60c37e4be464a5452a4a5",
          "message": "fix(l2): ignore deposits after state reconstruction (#2642)\n\n**Motivation**\n\nCurrently, If we start our l2 node with a reconstructed state, the node\nwill process all deposit logs from l1 and mint them again in l2. This is\nbecause, in a reconstructed store, we don't have the included\ntransactions to determine whether a deposit was previously processed or\nnot.\n\n**Description**\n\n- Fixes the reconstruct algorithm to start from batch_number=1.\n- Fixes the `l2MintTxHash` emitted in the `CommonBridge` contract.\n- Adds an additional check to the `integration_test` to wait for the\ndeposit receipt on L2.\n- Reuses the emitted `l2MintTxHash` instead of recalculating it in the\nwatcher.\n- Checks, in the `CommonBridge` contract, whether a deposit is pending\nor not before minting the transaction.\n- Creates `DepositData` struct in `l1_watcher`\n\n### How to test\n\nHere we are going to run the integration test on a node with a\nreconstructed state.\nYou may want to lower the `commit_time_ms`.\n\n1. Start the prover and network  with:\n\n```\nmake init-prover\nmake init\n```\n\n2. Wait until batch 6 is verified and stop the l2 node with `ctrl + c`:\n\n```\nINFO ethrex_l2::sequencer::l1_proof_sender: Sent proof for batch 6...\nctrl + c\n```\n\n\n> [!NOTE]\n> This is because we are going to use already created blobs with 6\nbatches and we need\n> to advance the L1 until that point.\n\n\n3. Clean db:\n\n```\nmake rm-db-l2\n```\n\n4. Reconstruct the state choosing a `path_to_store`:\n```\ncargo run --release --manifest-path ../../cmd/ethrex_l2/Cargo.toml --bin ethrex_l2 -- stack reconstruct -g ../../test_data/genesis-l2.json -b ../../test_data/blobs/ -s path_to_store -c 0x0007a881CD95B1484fca47615B64803dad620C8d\n```\n\n5. Start the l2 node using `path_to_store`:\n\n```\nmake init-l2 ethrex_L2_DEV_LIBMDBX=path_to_store\n```\n\nYou should observe that all deposits are skipped now.\n\n6. In a new terminal, run the integration test:\n\n```\ncd crates/l2\nmake test\n```\n\n> [!WARNING]\n> Before running the integration test, wait for 20 blocks to be built in\nthe L2.\n> This is because the test currently uses\n[estimate_gas_tip](https://github.com/lambdaclass/ethrex/blob/aa3c41b8da043ff5cd1ad699ce882c41edefc460/crates/networking/rpc/eth/fee_calculator.rs#L30)\nthat needs at least 20 blocks to estimate the gas price.\n\nCloses #1279",
          "timestamp": "2025-05-05T15:45:26Z",
          "tree_id": "ed439d0b62fa3fc2631f7429301389feee87ae52",
          "url": "https://github.com/lambdaclass/ethrex/commit/b817a9a73511343006a60c37e4be464a5452a4a5"
        },
        "date": 1746463638421,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179227682735,
            "range": "± 584334148",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "6ed8a1fcbe483165e0ad70c18edd4dcb427c8e91",
          "message": "docs(levm): add forks docs (#2644)\n\n**Description**\n- Add docs about forks explaining why we don't want to support pre-Merge\nforks.\n- Change EFTests so they run by default for the forks we are interested\nin.",
          "timestamp": "2025-05-06T11:11:25Z",
          "tree_id": "cddb636d0fa85bfd1b623c5d90809269519a5e5c",
          "url": "https://github.com/lambdaclass/ethrex/commit/6ed8a1fcbe483165e0ad70c18edd4dcb427c8e91"
        },
        "date": 1746533459377,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 177292028864,
            "range": "± 493906369",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a44f435ba097fbfefb43080c8e7fac4f10e05143",
          "message": "fix(levm): propagate database errors (#2639)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n- We were just propagating Internal errors but we also want to propagate\nDatabaseErrors. Before this we were just reverting the transaction and\nthat is wrong.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-06T11:11:36Z",
          "tree_id": "89dd354e3781b03f422c5b2ccc9ec511d8e30f6d",
          "url": "https://github.com/lambdaclass/ethrex/commit/a44f435ba097fbfefb43080c8e7fac4f10e05143"
        },
        "date": 1746534717026,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180250911049,
            "range": "± 1006527421",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e920898c576371ff09ca1b610d08a8a2ccfacd97",
          "message": "feat(docs): latest valid ancestor store methods (#2669)\n\n**Motivation**\nThe `Store` methods `set_latest_valid_ancestor` &\n`get_latest_valid_ancestor` can be confusing without proper\ndocumentation. These methods were properly documented on the\n`StoreEngine` trait, but they were not documented in the `Store`\nstructure where they will be most often called from. This PR adds\ndocumentation for these methods on the `Store` implementation while also\nsimplifying it, as the internal trait documentation provides more\ninformation on the context and design choices/requirements for the\nimplementation which are not necessary for the top-level methods.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add doc comments for `Store` methods `set_latest_valid_ancestor` &\n`get_latest_valid_ancestor`\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses None",
          "timestamp": "2025-05-06T13:33:18Z",
          "tree_id": "8275632b0c4590b77810dc8f928e473c5cbf7df1",
          "url": "https://github.com/lambdaclass/ethrex/commit/e920898c576371ff09ca1b610d08a8a2ccfacd97"
        },
        "date": 1746542100401,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182626211524,
            "range": "± 1258129811",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e08e959f43215e90a71f8642b275c8c9ddb2e490",
          "message": "refactor(levm): improve and simplify some db functions (#2651)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n- Try to remove `account_exists` if possible because it adds complexity\nand unnecessary checks to the DB.\n- Try to finally remove `get_account_no_push_cache`, which is related to\nthe previous thing too.\n\n**Description**\n\n- We now ignore a specific test because [EIP-7702 spec has\nchanged](https://github.com/ethereum/EIPs/pull/9710) and we no longer\nneed to check if the account exists in the trie.\n- Remove `Option` from `specific_tests`\n- Remove `get_account_no_push_cache` and the usage of `account_exists`\nin LEVM. This method is not deleted from the Database because it's used\nin `get_state_transitions`, and even here it could be removed but I\nthink it is better to keep it in this PR and maybe decide later what to\ndo with this function. (If we remove it it wouldn't make a difference to\nthe state though).\n- We were able to remove a SpuriousDragon check because we don't support\npre-merge forks now\n\n\nNote: `account_exists` hasn't been completely removed from `Database`\nbecause we use it in `get_state_transitions` but that is going to change\nsoon and we'll be able to remove it.\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-06T15:06:27Z",
          "tree_id": "df88f4a1dd9a86e832f5d5b6bef88450f059e3c7",
          "url": "https://github.com/lambdaclass/ethrex/commit/e08e959f43215e90a71f8642b275c8c9ddb2e490"
        },
        "date": 1746547825082,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 190818320644,
            "range": "± 3574101557",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "8e9c3c57b92ea7c48b0314676a5949532ec12ac3",
          "message": "feat(levm): replace ambiguous error with proper validation error when obtaining effective gas price (#2667)\n\n**Motivation**\nWhile implementing a mapper for our ethrex & levm error types for the\nconsume-engine hive test I ran into a test that was returning the error\n`Invalid Transaction: Invalid Transaction` which doesn't look useful at\nall. The error comes up when we fail to compute the effective gas for a\ntransaction (aka the block's base_fee is higher than the transaction's\nmax fee), so I replaced it with the appropriate error\n(TxValidationError::InsufficientMaxFeePerGas) which is also the one\nexpected by the test suite.\n\n**Description**\n* Replace ambiguous error used when calculating effective gas price\nbefore tx execution with proper validation error.\n\nCloses: None, but is needed to cleanly implement the error mapper needed\nfor #2474",
          "timestamp": "2025-05-06T15:25:40Z",
          "tree_id": "afe82607b68d6abb20a3781f37d1a9d7867e961f",
          "url": "https://github.com/lambdaclass/ethrex/commit/8e9c3c57b92ea7c48b0314676a5949532ec12ac3"
        },
        "date": 1746548979556,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178323401477,
            "range": "± 409654033",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c34b58cbe24874b69511ec1ab801ad58132f668a",
          "message": "fix(l2): sigint to kill prover in integration test (#2680)\n\n**Motivation**\n\nSP1 deploys a container for GPU proving. If the prover is killed with\n`SIGTERM`, the program does not remove the container and a next run may\nget stuck. If the prover is killed with `SIGINT`, then the container\ngets deleted.",
          "timestamp": "2025-05-06T18:04:37Z",
          "tree_id": "8cfc042a7a54fcc7462dae1e2f2ee38655a0605a",
          "url": "https://github.com/lambdaclass/ethrex/commit/c34b58cbe24874b69511ec1ab801ad58132f668a"
        },
        "date": 1746558334165,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180480458002,
            "range": "± 1085212936",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c4e0b92abfd4a02f3c96cf62950d4b876ab3dae2",
          "message": "feat(levm): add error messages for levm validation errors (#2678)\n\n**Motivation**\nSome levm validation errors use the enum variant's name as display\nmessage instead of displaying a proper error message.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add error messages for some levm validation errors\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-06T19:16:24Z",
          "tree_id": "a70c482f85b5a5849cd9da3e1d69c9d4abd1cb4e",
          "url": "https://github.com/lambdaclass/ethrex/commit/c4e0b92abfd4a02f3c96cf62950d4b876ab3dae2"
        },
        "date": 1746562670499,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182010271770,
            "range": "± 1370093449",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5cc86fbe70930ccec17e0e02caae7094936a3245",
          "message": "fix(l1): prevent amplification attack on `FindNode` request (#2693)\n\n**Motivation**\nSome hive devp2p tests have been failing as of lately. Particularly the\n`discv4/Amplification/WrongIP` test. Upon further investigation it looks\nlike the test was previously passing but not for the right reasons. The\ntest consists of sending Ping and Pong messages to the node from a given\nIP and then sending a `FindNode` request from the same node id but a\ndifferent IP. The test fails if the node replies with a `Neighbours`\nmessage instead of noticing the IP mismatch that could represent an\namplification attack.\nOur test used to pass, but not due to the node catching the potential\nattack but due to a failure to deliver the neighbors message. On both\nfailing and non-failing attempts the node constructs the neighbors\nmessage and attempts to send it which is not the correct behaviour.\n\nThis PR fixes this problem by checking that the IP from which we\nreceived the `FindNode` request matches the ip we stored when validating\nthe node (via ping pong messages) as to prevent amplification attacks.\nIt also adds some doc about the potential attack (taken from geth\nimplementation)\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Check that the IP from which we receive a FindNode message matches the\nIP of the node\n* Add doc about potential amplification attacks on FindNode requests\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-08T09:59:02Z",
          "tree_id": "dc2eb167f73cf784219a246280bfa1defb9298cb",
          "url": "https://github.com/lambdaclass/ethrex/commit/5cc86fbe70930ccec17e0e02caae7094936a3245"
        },
        "date": 1746701020974,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180687207565,
            "range": "± 818675359",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "7da4c07f42320f4cf91adbf611044226fadf816e",
          "message": "fix(l2): download solc fixed version in Dockerfile (#2700)\n\n**Motivation**\n\nA new version of solidity was released a few hours ago\n([`0.8.30`](https://github.com/ethereum/solidity/releases/latest)) and\nthe Dockerfile was written to always download the latest version while\nour contracts Solidity version is fixed to `0.8.29`.\n\n**Description**\n\nUpdates the L1 contract deployer Dockerfile to download a fixed version\nof solc.",
          "timestamp": "2025-05-08T12:39:01Z",
          "tree_id": "ae33dbed81d3a6661b8033bb15e5e6135b0e7349",
          "url": "https://github.com/lambdaclass/ethrex/commit/7da4c07f42320f4cf91adbf611044226fadf816e"
        },
        "date": 1746710788221,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178973456783,
            "range": "± 700514412",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "francisco.gauna@lambdaclass.com",
            "name": "fedacking",
            "username": "fedacking"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "83158ad356fb739f19a2d8b15864656d9f700462",
          "message": "fix(l1): fixed proper parent when receiveing a NewPayloadRequest (#2690)\n\n**Motivation**\n\nThis pr aims to fix a bug with the parent assigned in NewPayloadRequest\nif the parent is valid. From the [Paris fork\ndocumentation](https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md)\n\"latestValidHash: DATA|null, 32 Bytes - the hash of the most recent\nvalid block in the branch defined by payload and its ancestors\"\n\n**Description**\n\nRemoved storage get for the canonical latest valid ancestor and replaced\nwith the parent hash (if it's valid).\n\nFixes 27 tests in #1285 in \"engine-cancun\"",
          "timestamp": "2025-05-08T13:18:54Z",
          "tree_id": "823afb0e12762ec7aa6b0cff9111711c90bf175a",
          "url": "https://github.com/lambdaclass/ethrex/commit/83158ad356fb739f19a2d8b15864656d9f700462"
        },
        "date": 1746713183749,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179086421038,
            "range": "± 465546481",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "352e5b619150a2ced54e9e37a6b487d5d41e97bc",
          "message": "fix(l1): gate blob tests behind `c-kzg` feature (#2686)\n\n**Motivation**\nCurrently, attempting to run any test on the common crate fails unless\nwe explicitly add `--features c-kzg` due to the tests on the\nblobs_bundle module using code gated behind `c-kzg` feature. This PR\nsolves this issue by feature-gating tests that use these feature-gated\ncode.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add `c-kzg` feature gate to tests on blobs_bundle module\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-08T13:35:59Z",
          "tree_id": "249ffb820c5a9dd15a8a5031833084a64d17efab",
          "url": "https://github.com/lambdaclass/ethrex/commit/352e5b619150a2ced54e9e37a6b487d5d41e97bc"
        },
        "date": 1746715262105,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182168081852,
            "range": "± 774191331",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "b0f348f19a3750b6ddb635a739aff2e89d78c0ae",
          "message": "fix(l1): catch potential panic when decoding `NodeHash` (#2683)\n\n**Motivation**\nThe method `NodeHash::from_slice` can panic if the slice is over 32\nbytes. This could cause panics when decoding nodes as it is used without\nchecking the length beforehand. This PR adds a check and returns an\ninvalid length error before calling `from_slice`. It also mentions the\npotential panic on the method's documentation & removes a misleading\n`From<Vec<u8>>` implementation that would also panic under the same\ncondition.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Remove `From<Vec<u8>> for NodeHash` impl as it could cause panics\n* Mention potential panic on `NodeHash::from_slice` doc\n* Check rlp decoded data len to avoid panics when decoding `NodeHash`\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2649",
          "timestamp": "2025-05-08T13:36:38Z",
          "tree_id": "6d135aec2c67e53e040f38085d273cd0ab325b33",
          "url": "https://github.com/lambdaclass/ethrex/commit/b0f348f19a3750b6ddb635a739aff2e89d78c0ae"
        },
        "date": 1746716463526,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178510514975,
            "range": "± 735084580",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "90105443+DiegoCivi@users.noreply.github.com",
            "name": "DiegoC",
            "username": "DiegoCivi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "6f959f5d1457438815278c5f62e60cf25cd5097d",
          "message": "chore(l1): fix contract deployment tests from EIP-7002 (#2630)\n\n**Motivation**\n\nOn #2586 new tests were added and some of them failed on LEVM and REVM.\n\n**Description**\n\n8 new tests are now working and dont need to be skipped in each of the\nVMs. The tests were failing because we were not checking if the bytecode\nof the system contracts that the EIPs\n([7002](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7002.md#empty-code-failure)\nand\n[7251](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7251.md))\ndefine were empty or not. And also because the we were not handling the\ncase were the system calls revert, leading to an invalidate block.\n\nCloses #2598\n\n---------\n\nCo-authored-by: Jeremías Salomón <48994069+JereSalo@users.noreply.github.com>",
          "timestamp": "2025-05-08T17:09:51Z",
          "tree_id": "5c590710f96e22fecdf164f87a712b476cecc6dd",
          "url": "https://github.com/lambdaclass/ethrex/commit/6f959f5d1457438815278c5f62e60cf25cd5097d"
        },
        "date": 1746727743600,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179316441520,
            "range": "± 927628046",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "af8f6ec944b4b09ed03a0b8369d4c756c1f68781",
          "message": "refactor(l2): rewrite integration tests (#2681)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nL2 tests were broken since two tests were waiting for funds in L2\nwithout depositing.\n\n**Description**\n\n- Adds `test_deposit`, `test_transfer`, `test_withdraw`, `test_deploy`,\n`test_call_with_deposit` functions that are used by all the tests.\n- The deposits and transfers are now done from an L1 rich wallet to a\nrandom L2 wallet.\n- Adds `L1ToL2TransactionData` struct to the SDK. This struct contains\nthe current L2 data for privileged transactions.\n- Adds `send_l1_to_l2_transaction` function to the SDK.\n- Adds `deposit_through_contract_call` function to the SDK (wrapper over\nthe above).\n\n---------\n\nCo-authored-by: ilitteri <ilitteri@fi.uba.ar>",
          "timestamp": "2025-05-08T17:11:42Z",
          "tree_id": "7d29f719ad8c8db99ff4a265a5c19689db7081f7",
          "url": "https://github.com/lambdaclass/ethrex/commit/af8f6ec944b4b09ed03a0b8369d4c756c1f68781"
        },
        "date": 1746729086130,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179334957227,
            "range": "± 898033091",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "30327624+mechanix97@users.noreply.github.com",
            "name": "Mechardo",
            "username": "mechanix97"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "435107be79d0df4d2ece43b77a359b70ed26ba8f",
          "message": "docs(p2p): Update network docs (#2613)\n\n**Motivation**\n\nThe network example was outdated and it was not working\n\n**Description**\n\nModified the commands to use diferents datadirs in order to generate\ndistincts node_id\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2608\n\n---------\n\nCo-authored-by: Tomás Paradelo <112426153+tomip01@users.noreply.github.com>\nCo-authored-by: Martin Paulucci <martin.c.paulucci@gmail.com>",
          "timestamp": "2025-05-08T18:20:11Z",
          "tree_id": "aa63b51ed79f162cc772050e46a538257851fb12",
          "url": "https://github.com/lambdaclass/ethrex/commit/435107be79d0df4d2ece43b77a359b70ed26ba8f"
        },
        "date": 1746731935721,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179470806469,
            "range": "± 803373101",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "ef8fdb5a119835d72098cc934c337a627b728afa",
          "message": "refactor(levm): improve error message in nonce mismatch (#2698)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n- When running load tests I realized that when there's a nonce mismatch\nwe should give more detail so that the user takes that into account.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-08T18:29:19Z",
          "tree_id": "316b19cedd367fe600943f37e77499299592eaef",
          "url": "https://github.com/lambdaclass/ethrex/commit/ef8fdb5a119835d72098cc934c337a627b728afa"
        },
        "date": 1746733187504,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180222750263,
            "range": "± 848434366",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9ace51f37360186a4d4ad31a7ab32865071e2fe7",
          "message": "perf(levm): remove unnecessary double copying in op_push (#2702)\n\n**Motivation**\n\nRemoves a call to the `bytes_to_word` function (and the function\nitself), as it was unnecessary and implied copying the same slice twice.\n\nI noticed while syncing in Holesky that (somewhat expectedly) a lot of\ntime was spent on `op_push`, and while looking deeper realized that\nthere was unnecessary work being done.\n\nFlamegraph on `op_push` on main:\n<img width=\"1504\" alt=\"Screenshot 2025-05-08 at 11 32 37\"\nsrc=\"https://github.com/user-attachments/assets/e990fa05-9a7b-4ba5-8a5b-7b177eeb25d4\"\n/>\n\nFlamegraph on `op_push` on this branch:\n<img width=\"1502\" alt=\"Screenshot 2025-05-08 at 11 33 01\"\nsrc=\"https://github.com/user-attachments/assets/ed0fc3d8-8c6b-4a11-9ca2-16d8f7afd1e1\"\n/>\n\nMy impression is that there's still work to be done on `op_push`\nhowever.\n\nThe bench comparison against `revm` in the comments shows around a ~5-6%\nimprovement.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-08T18:30:25Z",
          "tree_id": "b8c57586a329270b399308ca63bb8de643fb1758",
          "url": "https://github.com/lambdaclass/ethrex/commit/9ace51f37360186a4d4ad31a7ab32865071e2fe7"
        },
        "date": 1746734377217,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178199303457,
            "range": "± 442468797",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "44068466+SDartayet@users.noreply.github.com",
            "name": "SDartayet",
            "username": "SDartayet"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "a5da369f9a220976eb97429dcce0356363025d87",
          "message": "chore(levm, l1, l2): remove code specific to unsupported forks (#2670)\n\n**Motivation**\n\nKeep the codebase clean and as simple as possible by removing code we\ndon't really need.\n\n**Description**\n\nAll the code that was only relevant to forks prior to Paris was removed.\nThis includes constants, ifs, etc.\n\nResolves issue\n[#2659](https://github.com/lambdaclass/ethrex/issues/2659)\n\n---------\n\nCo-authored-by: JereSalo <jeresalo17@gmail.com>",
          "timestamp": "2025-05-08T19:37:09Z",
          "tree_id": "d64e0a4b1b685f34041dd134fe25f1a797ad715a",
          "url": "https://github.com/lambdaclass/ethrex/commit/a5da369f9a220976eb97429dcce0356363025d87"
        },
        "date": 1746737049371,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178106134794,
            "range": "± 500236814",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b6a13200d8af5a770cf3effe3a638eff2656fc27",
          "message": "perf(levm): optimize how levm tracks storage modifications in case of reverts (#2699)\n\n**Motivation**\n\nThis PR replaces the way we track storage modifications to contracts\nwhen executing to handle reverts. Previously, when writing to an account\nwe were cloning its entire accumulated modified state, so in case we\nneeded to revert we could overwrite it back to its former values. These\nwere the lines of code:\n\n```\n        let previous_account = cache::insert_account(&mut self.db.cache, address, account);\n\n        if let Ok(frame) = self.current_call_frame_mut() {\n            frame\n                .cache_backup\n                .entry(address)\n                .or_insert_with(|| previous_account.as_ref().map(|account| (*account).clone()));\n        }\n```\n\nWith the changes here, we now track the individual storage slots that\nare modified when executing and avoid cloning the entire modified\nstorage. This was done by replacing the `CacheBackup` with a\n`CallFrameBackup` that keeps separate track of account infos and storage\nslots.\n\nThe performance benefits are noticeable mostly in very large load tests,\nwith block gas limits around 1 Gigagas and beyond. At that point the\nload test gets around 2x faster compared to main (80 seconds down from\n160s for the load test to finish, gigagas/s goes from ~0.11 to ~0.2).\n\nThis is also noticeable within flamegraphs of these load tests, as in\n`main` currently there's a huge portion of it devoted to `sstore` that\ndisappears.\n\nMain:\n\n<img width=\"1505\" alt=\"Screenshot 2025-05-08 at 11 20 53\"\nsrc=\"https://github.com/user-attachments/assets/5d7f6dbd-d4eb-42e3-bec3-b81632ec9409\"\n/>\n\nThis branch:\n\n<img width=\"1503\" alt=\"Screenshot 2025-05-08 at 11 22 03\"\nsrc=\"https://github.com/user-attachments/assets/b6e83203-f31c-46fc-8434-998e585cabbf\"\n/>\n\nWhile most instances of deployed ethrex will probably not feature such\nlarge gas limits on blocks, this change should improve syncing times, as\nthere we execute batches of 1024 blocks at a time, which is functionally\nequivalent to executing one very large block when it comes to the\nbehaviour of this code. Trying out the changes while syncing in Holesky,\nI noticed an improvement of around the magnitude above (~2x), though of\ncourse it is highly variable and dependent on which blocks get executed.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number\n\n---------\n\nCo-authored-by: Jeremías Salomón <48994069+JereSalo@users.noreply.github.com>",
          "timestamp": "2025-05-08T21:11:24Z",
          "tree_id": "7643b56642777111418fe72272a043a1306dd262",
          "url": "https://github.com/lambdaclass/ethrex/commit/b6a13200d8af5a770cf3effe3a638eff2656fc27"
        },
        "date": 1746742289654,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179287175011,
            "range": "± 871818788",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a4da254c641aa58eeb36c9c6946239e48cb28389",
          "message": "docs(levm): add some docs and delete unnecessary stuff (#2716)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n- Clean the VM and document it where necessary.\n\n**Description**\n\n- Add simple rustdocs comments where I consider appropriate adding and\nexplain some things that were left unexplained before.\n- Delete `operations.rs` because we weren't using it.\n- Left some TODOs in the comment, for which I created issues:\n  - https://github.com/lambdaclass/ethrex/issues/2717\n  - https://github.com/lambdaclass/ethrex/issues/2718\n  - https://github.com/lambdaclass/ethrex/issues/2720\n\n\n\nCloses #2546",
          "timestamp": "2025-05-08T22:39:24Z",
          "tree_id": "d9302debea63d07df8623841f7aeb491db693710",
          "url": "https://github.com/lambdaclass/ethrex/commit/a4da254c641aa58eeb36c9c6946239e48cb28389"
        },
        "date": 1746747580269,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179811306650,
            "range": "± 634115932",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "44068466+SDartayet@users.noreply.github.com",
            "name": "SDartayet",
            "username": "SDartayet"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "f43bd77b86c5654ce2e7fd91c6fe73fc9c534dcb",
          "message": "chore(levm): minor fixes and refactors to previous PR (#2721)\n\n**Motivation**\n\nFixing some comments left in a previous PR.\n\n**Description**\n\nJust opened this PR since some of the changes requested were out of\nscope. Simply swapped some variables for constants in places where the\nvariables simply held the value of said constants, and applied a minor\nchange to an unwrap in the execution handlers.\n\nCloses #2719",
          "timestamp": "2025-05-09T14:52:46Z",
          "tree_id": "513cfa0586799fbb392de635ef8ac10235b260ea",
          "url": "https://github.com/lambdaclass/ethrex/commit/f43bd77b86c5654ce2e7fd91c6fe73fc9c534dcb"
        },
        "date": 1746806098424,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178688822819,
            "range": "± 640389179",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "688e1d6c70c614879c1c063eac9694dc51249c07",
          "message": "fix(core): fix redb not working due to missing table (#2650)\n\n**Motivation**\n\nThe redb code was missing the `InvalidAncestors` table\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-09T16:14:04Z",
          "tree_id": "30ee848ad871b57cc6ac2e4462b61e4d8be1c2a4",
          "url": "https://github.com/lambdaclass/ethrex/commit/688e1d6c70c614879c1c063eac9694dc51249c07"
        },
        "date": 1746810899414,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178119940301,
            "range": "± 438193991",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "francisco.gauna@lambdaclass.com",
            "name": "fedacking",
            "username": "fedacking"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "08c6ba25e75f94775fdb15ab4a8db148333c1dcc",
          "message": "ci(l1): bypassed flaky test, returned comment saying it's flaky (#2736)\n\n**Motivation**\n\nThis removes the flaky tests indicated in #2565 who were added before\nonly with local testing. The issue happens only in\n\n**Description**\n\nRemoves the \"Invalid Missing Ancestor Syncing ReOrg\" tests, while\nkeeping the \"Invalid Missing Ancestor ReOrg\" tests that were fixed and\nadded in #2690. Readded the comment saying is flaky, and expanded by\nsaying it happens only in CI.",
          "timestamp": "2025-05-09T20:33:05Z",
          "tree_id": "9cf0e661ab48069e0223b10b03a526a20c1f9c2c",
          "url": "https://github.com/lambdaclass/ethrex/commit/08c6ba25e75f94775fdb15ab4a8db148333c1dcc"
        },
        "date": 1746826404840,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 182562294054,
            "range": "± 717984892",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "938db195e8a49bd208ab48bb30978ead9e3ed2b2",
          "message": "refactor(l2): replace sequencer config toml with CLI flags (#2606)\n\n**Motivation**\n\n- https://github.com/lambdaclass/ethrex/issues/2380\n- https://github.com/lambdaclass/ethrex/issues/2574\n- https://github.com/lambdaclass/ethrex/issues/2609\n\n**Description**\n\n- Adds CLI options for the sequencer components\n- Extends `ethrex l2 init` options with `SequencerOptions` (a struct\nthat contains all the different components' options)\n- Refactors `cmd/ethrex/l2.rs`\n    - Moved the command code to `cmd/ethrex/l2/command.rs`.\n    - Moved the command options to `cmd/ethrex/l2/options.rs`.\n- Leaves the minimum necessary config in the\n`sequencer_config_example.toml` (needed by the deployer).\n- Leaves the minimum necessary logic in the\n`crates/l2/utils/configs/toml_parser.rs` module (needed by the deployer\nand prover).\n- Adds CLI options for the contract deployer bin and the system\ncontracts updater bin (removing the need of a config file).\n- Updates the L2 Makefile.\n- Updates the Docker Compose files.\n- Updates the `pr-main_l2` workflow.\n- Updates the L2 integration test.\n- Removes the `sequencer_config_example.toml` since it is not needed\nanymore.\n- Refactors the `crates/l2/contracts` module\n- Renames the crate from `ethrex-l2_deployer` to `ethrex-l2_contracts`.\n- Adds a `bin` module with the bins `ethrex_l2_l1_deployer` and\n`ethrex_l2_system_contracts_updater`.\n    - All the SDK-related logic was moved to the SDK lib.\n- Cleans up the logic related to the config and toml parsing since now\nthe only bin relying on the config is the Prover. Everything relative to\nthe sequencer was removed, and now it is \"hardcoded\" for the Prover.\n\n**How to test**\n\nIf you are in a dev environment, keep working as usual because under the\nhood, the sequencer initialization is not relying anymore on the\n`sequencer_config.toml`.\n\nIf you are in a prod environment, run `cargo run --release --features l2\n-- l2 init --help` at the root of the repository to explore the\ndifferent configuration flags this PR adds.\n\n**Caveats**\n\nThe prover config file is still needed by the prover (tracked in\nhttps://github.com/lambdaclass/ethrex/issues/2576).\n\nCloses #2574\n\n---------\n\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>\nCo-authored-by: Manuel Iñaki Bilbao <manuel.bilbao@lambdaclass.com>",
          "timestamp": "2025-05-10T13:10:11Z",
          "tree_id": "4c99a1cc733d2700b4e256ab7fa91053bfc8fd23",
          "url": "https://github.com/lambdaclass/ethrex/commit/938db195e8a49bd208ab48bb30978ead9e3ed2b2"
        },
        "date": 1746886170512,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 180007591893,
            "range": "± 632552860",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "49fd5c7b2fd195d8e80b96eb9f1e0495ade77cb2",
          "message": "refactor(core): cleanup import blocks bench code (#2631)\n\n**Description**\n- Moved import blocks benchmark from the top folder to /cmd/ethrex\n- Updated evm in benchmark to use the default one\n- Renamed generic `criterion_benchmark` to `import_block_benchmark`\n- Renamed confusing `genesis-l2-ci.json` to `genesis-perf-ci.json` since\nit's not really related to l2.\n- Removed deprecated flamegraph script\n\n---------\n\nCo-authored-by: Javier Chatruc <jrchatruc@gmail.com>",
          "timestamp": "2025-05-12T10:15:38Z",
          "tree_id": "e638530518a4f09b16687da111fb1a034f54765f",
          "url": "https://github.com/lambdaclass/ethrex/commit/49fd5c7b2fd195d8e80b96eb9f1e0495ade77cb2"
        },
        "date": 1747047763854,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 177054188943,
            "range": "± 639538719",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "7841ac97a2835b690fa969936ba1a1d0646f34d9",
          "message": "fix(l2): `make deploy-l1` (#2740)\n\n**Motivation**\n\n- `--deposit-rich` flag is missing in `make deploy-l1`.\n- `--private-keys-file-path` path is wrong in `make deploy-l1`.\n- `--genesis-l1-path` path is wrong in `make deploy-l1`.",
          "timestamp": "2025-05-12T14:26:16Z",
          "tree_id": "b53752c50ba1bad6d8e8fe34362b7e67cc08d288",
          "url": "https://github.com/lambdaclass/ethrex/commit/7841ac97a2835b690fa969936ba1a1d0646f34d9"
        },
        "date": 1747063410355,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 183775110439,
            "range": "± 1826527448",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67517699+ilitteri@users.noreply.github.com",
            "name": "Ivan Litteri",
            "username": "ilitteri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "4492a243d6fe45b6194d1b83e1c399f6419059de",
          "message": "ci(l2): patch `main_prover` workflow (#2741)\n\n**Motivation**\n\nThere's a bug in our GPU runner where sometimes a `.env` directory is\ncreated, which causes the workflow to fail in different steps.\n\nThis only happens in our GPU runner. I filed an issue to tackle this\nhttps://github.com/lambdaclass/ethrex/pull/2741.\n\n**Description**\n\nRemoves the `.env` dir if it exists.",
          "timestamp": "2025-05-12T14:34:36Z",
          "tree_id": "1aa13a4df0acb24f6c6a702910113d1ec3e0b6ea",
          "url": "https://github.com/lambdaclass/ethrex/commit/4492a243d6fe45b6194d1b83e1c399f6419059de"
        },
        "date": 1747064474689,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179421695544,
            "range": "± 1126619344",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9c9fd9257cd3f25be52f41864ba9562427ca66c2",
          "message": "fix(l2): remove fork as parameter in get_state_transitions function (#2723)\n\nIn [this\nPR](https://github.com/lambdaclass/ethrex/commit/a5da369f9a220976eb97429dcce0356363025d87)\nwe forgot to remove fork from some places in which get_state_transitions\nwas being used.\n\nWe should try to find a way to fix rust-analyzer so that it detects\nthose cases but I don't know how hard it is.",
          "timestamp": "2025-05-12T15:57:48Z",
          "tree_id": "72050d6af6a533468e55248afe05ecff462dac53",
          "url": "https://github.com/lambdaclass/ethrex/commit/9c9fd9257cd3f25be52f41864ba9562427ca66c2"
        },
        "date": 1747069144620,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 179086308237,
            "range": "± 803295633",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "90105443+DiegoCivi@users.noreply.github.com",
            "name": "DiegoC",
            "username": "DiegoCivi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "d1003c1451d9fdaddb3f6c97dae992eac034377c",
          "message": "refactor(levm): use more descriptive names when popping call_frame  (#2730)\n\n**Motivation**\n\nGive a better description of call_frame related variables in\nrun_execution().\n\n**Description**\n\n- Use `executed_call_frame` in scenarios in which the callframe has\nalready been executed.\n- Use `parent_call_frame` in scenarios in which a callframe has been\npopped before, to we are working with the previous one.\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2569",
          "timestamp": "2025-05-12T16:20:42Z",
          "tree_id": "6401b1a228e1a3fae6419d4dd35298a607e0f525",
          "url": "https://github.com/lambdaclass/ethrex/commit/d1003c1451d9fdaddb3f6c97dae992eac034377c"
        },
        "date": 1747069696027,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 178607911356,
            "range": "± 1250090379",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "897af4f15412c87f82e434e784e5717a4d3b3b62",
          "message": "feat(l2): bench job (#2663)\n\n**Motivation**\n\nContinously (on each push to main) prove an Ethereum Mainnet block to\ntest and benchmark ethrex-prover.\n\n**Description**\n\n- adds job to prove an L1 block using the `bench` crate\n- post the gas rate (Mgas/s) into gh pages with the github benchmark\naction.",
          "timestamp": "2025-05-12T18:13:42Z",
          "tree_id": "8bc3d7fd4c58439dd35616dbef9894ef3ae7995e",
          "url": "https://github.com/lambdaclass/ethrex/commit/897af4f15412c87f82e434e784e5717a4d3b3b62"
        },
        "date": 1747076517684,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 181842593499,
            "range": "± 911294658",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "18f113b85e5d79c88ef29cf4dc796f87fde33def",
          "message": "fix(l1, l2): make levm default in enum (#2632)\n\n**Motivation**\nJust set the default vm in a single place\n\n**Description**\n- Even though the cli changed to `levm`, we still had `revm` as the\ndefault enum\n\n---------\n\nCo-authored-by: Javier Chatruc <jrchatruc@gmail.com>\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>",
          "timestamp": "2025-05-12T18:28:19Z",
          "tree_id": "7ed875111239d95fc9900ad507c008d67d55a2de",
          "url": "https://github.com/lambdaclass/ethrex/commit/18f113b85e5d79c88ef29cf4dc796f87fde33def"
        },
        "date": 1747079866880,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 216779995269,
            "range": "± 1993440012",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2a6c44c3aee6477c17755b6d5523ba23d7065d1d",
          "message": "feat(l2): config eth client through .toml (#2510)\n\n**Motivation**\n\nHere we want to be able to configure some constant values in our L2.\nThese changes aim to improve flexibility in the L2 and provide better\ncontrol.\n\n**Description**\n\n* Added `elasticity_multiplier` to `BuildPayloadArgs` and passed it to\n`calculate_base_fee_per_gas`.\n* Incorporated `elasticity_multiplier` into `BlockProducer`.\n* Introduced new fields (`max_number_of_retries`, `backoff_factor`,\n`min_retry_delay`, `max_retry_delay`) in `EthClient`.\n\nCloses #2479\n\n---------\n\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>",
          "timestamp": "2025-05-12T21:22:40Z",
          "tree_id": "65e61f12e2ef168d96dc2bc4dde6548ee55bf123",
          "url": "https://github.com/lambdaclass/ethrex/commit/2a6c44c3aee6477c17755b6d5523ba23d7065d1d"
        },
        "date": 1747088794426,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 221423130440,
            "range": "± 542666992",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "b038adc6a2af4a120c2748205088715e32003e79",
          "message": "fix(l2): panic when trying to read gpu info in bench crate (#2755)\n\n**Motivation**\n\nThe ci was failing because a crate `machine-info` was panicking when\ntrying to read gpu info\nsystem-info-lite crate was tried but returns an empty string in linux\nservers with nvidia-gpu so for now the gpu/cpu info was removed and only\nshows if it ran in a gpu or in a cpu\n\n**Description**\n\n- Remove gpu/cpu information from output json\n\nCreated #2756 to re-add this when possible",
          "timestamp": "2025-05-12T21:42:52Z",
          "tree_id": "f305c2d5311785ed2933f26d7de6f4ddc094cdeb",
          "url": "https://github.com/lambdaclass/ethrex/commit/b038adc6a2af4a120c2748205088715e32003e79"
        },
        "date": 1747089985847,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 217621497335,
            "range": "± 826858822",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "1dd145092a00b26da441f50f76a200243e9c3f81",
          "message": "fix(core): add tokio as dev-dependency for ethrex-storage (#2747)\n\n**Motivation**\nWhen running the tests for the ethrex-storage package (via cargo t\n--package `ethrex-storage`) due to `tokio` being used by the test module\nbut not being declared as a dependency. This PR fixes this issue by\nadding it as a dev-dependency.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* add `tokio` as dev-dependency for `ethrex-storage` crate\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses None, but fixes developer experience",
          "timestamp": "2025-05-13T10:48:22Z",
          "tree_id": "6c53d581e009ea34c27672dbc4bf56da7a5686f6",
          "url": "https://github.com/lambdaclass/ethrex/commit/1dd145092a00b26da441f50f76a200243e9c3f81"
        },
        "date": 1747144239048,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 217113916878,
            "range": "± 553393828",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "175ce2691ba329e247918c4eef505f6e241b25cc",
          "message": "fix(core): warnings when compiling crates separately (#2749)\n\n**Motivation**\nSeveral warnings pop up when trying to test or build ethrex crates\nseparately. Most of them are due to code that is only used under\nfeature-gated code not being imported of defined under the respective\nfeature. While these warnings don't prevent compilation and don't pop up\nwhen building the full project, they can still be annoying during\nspecific dev cycles (such as adding or running a crate's unit tests) and\ncan be easily removed by using the correct feature flags\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Use an underscore for the path when creating a Store, as the path\nvariable is only used under the libmdbx feature\n* Fix an import only being used under featured code not being in a\nfeature-gated import statement\n* Only compile `storage::rlp` module under `libmdbx` & `redb` features,\nas we don't use it on the in-memory version\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-13T13:01:48Z",
          "tree_id": "f0b35b5df10b032f7ab9919ef8bf4ad974aab034",
          "url": "https://github.com/lambdaclass/ethrex/commit/175ce2691ba329e247918c4eef505f6e241b25cc"
        },
        "date": 1747144732593,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 215258300059,
            "range": "± 381179602",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "12bb08d726dcb1515391ea4846399a6c41fd63b4",
          "message": "fix(l2): fix prover benchmarks not compiling (#2757)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-13T13:07:50Z",
          "tree_id": "fe9bd1acf64e6517a84b840ec0215933c89a958f",
          "url": "https://github.com/lambdaclass/ethrex/commit/12bb08d726dcb1515391ea4846399a6c41fd63b4"
        },
        "date": 1747145055671,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 216613314283,
            "range": "± 471487870",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "francisco.gauna@lambdaclass.com",
            "name": "fedacking",
            "username": "fedacking"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "987089f71eb5c446c4a51ba4db3bac7b1edd3695",
          "message": "fix(l1): fixed engine_forkchoiceUpdatedV1 on canonical heads (#2754)\n\n**Motivation**\n\nThis test updates the forkchoiceupdated method to respect the paris\nspecification. The wrong latestValidHash was being sent.\n\n```Client software MAY skip an update of the forkchoice state and MUST NOT begin a payload build process if forkchoiceState.headBlockHash references a VALID ancestor of the head of canonical chain, i.e. the ancestor passed [payload validation](https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#payload-validation) process and deemed VALID. In the case of such an event, client software MUST return {payloadStatus: {status: VALID, latestValidHash: forkchoiceState.headBlockHash, validationError: null}, payloadId: null}.```\n\n**Description**\n\nWhen on an `InvalidForkChoice::NewHeadAlreadyCanonical` branch, changed the `latestValidHash` from the latest canonical for the one given in the `forkchoiceState.headBlockHash` field, as indicated by the spec. Added the `Re-Org Back into Canonical Chain, Depth=10, Execute Side Payload on Re-Org` test back to the CI as it's now fixed.\n\nFixed a test on #1285",
          "timestamp": "2025-05-13T13:59:48Z",
          "tree_id": "14aecde51550040a9d7754f18279bb25965ca142",
          "url": "https://github.com/lambdaclass/ethrex/commit/987089f71eb5c446c4a51ba4db3bac7b1edd3695"
        },
        "date": 1747148065786,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 218104494696,
            "range": "± 989460263",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e3d755829dcf91ab2c31f44d6d6fba196fe4f868",
          "message": "refactor(l1): group node data in RpcContext (#2752)\n\n**Motivation**\n`RpcContext` has become quite extensive lately, so we need to group some\nof its fields into individual structures that hold data used for similar\npurposes. This PR groups static data related to the node (such as p2p\naddress, version, etc) into a `NodeData` struct in order to simplify it.\n\n**Description**\n* Group static data about the node held in `RpcContext` into `NodeData`\n* (Misc) Remove duplicated code between test functions\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nAddresses review comment:\nhttps://github.com/lambdaclass/ethrex/pull/2732#discussion_r2084894577",
          "timestamp": "2025-05-13T14:21:16Z",
          "tree_id": "6eb11c4593dd4a636ed0fd0000a503ab0b60989a",
          "url": "https://github.com/lambdaclass/ethrex/commit/e3d755829dcf91ab2c31f44d6d6fba196fe4f868"
        },
        "date": 1747149320481,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 215689162333,
            "range": "± 607668027",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "git@edgl.dev",
            "name": "Edgar",
            "username": "edg-l"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5d3354f492aa8a1f880d366131ee8e14d86d6b69",
          "message": "perf(l1): reduce transaction clone and Vec grow overhead in mempool (#2637)\n\n**Motivation**\n\nImprove perfomance\n\n**Description**\n\nReduces transaction clone overhead on the mempool and Vec initial grow\noverhead.\n\nThe main focus on this pr was the mempool fetch transaction method whose\noverhead before was 15%~, reducing it to 13%~, whose main time is spent\nin the filter transaction method, which had a clone taking 5% of the\ntime now reduced to non existent levels using an Arc.\n\nImages of the perf profile:\n\nBefore\n\n\n![image](https://github.com/user-attachments/assets/8a2a9e32-8e8d-4c24-8fd2-b5cb91401ee5)\n\nAfter\n\n\n![image](https://github.com/user-attachments/assets/1d3a0c56-5826-4efe-874b-8687c230c070)\n\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-13T14:24:24Z",
          "tree_id": "af56d3b6746259cf1d61d3c2da8ae37d3545ded7",
          "url": "https://github.com/lambdaclass/ethrex/commit/5d3354f492aa8a1f880d366131ee8e14d86d6b69"
        },
        "date": 1747149709029,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 216117720419,
            "range": "± 813275620",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "00f6389fdcfc07c8c31350c311475cd0c64f9ca9",
          "message": "feat(l2): prove withdrawals (#2668)\n\n**Motivation**\n\nWe want to prove the L2 withdrawals in our prover.\n\n**Description**\n\n- Add to `ProgramInput` and `ProverInputData` the field\n`withdrawals_merkle_root` the merkle root that is created by merkelizing\nall the withdrawals from a batch of blocks to send to the prover\n- Inside the prover add logic to for every batch:\n- Gather the withdrawals hashes for each block from the block's\ntransactions.\n  - Get the root of the Merkle tree from these hashes\n- Compare our resulting Merkle root with the incoming from the\n`ProgramInput`\n- Modify the l2 integration-test so that it executes 5 withdrawals to\nensure that the merkelization is working correctly\n- Added a dirty fix where `cargo check` is complaining about a missing\nfield in the struct `ProgramInput` because the crate `l2` enables the\nfeature `l2` in `zkvm-interface` but neither of those crates depend on\n`ethrex-prover` so the feature isn't enabled\n  - This should be fixed by completing #2662\n\nCloses #2201\n\n---------\n\nCo-authored-by: Estéfano Bargas <estefano.bargas@fing.edu.uy>",
          "timestamp": "2025-05-13T14:38:18Z",
          "tree_id": "da414022328038ea91bbd3af15c2678f475eaf6e",
          "url": "https://github.com/lambdaclass/ethrex/commit/00f6389fdcfc07c8c31350c311475cd0c64f9ca9"
        },
        "date": 1747150586903,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 215909501737,
            "range": "± 407125643",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "44068466+SDartayet@users.noreply.github.com",
            "name": "SDartayet",
            "username": "SDartayet"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "ce61df3edb1c9cc5f0b491d8b98d8b6d6ea589a8",
          "message": "refactor(levm): moved retdata from vm to callframe (#2694)\n\n**Motivation**\n\nMake code more readable by coupling related behaviour.\n\n**Description**\n\nSome fields in retdata were repeated in the callframe, and the retdata\nwas always being popped alongside the current call frame. This PR\ndeletes the retdata struct, and moves the fields that weren't redundant\nto the call frame, refactoring the code where appropriate.\n\nIt also removes `gas_used` from `CallFrame::new()` because we were\nalways setting it to zero.\n\nCloses #2571, Closes #2720\n\n---------\n\nCo-authored-by: JereSalo <jeresalo17@gmail.com>\nCo-authored-by: Jeremías Salomón <48994069+JereSalo@users.noreply.github.com>",
          "timestamp": "2025-05-13T15:12:34Z",
          "tree_id": "c982bbf01e83b34c55d1770a73656968e84d4469",
          "url": "https://github.com/lambdaclass/ethrex/commit/ce61df3edb1c9cc5f0b491d8b98d8b6d6ea589a8"
        },
        "date": 1747152672369,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 219429486378,
            "range": "± 473058913",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "cbe66e9c87ea0b67ab86e7b930784d03580c3751",
          "message": "fix(l2): disable RPC bench slack message (#2765)\n\n**Motivation**\n\nThe job is unstable, we should reenable when possible\n\n**Description**\n\n- Comment out the last step of the job",
          "timestamp": "2025-05-13T15:30:24Z",
          "tree_id": "ab1ff838429147820ba7652ecb72b21cffe19f30",
          "url": "https://github.com/lambdaclass/ethrex/commit/cbe66e9c87ea0b67ab86e7b930784d03580c3751"
        },
        "date": 1747153568728,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 214787702115,
            "range": "± 1266159413",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "37498c67ad14aea3aaf0e68ae433762022306dda",
          "message": "ci(l1): comment flaky snap sync test (#2672)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n- Test is flaky in CI\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-13T15:52:23Z",
          "tree_id": "f184df6d22863e40b16db7bb3514450de8493f93",
          "url": "https://github.com/lambdaclass/ethrex/commit/37498c67ad14aea3aaf0e68ae433762022306dda"
        },
        "date": 1747154905475,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 212556006834,
            "range": "± 468298929",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9faceb7cda8f4317ed9ea465aa2d38a49fe1ca50",
          "message": "fix(l1): support both `data` and `input` fields on `GenericTransaction` as long as they have the same value (#2685)\n\n**Motivation**\nIssue #2665 reported that some tools create transactions with both the\n`data` and `input` fields set to the same value, which is not currently\nsupported by our deserialization which admits only one. Other\nimplementations also support having both fields in their equivalent of\n`GenericTransaction`. This PR handles this case by adding a custom\ndeserialization that can parse both fields and check that they are equal\nif set to prevent unexpected behaviours.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Implement custom field deserialization so that both `input` & `data`\nfields are supported but deserialized as one\n* Add test case for the reported failure case\n* Use a non-trivial input for the current and added deserialization test\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2665",
          "timestamp": "2025-05-13T16:14:39Z",
          "tree_id": "4096c716b0add7c4617dfe56b24f76e6de3b2460",
          "url": "https://github.com/lambdaclass/ethrex/commit/9faceb7cda8f4317ed9ea465aa2d38a49fe1ca50"
        },
        "date": 1747156236876,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 218439928619,
            "range": "± 1275869476",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "cf1b0a811151ef84f5eee3832356fddbdf01b2db",
          "message": "feat(l2): prove deposits (#2737)\n\n> [!NOTE]\n> This is an updated version of #2209  from @xqft \n\n**Motivation**\n\nWe want to prove the L2 deposits in our prover\n\n**Description**\n\n- Add to `ProgramInput` and `ProverInputData` the field\n`deposit_logs_hash` the hash that is created by hashing the concatenated\ntransaction hashes from a batch of blocks to send to the prover\n- Inside the prover add logic to for every batch:\n- Gather the deposit tx hashes for each block from the block's\ntransactions.\n  - Calculate the logs hash the same way the l1_committer does\n  - Compare our resulting hash with the incoming from the `ProgramInput`\n\n\nCloses #2199\n\n---------\n\nCo-authored-by: Estéfano Bargas <estefano.bargas@fing.edu.uy>",
          "timestamp": "2025-05-13T16:45:04Z",
          "tree_id": "a0311c49b1691af7c96d595664f3d13217f2c8dc",
          "url": "https://github.com/lambdaclass/ethrex/commit/cf1b0a811151ef84f5eee3832356fddbdf01b2db"
        },
        "date": 1747158142215,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 217383880094,
            "range": "± 489849781",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "20262dbd521ff694788b2739087a6965001b0bf8",
          "message": "chore(l2): remove default contract addresses from Makefile (#2769)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nContract addresses change frequently and they need to be changed in the\nMakefile.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nRemove the default values and read the addresses from the `.env` file,\nwhich are written by the deployer in case of using. In case you want to\nuse the `init-l2` flow without the deployer and the `.env` file, you\nhave to set the variables `BRIDGE_ADDRESS` and\n`ON_CHAIN_PROPOSER_ADDRESS` when running the target, else it will fail\nwith an error like `error: a value is required for '--bridge-address\n<ADDRESS>' but none was supplied`. For example:\n\n```sh\nmake init-l2 BRIDGE_ADDRESS=0x8ccf74999c496e4d27a2b02941673f41dd0dab2a ON_CHAIN_PROPOSER_ADDRESS=0x60020c8cc59dac4716a0375f1d30e65da9915d3f\n```\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-05-13T17:26:45Z",
          "tree_id": "90a0c46f8a377e45e8167cb92d9f0d0811c70458",
          "url": "https://github.com/lambdaclass/ethrex/commit/20262dbd521ff694788b2739087a6965001b0bf8"
        },
        "date": 1747160514719,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 214806609740,
            "range": "± 604960177",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b0cdf7d0aadfc9e88fc204aa7b0c1bbae6221382",
          "message": "refactor(l1): rename ExecutionDB to ProverDB. (#2770)\n\n**Motivation**\nTo have a clearer name.",
          "timestamp": "2025-05-13T17:46:25Z",
          "tree_id": "fc5fe9ab4869c2c5a2ceb7db65e611b5fcfeb0eb",
          "url": "https://github.com/lambdaclass/ethrex/commit/b0cdf7d0aadfc9e88fc204aa7b0c1bbae6221382"
        },
        "date": 1747161826315,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 216092296164,
            "range": "± 748659977",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "44068466+SDartayet@users.noreply.github.com",
            "name": "SDartayet",
            "username": "SDartayet"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "a1699859576100713a64b17d45ffa66e49597380",
          "message": "refactor(levm): decluttering vm.rs (#2733)\n\n**Motivation**\n\nMaking the code of the vm.rs file cleaner, since it's a bit cluttered\nright now.\n\n**Description**\n\nThe code of vm.rs is a bit messy right now. This PR moves EVM config to\nenvironment, moves a few attributes from environment to substate that\nmake more sense there, and removes the StateBackup struct since it's\nmade unnecessary by this change.\n\nCloses #2731, Closes #2717 \nResolves most of #2718\n\n---------\n\nCo-authored-by: JereSalo <jeresalo17@gmail.com>",
          "timestamp": "2025-05-13T18:45:14Z",
          "tree_id": "3b22d90177c95ac844d95c6f4ae34f98db195cd3",
          "url": "https://github.com/lambdaclass/ethrex/commit/a1699859576100713a64b17d45ffa66e49597380"
        },
        "date": 1747165259658,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 215414120977,
            "range": "± 501244339",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e92418ed4dc8f915f603be49eadd192aeed78b27",
          "message": "feat(l2): make L1 contracts upgradeable (#2660)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nWe want the L1 contracts to be upgradeable so it's possible to fix bugs\nand introduce new features.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nChanged the contracts to follow the UUPS proxy pattern (from\nOpenZeppelin's library). The deployer binary now deploys both the\nimplementation and the proxy.\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-05-13T22:47:52Z",
          "tree_id": "78298de98b0eafc8acd0b8f9c26b625b05e8da60",
          "url": "https://github.com/lambdaclass/ethrex/commit/e92418ed4dc8f915f603be49eadd192aeed78b27"
        },
        "date": 1747179752639,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 216876058534,
            "range": "± 1052910502",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "bc79391f811cad4e744f294c95580bd48b6d6d5b",
          "message": "feat(l2): signature-based TDX (#2677)\n\n**Motivation**\n\nVerifying TDX attestations on-chain is expensive (~5M gas), so it would\nbe better to avoid them if possible\n\n**Description**\n\nBy generating a private key inside the TDX VM (where the host can't read\nit), attesting it's validity and then using it to sign updates it's\npossible to massively decrease gas usage.",
          "timestamp": "2025-05-14T12:50:56Z",
          "tree_id": "d9a51beed6c4778ec24646ce23d11ce277e5d30b",
          "url": "https://github.com/lambdaclass/ethrex/commit/bc79391f811cad4e744f294c95580bd48b6d6d5b"
        },
        "date": 1747230630465,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 218414268838,
            "range": "± 693614133",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "garmasholeksii@gmail.com",
            "name": "GarmashAlex",
            "username": "GarmashAlex"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "3b6efc87ee15fb79bdd18f8a3cfb5f3ab55e2e30",
          "message": "refactor(l2): Remove redundant address derivation function in load_test (#2494)\n\n**Motivation**\n\nThis pull request addresses a TODO comment in the load_test code that\nsuggested moving the custom address derivation function to common\nutilities. Instead of duplicating functionality, we should leverage\nexisting code from the SDK to improve maintainability and consistency\nacross the codebase.\n\n**Description**\n\nThis PR removes a redundant implementation of Ethereum address\nderivation in the load_test tool by replacing it with the existing\nget_address_from_secret_key function from the L2 SDK. The changes\ninclude:\n- Removed the custom address_from_pub_key function that was marked with\na TODO comment\n- Added an import for get_address_from_secret_key from ethrex_l2_sdk\n- Updated all usages throughout the code to use the SDK function instead\n- Added proper error handling for the SDK function calls\n\n---------\n\nCo-authored-by: Tomás Paradelo <112426153+tomip01@users.noreply.github.com>\nCo-authored-by: Martin Paulucci <martin.c.paulucci@gmail.com>\nCo-authored-by: Tomás Arjovsky <tomas.arjovsky@lambdaclass.com>",
          "timestamp": "2025-05-14T14:30:11Z",
          "tree_id": "67f931ab8af0a738c16e13d99c109f4b621642bf",
          "url": "https://github.com/lambdaclass/ethrex/commit/3b6efc87ee15fb79bdd18f8a3cfb5f3ab55e2e30"
        },
        "date": 1747236319834,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 219789260989,
            "range": "± 1654376614",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "77f7dd4e48ad8008818e9067e9e82e99131e109b",
          "message": "refactor(l2): replace prover config toml with CLI flags (#2771)\n\n**Motivation**\n\nWe want to replace the .toml file used to configure the prover with a\ncli\n\n**Description**\n\n- Remove all the code related to reading toml files\n- Implement a struct ProverClientOptions that adds CLI options for the\nprover\n\n**How to test**\n\nIf you are in a dev environment, keep working as usual because under the\nhood, the sequencer initialization is not relying anymore on the\nprover_client_config.toml.\n\nIf you are in a prod environment, inside `crates/l2/prover` run `cargo\nrun --release -- --help` to explore the different configuration flags\nthis PR adds.\n\nCloses #2576",
          "timestamp": "2025-05-14T16:51:47Z",
          "tree_id": "39aa5a67946e692e9d0627237e8ad29578479091",
          "url": "https://github.com/lambdaclass/ethrex/commit/77f7dd4e48ad8008818e9067e9e82e99131e109b"
        },
        "date": 1747244812554,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 218451050738,
            "range": "± 825432720",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "onoratomatias@gmail.com",
            "name": "Matías Onorato",
            "username": "mationorato"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "ac0b378a346cbadec43a1a4464f58d1524a93c6d",
          "message": "fix(l2): remove rich wallets from l2 genesis (#2781)\n\n**Motivation**\nRemove no longer needed rich wallets from l2 genesis file\n\n---------\n\nCo-authored-by: Leandro Serra <leandro.serra@lambdaclass.com>\nCo-authored-by: Javier Chatruc <jrchatruc@gmail.com>\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>",
          "timestamp": "2025-05-14T17:09:35Z",
          "tree_id": "283b1c9d6bca4d5952c4808241396bfcb84bdcc3",
          "url": "https://github.com/lambdaclass/ethrex/commit/ac0b378a346cbadec43a1a4464f58d1524a93c6d"
        },
        "date": 1747245836503,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 214931652850,
            "range": "± 662253206",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9779033a81150bc1975cf5d8bcab701935fca5c9",
          "message": "refactor(l1): rename incorrect usage of `node_id` to `public_key` (node_id refactor 1/3) (#2778)\n\n**Motivation**\nOur implementation of `Node` stores the node's public key as `node_id`\nwhich is very confusing, as the `node_id` is the keccak256 hash of the\npublic key. This can lead to potential bugs and discrepancies with other\nimplementations where node_id is indeed the keccack hash of the public\nkey.\nFor this PR I left the public key as part of the Node but corrected its\nname to `public_key`, leaving all use cases as is.\nI also renamed some functions that mislabeled public key as node_id to\nbetter reflect what they do. The methods `id2pubkey` and `pubkey2id`\nconvert between the uncompressed (H512) and compressed (PubKey) versions\nof the same data so I renamed them to `compress_pubkey` and\n`decompress_pubkey`.\nI also added the method `node_id` to `Node` which returns the actual\nnode_id (aka the keccak252 hash of the public key).\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Rename various instances of `node_id` to `public_key`\n* Rename methods `id2pubkey` and `pubkey2id` to `compress_pubkey` and\n`decompress_pubkey`.\n* Add `Node` method `node_id`\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n**Potential Follow-Up work**\nCache node_id computation so we don't need to hash the public key on\nevery Kademlia table operation (#2786 + #2789 )\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2774",
          "timestamp": "2025-05-14T17:45:15Z",
          "tree_id": "9946ff2cca57f38af4c8bcfb8f19be9ad3532255",
          "url": "https://github.com/lambdaclass/ethrex/commit/9779033a81150bc1975cf5d8bcab701935fca5c9"
        },
        "date": 1747247974746,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 216845771775,
            "range": "± 626773854",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e77e18db5b13cc888f1d7e29ec1cd898b3322e1f",
          "message": "fix(core): remove hardcoded gas_limits use eth_estimateGas (#2793)\n\n**Motivation**\n\nGas limit was hardcoded in some cases because we didn't have\neth_estimateGas implemented now we do so we want to use it when possible\n**Description**\n\n- Replace instances of hardcoded gas_limit and remove it as\n`build_xxxx_transaction` functions already estimate gas if the override\ndoes not include it\n- Set nonce to none when estimating the gas so that doesn't fail when\nsending multiple txs at the same time\n\n\nCloses #2782",
          "timestamp": "2025-05-14T20:04:57Z",
          "tree_id": "377ba81f14d36a331cac222a127f75e683e5eb4f",
          "url": "https://github.com/lambdaclass/ethrex/commit/e77e18db5b13cc888f1d7e29ec1cd898b3322e1f"
        },
        "date": 1747256341133,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 212074008379,
            "range": "± 1026379321",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "76521daffea5dfb35562c67903f4cbd028eeb77c",
          "message": "feat(l2): verify state roots (#2784)\n\n**Motivation**\n\nCurrently the OnChainProposer does not verify the initial and final\nstate roots contained in the program output.\n\n**Description**\n\nThe initial and state roots are verified, based on the commitment\nvalues. The genesis state root is added as a 0th block at initialization\ntime.\n\nCloses #2772",
          "timestamp": "2025-05-14T20:35:46Z",
          "tree_id": "41ad4be8fa147cf42bf27a250fb4b48692af9507",
          "url": "https://github.com/lambdaclass/ethrex/commit/76521daffea5dfb35562c67903f4cbd028eeb77c"
        },
        "date": 1747258220468,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 215871106532,
            "range": "± 673861273",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "44068466+SDartayet@users.noreply.github.com",
            "name": "SDartayet",
            "username": "SDartayet"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b47623fdc8865f8e6f83857fccee1d74f145e03e",
          "message": "docs(levm): update levm readme (#2712)\n\n**Motivation**\n\nKeeping docs updated.\n\n**Description**\n\nThe README was severely out of date, specially the roadmap. This updates\nit to line up with the current project state and goals.\n\nCloses #2704\n\n---------\n\nCo-authored-by: Jeremías Salomón <48994069+JereSalo@users.noreply.github.com>\nCo-authored-by: Martin Paulucci <martin.c.paulucci@gmail.com>",
          "timestamp": "2025-05-14T21:21:08Z",
          "tree_id": "48e8dd7ddc3cfc5cd0de6bda26c06bd70643bd90",
          "url": "https://github.com/lambdaclass/ethrex/commit/b47623fdc8865f8e6f83857fccee1d74f145e03e"
        },
        "date": 1747260913598,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 213977625223,
            "range": "± 486410635",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "cba42cdcb2efcf1c3ab2fa204ccefffc1d37c5bf",
          "message": "fix(l2): fix indices (#2802)\n\n**Motivation**\n\nThere was an error in verifyPublicData when running with SP1\n\n**Description**\n\nverifyPublicData didn't take into account that SP1 contains a 16 byte\nheader with the length of the data",
          "timestamp": "2025-05-15T14:40:27Z",
          "tree_id": "2d57562e6595c57822ebc83a1859e79da4a8d56d",
          "url": "https://github.com/lambdaclass/ethrex/commit/cba42cdcb2efcf1c3ab2fa204ccefffc1d37c5bf"
        },
        "date": 1747323240121,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 211524278737,
            "range": "± 407033651",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "francisco.gauna@lambdaclass.com",
            "name": "fedacking",
            "username": "fedacking"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c558c8db13a7f12dffe9cd13e979e0f551fbe6f0",
          "message": "fix(l1): lowered time for periodic tx broadcast interval (#2751)\n\n**Motivation**\n\nA test that involved multiple clients was failing due to the clients not\ncommunicating their transactions between them before the tests asked for\na new block.\n\n**Description**\n\nThis pr reduces the checking time from 5 seconds to 500 miliseconds and\nadds the test to the CI.\n\nFixes \"Blob Transaction Ordering, Multiple Clients\" failing test in\n#1285.",
          "timestamp": "2025-05-15T14:50:55Z",
          "tree_id": "50badb1b21a128e454143540cf788d626270200a",
          "url": "https://github.com/lambdaclass/ethrex/commit/c558c8db13a7f12dffe9cd13e979e0f551fbe6f0"
        },
        "date": 1747323864035,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 212299379963,
            "range": "± 995047590",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "ce76f6903fc702671d943c5fe9717f08d77fe951",
          "message": "refactor(l1): add `node_id` field to Node (node_id refactor 2/3) (#2786)\n\nBased on #2778 \n**Motivation**\nAvoid constantly hashing the node's public key on kademlia operations by\nadding `node_id` field. Before this PR we would hash the node's public\nkey every time we needed to add, remove or find a node in the kademlia\ntable, which is pretty often.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add `Node` field `node_id`\n* Add `new` method for `Node` which handles node_id computation\n* Use `node_id` for kademlia table (and some other) operations instead\nof the public key so we no longer need to hash it when calculating the\nbucket index (this affects most kademlia table reads/writes)\n\n**Follow-Up Work**\nUse `OnceLock` to cache for `node_id` computation (replacing the field\nadded by this PR) #2789\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-15T15:15:26Z",
          "tree_id": "96bf81f986d995dc5589a52cd3eb5a35ed4e516f",
          "url": "https://github.com/lambdaclass/ethrex/commit/ce76f6903fc702671d943c5fe9717f08d77fe951"
        },
        "date": 1747325360999,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 213187996576,
            "range": "± 957701325",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomas.arjovsky@lambdaclass.com",
            "name": "Tomás Arjovsky",
            "username": "Arkenan"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "621ac953a3fab3f05efff24aa82db8591fab0bf2",
          "message": "fix(core): timeout due to node inactivity instead of total load test time (#2530)\n\nChanges:\n\n- Timeout is now smarter. Instead of waiting a fixed amount of time\n(e.g. 10 minutes) for the whole load test to happen, which is a bit\nunpredictable, the load test waits at most 1 minute (configurable) of\nno-updates from the node. This way it's less machine dependent and more\nbased on responsiveness.\n- load-test-ci.json is fixed to be similar to perf-ci.json, but in\nprague and with the system smart contracts from l1-dev.json deployed.\n- logs are re-added.\n- Readme si fixed.\n- Re-add flamegraph reporter to CI so they are generated on every push.\n\nCloses #2522",
          "timestamp": "2025-05-15T17:04:16Z",
          "tree_id": "f64c37d48452480f6003549cb7916a399c25f745",
          "url": "https://github.com/lambdaclass/ethrex/commit/621ac953a3fab3f05efff24aa82db8591fab0bf2"
        },
        "date": 1747331906099,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 216034894492,
            "range": "± 738409528",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "0f9cc95d8cf5fb15b0d5acc37bf9c2264e0ff5db",
          "message": "refactor(l1): cache `node_id` computation (node_id refactor 3/3) (#2789)\n\nBased on #2786 \n**Motivation**\nUse `OnceLock` to cache node_id computation so we only do it once but at\nthe same time don't need to do it unless we will use it. For example,\nwhen we receive a Neighbours message we will decode all received nodes\nbut may not use them all if our kademlia table is full.\nThis PR can be ignored if we consider the cases where we would not need\nto use a node's id scarce enough to not warrant the added complexity of\na cache. For example, the Neighbours case could be handled by using a\nseparate structure (without node_id) to decode the incoming node and\nconverting that to our Node (with node_id) when we insert that node into\nour table.\nThe main consecuente of adding this cache is the `Node` no longer being\ncopy, which affects various areas of the networking codebase\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Convert public `Node` field `node_id: H256` into private field\n`node_id: OnceLock<H256>`\n* Add `Node` method `node_id`\n* Fix code affected by `Node` no longer being `Copy`\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-15T18:40:12Z",
          "tree_id": "7ab0821461058532c135bdaf08ba49e22fa73d0c",
          "url": "https://github.com/lambdaclass/ethrex/commit/0f9cc95d8cf5fb15b0d5acc37bf9c2264e0ff5db"
        },
        "date": 1747337654065,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 214059266089,
            "range": "± 656689088",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "47ffb22802baaee9c132c4b3e68cc8393b143fff",
          "message": "fix(l2): contract deployer fixes (#2779)\n\n**Motivation**\n\nIf an integration test fails, it's really difficult to debug the\ncontract deployer and know that the problem was there in the first\nplace.\n\n**Description**\n\n- removes spinner\n- adds clearer logs and traces\n- make ethrex_l2 container depend on the deployer terminating\nsuccessfuly (so flow stops if deployer failed)",
          "timestamp": "2025-05-15T18:57:07Z",
          "tree_id": "dc79c11341afae3ba40d1e7f85e51ed842600a9c",
          "url": "https://github.com/lambdaclass/ethrex/commit/47ffb22802baaee9c132c4b3e68cc8393b143fff"
        },
        "date": 1747338700803,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 215684276859,
            "range": "± 1122022987",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c3c01438d5bdbd8f7e2f0203d670613a2a821c15",
          "message": "fix(l1, levm): propagate error that we were ignoring when getting account (#2813)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n- We shouldn't ignore the case in which there's a StoreError or a\nTrieError when trying to get an account's info. It is something that\nprobably doesn't happen very often but I think it's a mistake to ignore\nit as we've been doing.",
          "timestamp": "2025-05-15T19:34:48Z",
          "tree_id": "edfe8cac6b4cda4e1fad038f6d41e59cd198bff2",
          "url": "https://github.com/lambdaclass/ethrex/commit/c3c01438d5bdbd8f7e2f0203d670613a2a821c15"
        },
        "date": 1747340910229,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 211834931856,
            "range": "± 762639883",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "19097eeba57defb13af215cf50adb39d6eada412",
          "message": "chore(l2): separate address initialization (#2809)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nDeploy proxy contracts without instant initialization is considered\ninsecure.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nChange OnChainProposer contract so it can be initialized and then the\nowner can set (only once) the bridge address\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-05-15T19:47:53Z",
          "tree_id": "aa0dfc08af20716fab5374f5f6d7aacbf355b1fa",
          "url": "https://github.com/lambdaclass/ethrex/commit/19097eeba57defb13af215cf50adb39d6eada412"
        },
        "date": 1747341717255,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 214211258971,
            "range": "± 457946020",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "56402156+fkrause98@users.noreply.github.com",
            "name": "Francisco Krause Arnim",
            "username": "fkrause98"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e1394a3058c308047c733289e917fb41e3552277",
          "message": "ci(l1,l2): run \"main-prover-l1\" only on merge to main (#2815)\n\n**Motivation**\n\nThis is not a required check anymore, so we only will run it on a merge\nto main instead of each PR.\n**Description**\n\n- Simply make the yml worklfow run on a merge to main",
          "timestamp": "2025-05-15T20:09:59Z",
          "tree_id": "321c0ba74181e40108d72208066a32e99250d2e6",
          "url": "https://github.com/lambdaclass/ethrex/commit/e1394a3058c308047c733289e917fb41e3552277"
        },
        "date": 1747343050392,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 214262421000,
            "range": "± 448241860",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e7a4a038c19709c129cdf7e3c93d9a6240a4481c",
          "message": "ci(l1): comment flaky devp2p test Findnode/UnsolicitedNeighbors (#2817)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nCommenting the test until it's fixed, just the one that's flaky\nOpened issue: https://github.com/lambdaclass/ethrex/issues/2818\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-15T20:34:43Z",
          "tree_id": "c13fc5b333fd0ce4619fa309398ef1e83e550aa3",
          "url": "https://github.com/lambdaclass/ethrex/commit/e7a4a038c19709c129cdf7e3c93d9a6240a4481c"
        },
        "date": 1747344568724,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 214406837672,
            "range": "± 357355357",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "6efc8891ed386e1410a747995d793c4e9442586f",
          "message": "chore(core): fix block producer logs. (#2806)\n\n**Motivation**\nLogs say v3, pero it is sending v4.",
          "timestamp": "2025-05-15T20:44:08Z",
          "tree_id": "45a01330683f0da442fd7f61d4d44d67dbf73dc6",
          "url": "https://github.com/lambdaclass/ethrex/commit/6efc8891ed386e1410a747995d793c4e9442586f"
        },
        "date": 1747345085906,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 213809807696,
            "range": "± 943858244",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "56402156+fkrause98@users.noreply.github.com",
            "name": "Francisco Krause Arnim",
            "username": "fkrause98"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d4d34595443f68a9f44c27d0d9db4a2ba67b9b1f",
          "message": "chore(l1,l2): ordered genesis files (#2713)\n\n**Motivation**\n\nOrdered genesis files make it easy to diff with one another.\n\n**Description**\n\n- Add function to write a Genesis json file with its keys ordered.\n- Genesis files are now ordered by key.\n\n\nCloses #2706.",
          "timestamp": "2025-05-15T21:07:01Z",
          "tree_id": "a99724ca368c79f6c2a29142ed03c84a6b70413e",
          "url": "https://github.com/lambdaclass/ethrex/commit/d4d34595443f68a9f44c27d0d9db4a2ba67b9b1f"
        },
        "date": 1747346571474,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 216993999533,
            "range": "± 414996510",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e3b8c3bf4d377f0c5232da117f35018993807041",
          "message": "refactor(levm): refactor the main execution flow methods (#2796)\n\n**Motivation**\n\n- Make LEVM a little bit more understandable and clean. It is a first\nimprovement of the main parts of the code. Improvements can still be\nmade there and even more changes can be made in other functions/methods.\n\n**Description**\n\nSome changes:\n- `VM::new()` doesn't return a `Result` anymore. Just a `VM`.\n- Some logic that was in `VM::new()` was moved to a new method\n`self.setup_vm()`\n- Created some methods for VM for callframe interaction. Just for having\ncleaner code.\n- Changed some variable names.\n- Popping callframe only when really necessary (after Call or Create),\nso no more popping and pushing back when we didn't want to pop in the\nfirst place. We now pop it inside handle_return because that method's\npurpose is handle interaction between callframes.\n- Delete some fields from VM and replaced those for a `Transaction`\nfield. Fields replaced were access_list, authorization_list and tx_kind\n- Early revert when creating an address that already exists is more\ngraceful and explicit now (in `execute()`).\n- Logic in generic_call for executing precompiles changed a bit so that\nwe don't call run_execution but instead we execute the precompile and\nhandle the return after doing so. So now we never call `run_execution`\nrecursively.\n- Moved some code mostly to utils.rs so that vm.rs is cleaner\n- Overall tidy all main methods (new, execute and run_execution)\n- Added and changed some comments where I considered appropriate doing\nso\n\nThe diff is hard to review. The code works as intended.\nThe most important thing is how the main functions changed.\nBefore and After `vm.rs`:\n\n[main](https://github.com/lambdaclass/ethrex/blob/76521daffea5dfb35562c67903f4cbd028eeb77c/crates/vm/levm/src/vm.rs)\n- [this\nbranch](https://github.com/lambdaclass/ethrex/blob/levm/refactor_new/crates/vm/levm/src/vm.rs)",
          "timestamp": "2025-05-16T15:14:39Z",
          "tree_id": "57f8ae0d879337b87451f7e5149687038293f539",
          "url": "https://github.com/lambdaclass/ethrex/commit/e3b8c3bf4d377f0c5232da117f35018993807041"
        },
        "date": 1747411657070,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 209179635152,
            "range": "± 1143289486",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e22c4dad2c151ad1f0aad8182f4d992c273c086e",
          "message": "fix(core): remove hardcoded max_fee_per_gas & max_priority_fee_per_gas (#2803)\n\n**Motivation**\n\nThis values should be set dinmically \n\n**Description**\n\n- Add `get_max_priority_fee` to `EthClient` to call\n`eth_maxPriorityFeePerGas` endpoint\n- When calling `build_xxxx_transaction` without `max_fee_per_gas`\noverride\n   - Set it to the result of calling `eth_gasPrice` endpoint\n- When calling `build_xxxx_transaction` without `max_fee_per_gas`\noverride\n  - Set it to the result of calling `eth_maxPriorityFeePerGas`\n- Because `eth_maxPriorityFeePerGas` in Ethrex can return null if it\ndoes set it to the result of calling `eth_gasPrice`\n\nCloses #2795",
          "timestamp": "2025-05-16T15:17:30Z",
          "tree_id": "6a3cf40f41ba17e606890b097ccae13050f573a4",
          "url": "https://github.com/lambdaclass/ethrex/commit/e22c4dad2c151ad1f0aad8182f4d992c273c086e"
        },
        "date": 1747411876523,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 209532389868,
            "range": "± 629754806",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "73589782ecbbff8d1c9f38efe5c9439748cbbdbe",
          "message": "fix(l2): fix fixed array and static tuple calldata encoding (#2821)\n\n**Motivation**\n\nFixes a bug when encoding calldata including fixed arrays or static\ntuples. The code for `encode_calldata` preallocates the entire static\nregion of calldata, but the code was mistakenly extending it instead of\njust copying into the static region the encoded fixed array/static tuple\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-16T15:58:33Z",
          "tree_id": "4f057b6150156d992b95b3576c98591de32cb0d1",
          "url": "https://github.com/lambdaclass/ethrex/commit/73589782ecbbff8d1c9f38efe5c9439748cbbdbe"
        },
        "date": 1747414327202,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 208134830896,
            "range": "± 317899704",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "391568ca6be059f8d3e61ce4282b0879718c3004",
          "message": "refactor(l1): don't persist `is_synced` + add doc (#2822)\n\n**Motivation**\nThe method `Store::is_synced` is quite confusing. This method aims to\nclarify what \"being synced\" means for its specific use case via\ndocumentation. It also removes it from the DB as we don't need to\npersist it (persisting it means that we need to purposefully set it to\nfalse upon startup each time). It also removes cases where it was being\nset to false after the initial sync had taken place.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Move `is_synced` method from `Store` (persisted) to `Blockchain` (not\npersisted)\n* Change `update_sync_status` to `set_synced` so we don't go back to\nunsynced state after the initial sync had taken place (This is the same\nbehaviour geth follows)\n* Remove instances where the sync status was updated outside of applying\nfork choices\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-05-16T18:23:43Z",
          "tree_id": "9e486db221d844386179a5a140ca4a3284b2cc3e",
          "url": "https://github.com/lambdaclass/ethrex/commit/391568ca6be059f8d3e61ce4282b0879718c3004"
        },
        "date": 1747423041373,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 212032059435,
            "range": "± 1028418602",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "eb946a3d71e628701a32d6296064b07ff0ffa0b5",
          "message": "fix(l2): rebuild prover when necessary with init-prover (#2810)\n\n**Motivation**\n\nRunning `make init-prover` didn't rebuild the binary when changes were\nmade to the crate, this lead to errors and bad dev experience.\n\n**Description**\n\n- Remove outdated `ethrex_L2_CONFIGS_PATH` var in Makefile\n- `build-prover` now deletes the existing prover executable and always\nrebuilds it\n- `init-prover` depends on target `../../target/release/ethrex_prover`\n- if the executable is outdated it's rebuilt & run otherwise it's just\nrun\n- `../../target/release/ethrex_prover` now depends on all the source\nfiles from `prover/` folder so it is only run if any of the files has a\nlater modified date than `../../target/release/ethrex_prover`\n\nOne thing to keep in mind if that you can't change the prover backend by\ndoing `make init-prover`.\nFor example if you first do `make init-prover PROVER=sp1` and then do\n`make init-prover PROVER=risc0` the prover won't be rebuilt, you need to\nuse `make build-prover PROVER=risc0` to do this or delete the executable\nat `../../target/release/ethrex_prover`\n\n\nCloses #2794",
          "timestamp": "2025-05-16T19:24:23Z",
          "tree_id": "bd3b1b96f0fd03a6279a9b5fd7b4d2f8b2182e0f",
          "url": "https://github.com/lambdaclass/ethrex/commit/eb946a3d71e628701a32d6296064b07ff0ffa0b5"
        },
        "date": 1747426670308,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 210629379672,
            "range": "± 559780210",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "30327624+mechanix97@users.noreply.github.com",
            "name": "Mechardo",
            "username": "mechanix97"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4f907545c69702c88bcf442ffcbfb38ad7a59c30",
          "message": "refactor(l1): capability struct instead of tuple (#2814)\n\n**Motivation**\n\nThe capability information was stored as a tuple\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\nA new struct was created in order to improve the readability and also\nmake place for future developments about the capability\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-05-16T20:18:20Z",
          "tree_id": "4ed1fdc5baaf87c4d56609242afe7039bfb46666",
          "url": "https://github.com/lambdaclass/ethrex/commit/4f907545c69702c88bcf442ffcbfb38ad7a59c30"
        },
        "date": 1747429969646,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 210783276694,
            "range": "± 515032646",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "90105443+DiegoCivi@users.noreply.github.com",
            "name": "DiegoC",
            "username": "DiegoCivi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c8fbd5cedcc04e131104d4e169c1e944d9a6b87c",
          "message": "chore(l1): fix remaining EIP-7002 and EIP-7251 ef tests (#2738)\n\n**Motivation**\n\nThere are tests from EIPs 7002 and 7251 that are being skipped on LEVM\nand REVM.\n\n**Description**\n\nAccording to\n[EIP-7002](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7002.md)\nand\n[EIP-7251](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7251.md),\nintrinsic gas does not count on system calls defined in this especific\nEIPs. In order to avoid introducing complexity elsewhere in the codebase\n(such as in intrinsic gas computation), system call contexts were\nupdated to include an extra 21,000 gas, the base cost of any\ntransaction.",
          "timestamp": "2025-05-16T20:38:37Z",
          "tree_id": "0c81c56b154b0d56e62aa57d5ed7a29b05647775",
          "url": "https://github.com/lambdaclass/ethrex/commit/c8fbd5cedcc04e131104d4e169c1e944d9a6b87c"
        },
        "date": 1747431147262,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 212766253430,
            "range": "± 308242943",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e965019cf45c637aa1786a6c0fefd6dd1a214b78",
          "message": "feat(l2): add flag to delay the watcher until a trusted block (#2816)\n\n**Motivation**\n\nL1 reorgs can left the L2 in a bad state if a reorged block deposits'\nare processed.\n\n**Description**\n\n- Add the flag `watcher_block_delay` with default value 0 that\nrepresents the amount of blocks of delay the l1 watcher has.\n- If the latest block in l1 is 100 and we set this delay to 10 l1\nwatcher will look for deposits until block 90\n- Add logs and return empty from the function if \n   - We are too close to genesis (current_block - block_delay < 0)\n- We changed the block delay and now the last block verified by the\ncontract is no longer a trusted block\n\n\nCloses #2187\n\n---------\n\nCo-authored-by: Ivan Litteri <67517699+ilitteri@users.noreply.github.com>\nCo-authored-by: Manuel Iñaki Bilbao <manuel.bilbao@lambdaclass.com>",
          "timestamp": "2025-05-16T21:11:17Z",
          "tree_id": "217e4cece58c4a4a0debb27e9747cc98574d950c",
          "url": "https://github.com/lambdaclass/ethrex/commit/e965019cf45c637aa1786a6c0fefd6dd1a214b78"
        },
        "date": 1747433196151,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 208995667996,
            "range": "± 1043990459",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "c6a0008475a45a9280a91fb85dc555658e95a20b",
          "message": "feat(l2): allow changing listen addresses in Makefile (#2834)\n\n**Motivation**\n\nFor running TDX, it's useful to set proof_coordinator_listen_ip to\n0.0.0.0 while in other contexts 127.0.0.1 might make more sense.\n\n**Description**\n\nThis PR adds support for setting listen ips in the l2 Makefile for\nproof_coordinator_listen_ip and the L1&L2 RPCs.",
          "timestamp": "2025-05-16T21:46:07Z",
          "tree_id": "505212ec954d47a240b0d37ce3c9f214dff76391",
          "url": "https://github.com/lambdaclass/ethrex/commit/c6a0008475a45a9280a91fb85dc555658e95a20b"
        },
        "date": 1747435445460,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 211851230370,
            "range": "± 466345296",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "56402156+fkrause98@users.noreply.github.com",
            "name": "Francisco Krause Arnim",
            "username": "fkrause98"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "437a4eea001e763280cd25aae6bdf862a0038c92",
          "message": "fix(core): restore fixed genesis file for load test (#2828)\n\n**Motivation**\n\nSome changes (probably #2713) undid the fixed changes for the load test\ngenesis file,\nthis PR restores it.",
          "timestamp": "2025-05-16T22:33:30Z",
          "tree_id": "0bff90767f240894bed19e509b5763687cbd32c4",
          "url": "https://github.com/lambdaclass/ethrex/commit/437a4eea001e763280cd25aae6bdf862a0038c92"
        },
        "date": 1747438067197,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 211152125175,
            "range": "± 672305743",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8c3408d1e1f9ea784cc27e1d7e4186b8068531ea",
          "message": "fix(l2): update system contracts before deployment (#2839)\n\n**Motivation**\n\nUpdating after deployment meant that we were deploying the\nOnChainProposer with an older initial state root (because the genesis\nwas being updated after and the L2 starts with a different genesis),\nleading to the `verifyBatch` function to always fail.",
          "timestamp": "2025-05-19T16:54:44Z",
          "tree_id": "1de7cacd6b47aa3b035aa853c710500511c8c5c4",
          "url": "https://github.com/lambdaclass/ethrex/commit/8c3408d1e1f9ea784cc27e1d7e4186b8068531ea"
        },
        "date": 1747676925579,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 211114655118,
            "range": "± 665494416",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e39ccb875c18b50fdb5b524c802d7e9cc469d619",
          "message": "fix(l2): failed compilation in crate prover/bench (#2830)\n\n**Motivation**\n\nThe ci is broken\n\n**Description**\n\n- Clone the access list as tx.access_list() now returns a reference\n- Fix all the warnings the prover crate had\n- Make the l2 lint ci run in every PR",
          "timestamp": "2025-05-19T17:45:20Z",
          "tree_id": "562110989686e0e4b0052021a50e9b4a7a1e1902",
          "url": "https://github.com/lambdaclass/ethrex/commit/e39ccb875c18b50fdb5b524c802d7e9cc469d619"
        },
        "date": 1747679959984,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 209707726458,
            "range": "± 570833560",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "30327624+mechanix97@users.noreply.github.com",
            "name": "Mechardo",
            "username": "mechanix97"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2fcf668a5c84b1dede8e868d1ad63c0d9474deab",
          "message": "feat(l1): properly calculate `enr` sequence field (#2679)\n\n**Motivation**\n\nThe seq field in the node record was hardcoded with the unix time. \n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\nThe enr_seq field is updated by one when the node_record is changed. The\nping/pong messages are sent with the enr_seq in it, so the peer knows\nwhen an update is made in the node_record. Since we don't modify the\nnode_record yet, the enr_seq is not being updated. There is a new PR\nincoming (#2654) which is using this funtionality to inform the peers\nabout changes in the node_record.\n\nA reference was added to the p2pcontext in order to be able to access\nthe current NodeRecord seq in several parts of the code.\n\nSome functions firms were changed to accept this improvement.\n\nA new config struct has been built to persist the enr seq field and also\nstore the known peers in the same file.\n\nThe test discv4::server::tests::discovery_enr_message checks this\nfeature\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\n[enr](https://github.com/ethereum/devp2p/blob/master/enr.md)\n\nCloses #1756",
          "timestamp": "2025-05-19T17:53:25Z",
          "tree_id": "7ca4ce20efe9f03f712421e6f8ff15159dfa376d",
          "url": "https://github.com/lambdaclass/ethrex/commit/2fcf668a5c84b1dede8e868d1ad63c0d9474deab"
        },
        "date": 1747680417130,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 209242250885,
            "range": "± 414689451",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9ba8270b2edadec13496080446025cd3b0eabf80",
          "message": "fix(levm): fix last blockchain tests for LEVM (#2842)\n\n**Motivation**\n\n- Fix remaining blockchain tests for Prague with LEVM.\n\n**Description**\n\n- Precompiles shouldn't be executed in case they are delegation target\nof the same transaction in which they are being called.\n- It also fixes a problem in the transfer of value in CALL. (It just\nmoves the place where the value transfer is performed)\n\nAfter this there are no more `blockchain` tests we need to fix.\n\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCo-authored-by: @DiegoCivi",
          "timestamp": "2025-05-19T19:55:34Z",
          "tree_id": "f402baf6112c7625c0542bd74bb503df650c4d04",
          "url": "https://github.com/lambdaclass/ethrex/commit/9ba8270b2edadec13496080446025cd3b0eabf80"
        },
        "date": 1747687789799,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 214134354799,
            "range": "± 1067686701",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c716b18ae0ee577eb9cc3889f70d152eb48e535c",
          "message": "fix(l1): add deposit request layout validations + return invalid deposit request error (#2832)\n\n**Motivation**\nCurrently, when we fail to parse a deposit request we simply ignore it\nand keep the rest of the deposits, relying on the request hash check\nafterwards to notice the missing deposit request. This PR handles the\nerror earlier and returns the appropriate `InvalidDepositRequest Error`.\nThis will provide better debugging information and also more accurate\ntesting via tools such as `execution-spec-tests` which rely on specific\nerror returns.\nWe also were not correctly validating the layout according to the\n[EIP](https://eips.ethereum.org/EIPS/eip-6110), as we were only checking\nthe total size and not the size and offset of each request field\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Check that the full layout of deposit requests is valid (aka the\ninternal sizes and offsets of the encoded data)\n* Handle errors when parsing deposit requests\n* Check log topic matches deposit topic before parsing a request as a\ndeposit request\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nAllows us to address review comment made on execution-specs-test PR\nhttps://github.com/ethereum/execution-spec-tests/pull/1607 + also closes\n#2132",
          "timestamp": "2025-05-19T21:11:46Z",
          "tree_id": "2de9920ba534f744b1f08be38261693601826892",
          "url": "https://github.com/lambdaclass/ethrex/commit/c716b18ae0ee577eb9cc3889f70d152eb48e535c"
        },
        "date": 1747692381524,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 210538713831,
            "range": "± 1176933805",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d73297f8624033d59c07ba887a007fe20071702c",
          "message": "feat(l1): add rpc endpoint admin_peers (#2732)\n\n**Motivation**\nSupport rpc endpoint `admin_peers`\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add rpc endpoint `admin_peers`\n* Track inbound connections \n* Store peer node version when starting a connection\n* Add `peer_handler: PeerHandler` field to `RpcContext` so we can access\npeers from the rpc\n* (Misc) `Syncer` & `SyncManager` now receive a `PeerHandler` upon\ncreation instead of a `KademliaTable`\n* (Misc) Fix common typo across the project\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\nData missing compared to geth implementation:\n* The local address of each connection\n* Whether a connection is trusted, static (we have no notion of this\nyet)\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2671",
          "timestamp": "2025-05-20T13:40:51Z",
          "tree_id": "1b839813ccf9db83001f1616c569634442f3aee3",
          "url": "https://github.com/lambdaclass/ethrex/commit/d73297f8624033d59c07ba887a007fe20071702c"
        },
        "date": 1747751688870,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 213261044004,
            "range": "± 1017060397",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "90105443+DiegoCivi@users.noreply.github.com",
            "name": "DiegoC",
            "username": "DiegoCivi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f691b847aff49587887b0e45c513a659f01875af",
          "message": "feat(l1): add eest hive tests to daily report (#2792)\n\n**Motivation**\n\nHave a better way to visualize the results from the execution of the EF\nblockchain tests using Hive.\n\n**Description**\n\nHive daily report now also runs the simulators\n`ethereum/eest/consume-engine` and `ethereum/eest/consume-rlp` with the\nblockchain fixtures of the `execution-spec-tests`. The version of the\nfixtures is taken from `cmd/ef_tests/blockchain/.fixtures_url`.\nThis was also talked in #2474. \n\nCloses #2746 and part of #1988",
          "timestamp": "2025-05-20T14:12:09Z",
          "tree_id": "5b0908e689956af280c60bb0a78562d489cc5fd0",
          "url": "https://github.com/lambdaclass/ethrex/commit/f691b847aff49587887b0e45c513a659f01875af"
        },
        "date": 1747753541522,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 211581166813,
            "range": "± 470956486",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "75658dc1e810b6f8712d44c4cdee3634367e7e20",
          "message": "chore(l2): don't init metrics for l1 when using make init (#2849)\n\n**Motivation**\n\nWhen starting l1 with `make init` or `make restart` the l1 node started\n2 more containers for prometheus + graphana. We don't care for the l1\nmetrics neither in development nor in production for l2 so we want to\nremove it\n\n**Description**\n\n- Build \"dev\" docker image without metrics feature\n- Remove include of `../metrics/docker-compose-metrics.yaml` file in\n`docker-compose-dev.yaml`\n- Remove metrics port from `docker-compose-dev.yaml`\n- Delete `docker-compose-metrics-l1-dev.overrides.yaml` file\n- Remove `docker-compose-metrics-l1-dev.overrides.yaml` from makefile\n\n\nCloses #2554",
          "timestamp": "2025-05-20T14:26:32Z",
          "tree_id": "a006830bcc4c1ba2927f6e276fd247fc0e5d97da",
          "url": "https://github.com/lambdaclass/ethrex/commit/75658dc1e810b6f8712d44c4cdee3634367e7e20"
        },
        "date": 1747754408660,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 209396132972,
            "range": "± 960550699",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "git@edgl.dev",
            "name": "Edgar",
            "username": "edg-l"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8afdb49fb6d357fa14dffd14e094d545e25a633c",
          "message": "chore(l1,l2): remove double Arc and Mutex from metrics (#2847)\n\n**Motivation**\n\nThe underlying Gauges are already thread safe and behind Arcs\ninternally, so the used Arc and Mutex wrapper were useless overhead.\n\n<!-- Why does this pull request exist? What are its goals? -->\n\nThe types in the library derive from\n\n```\npub struct GenericCounter<P: Atomic> {\n    v: Arc<Value<P>>,\n}\n```\n\nWhich is clone safe, furthermore P is atomic so it doesnt need a lock.\n\n**Description**\n\nRemove unused Mutex and Arc\n\nCloses #issue_number",
          "timestamp": "2025-05-20T14:56:34Z",
          "tree_id": "17ed1717dd6dcf7dd880049a12dcbf92ec4add4a",
          "url": "https://github.com/lambdaclass/ethrex/commit/8afdb49fb6d357fa14dffd14e094d545e25a633c"
        },
        "date": 1747756217764,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 211429844662,
            "range": "± 395892748",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a49cb6c6ff7f1e852a73b360553a17ee91d812e6",
          "message": "feat(core): add fallback url for EthClient (#2826)\n\n**Motivation**\n\nIn case the first rpc endpoint fails we want to have a second option. \n\n**Description**\n\n- Parse `eth-rpc-url` as a list of comma separated urls\n- Add logic to EthClient to retry with all rpc-urls if a request fails\n\n**How to test**\n\n```\ncargo run --release --manifest-path ../../Cargo.toml --bin ethrex --features \"l2,rollup_storage_libmdbx,metrics\" -- \\\n\tl2 init \\\n\t--eth-rpc-url \"http://aaaaaa\" \"http://localhost:8545\"  \\\n\t--watcher.block-delay 0 \\\n\t--network ../../test_data/genesis-l2.json \\\n\t--http.port 1729 \\\n\t--http.addr 0.0.0.0 \\\n\t--evm levm \\\n\t--datadir dev_ethrex_l2 \\\n\t--bridge-address 0x13a07379d93a0cf8c0c84e8e9cc31deab0da3ef0 \\\n\t--on-chain-proposer-address 0x628bb559d2bc6fdb402f7f1293f5aba689586189 \\\n\t--proof-coordinator-listen-ip 127.0.0.1\n```\n\n---------\n\nCo-authored-by: Manuel Iñaki Bilbao <manuel.bilbao@lambdaclass.com>",
          "timestamp": "2025-05-20T16:06:23Z",
          "tree_id": "3732e74370007342aebc2f6f520997d2c25d6e0c",
          "url": "https://github.com/lambdaclass/ethrex/commit/a49cb6c6ff7f1e852a73b360553a17ee91d812e6"
        },
        "date": 1747760386046,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 210711341179,
            "range": "± 510317707",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "git@edgl.dev",
            "name": "Edgar",
            "username": "edg-l"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "415a46dacc1ff5a9609e82df661643f9e1c05ee6",
          "message": "fix(core): fix load test not running properly (#2851)\n\n**Motivation**\n\nDue to changes to gas estimation the load test had to call estimage gas\na lot which slowed downn the load test \"setup\". Also increased the\nmax_fee_per_gas which was lowered in recent commits by mistake.",
          "timestamp": "2025-05-20T16:23:12Z",
          "tree_id": "74b4b1d6f118e8394b6eba3e1477c95a7c035326",
          "url": "https://github.com/lambdaclass/ethrex/commit/415a46dacc1ff5a9609e82df661643f9e1c05ee6"
        },
        "date": 1747761400440,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 210656545842,
            "range": "± 363645195",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "252d67040cc232e6f440f89daf5c4fc9f437ccd6",
          "message": "feat(l2): hardcode SP1 verification key (#2708)\n\n**Motivation**\n\nInstead of sending it as a parameter, it will be set as a contract\nstatic variable.\n\nAlso makes sp1 build in docker for reproducibility (and so the key\ndoesn't change depending on the platform we're building)\n\n---------\n\nCo-authored-by: ilitteri <ilitteri@fi.uba.ar>\nCo-authored-by: Ivan Litteri <67517699+ilitteri@users.noreply.github.com>\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>\nCo-authored-by: Manuel Iñaki Bilbao <manuel.bilbao@lambdaclass.com>",
          "timestamp": "2025-05-20T16:43:49Z",
          "tree_id": "34aca3ca7e81d3b11445d24e932f5b35b63ffeb6",
          "url": "https://github.com/lambdaclass/ethrex/commit/252d67040cc232e6f440f89daf5c4fc9f437ccd6"
        },
        "date": 1747762702051,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 213412236099,
            "range": "± 816074682",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c47725143e35457f53d360c0fa5b28524a954b45",
          "message": "feat(l2): add cli option to compute genesis state root (#2843)\n\n**Motivation**\n\nAdd a subcommand to compute a state root given a genesis file path\n\n**Description**\n\n* Add new variant to `Subcommand` struct called `ComputeStateRoot`\n* It has a required argument for the file path\n* Calls the existing function `pub fn compute_state_root(&self) -> H256`\n\n**How to use**\n\nrun:\n`cargo run --bin ethrex --release -- compute-state-root --path\ntest_data/genesis-l2.json`",
          "timestamp": "2025-05-20T17:22:33Z",
          "tree_id": "f848b297ae239f9faf7cd29924fb693b26ad7486",
          "url": "https://github.com/lambdaclass/ethrex/commit/c47725143e35457f53d360c0fa5b28524a954b45"
        },
        "date": 1747764997895,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 212577407430,
            "range": "± 930782910",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "30327624+mechanix97@users.noreply.github.com",
            "name": "Mechardo",
            "username": "mechanix97"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7c00fdc269a97c28fcdf849a01e73d424dce188f",
          "message": "feat(l1): capability negotation (#2840)\n\n**Motivation**\n\nMultiple version of the same protocol can be used when a connection is\nestablished(eth/68 and eth/69 for example). At the moment, we can only\nuse one protocol version.\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\nA vec of capability is used to pass multiple versions of the protocol to\nsome functions.\n\nThe struct RLPxConnection now stores capabilities struct instead of\nnumbers.\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-05-20T17:59:33Z",
          "tree_id": "2b5317048d54657af96870ce3ef27eafcf16643c",
          "url": "https://github.com/lambdaclass/ethrex/commit/7c00fdc269a97c28fcdf849a01e73d424dce188f"
        },
        "date": 1747767208891,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 211690851599,
            "range": "± 733654972",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e9b7de232230f24a6632d495b08dcf50d47f5c69",
          "message": "fix(l2): correct private key for load test account (#2837)\n\n**Motivation**\n\nAfter the changes introduced in #2781. The rich account needed for the\nload test no longer has funds to make the deploy and the transactions.\n\n**Description**\n\nChange the private key to one of the rich accounts that is used on the\ninitial deposit in the deployment of the L2\n\n**How to test**\n\nRunning: `cargo run --manifest-path ../../cmd/load_test/Cargo.toml -- -k\n../../test_data/private_keys.txt -t erc20 -N 50 -n\nhttp://localhost:1729`\n\nThis won't lead to panic.\n\nBut in main we get:\n```\nERC20 Load test starting\nDeploying ERC20 contract...\nthread 'main' panicked at cmd/load_test/src/main.rs:358:18:\nFailed to deploy ERC20 contract: eth_sendRawTransaction request error: Invalid params: Account does not have enough balance to cover the tx cost\n\nCaused by:\n    Invalid params: Account does not have enough balance to cover the tx cost\n```",
          "timestamp": "2025-05-20T18:51:24Z",
          "tree_id": "d4100a43ca2cfb2a1430792e48679a5b19938fcb",
          "url": "https://github.com/lambdaclass/ethrex/commit/e9b7de232230f24a6632d495b08dcf50d47f5c69"
        },
        "date": 1747770373896,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 212906341589,
            "range": "± 438632939",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomas.arjovsky@lambdaclass.com",
            "name": "Tomás Arjovsky",
            "username": "Arkenan"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "ee21522c5b196f07b3703a6d0b857d52cd4c094d",
          "message": "fix(core): remove eager rpc calls calls from eth client (#2862)\n\nThe eth client was calling gas price and max gas price even if the\noverrides where set. That heavily impacted load test in particular, but\nit also made overrides pointless. With this small change, the RPC calls\nare only called in the case that overrides are not provided.",
          "timestamp": "2025-05-21T11:56:05Z",
          "tree_id": "6a1798b38ae4a9f3891000a01ca100b75cc34c28",
          "url": "https://github.com/lambdaclass/ethrex/commit/ee21522c5b196f07b3703a6d0b857d52cd4c094d"
        },
        "date": 1747831791940,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 212139353641,
            "range": "± 1410246785",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "onoratomatias@gmail.com",
            "name": "Matías Onorato",
            "username": "mationorato"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "2dc43bdb26b36745beee89bbe2cf650ba3017e88",
          "message": "fix(l2): change the reentrancyguard for its upgradable version. (#2861)\n\n**Motivation**\nThis pr is needed to pass all the verification that foundry runs for\nupgradable contracts.",
          "timestamp": "2025-05-21T12:58:26Z",
          "tree_id": "dbba6063e5fba6a6d8c41afec6ce51666d4706e6",
          "url": "https://github.com/lambdaclass/ethrex/commit/2dc43bdb26b36745beee89bbe2cf650ba3017e88"
        },
        "date": 1747835602022,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 214562932298,
            "range": "± 491263154",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "90105443+DiegoCivi@users.noreply.github.com",
            "name": "DiegoC",
            "username": "DiegoCivi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1b9f5ddafebe57842533688a304c9112efd351c0",
          "message": "fix(l1,l2): fix Succint dependency error on cargo check (#2835)\n\n**Motivation**\n\nWe were excluding `ethrex-prover-bench` when doing `cargo check\n--workspace` because it failed when `succinct` was not instaled.\n\n**Description**\n\n- `sp1` feature was removed from the default features of\n`ethrex-prover-bench`.\n- After doing the step above, `cargo check --workspace` could be ran and\nsome errors and warnings appeared and they were fixed.\n- '--exclude ethrex-prover-bench' was removed from the L1 ci job\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2807",
          "timestamp": "2025-05-21T14:40:45Z",
          "tree_id": "59764f890d4872bf4fd2da6be07cd003cea8f0df",
          "url": "https://github.com/lambdaclass/ethrex/commit/1b9f5ddafebe57842533688a304c9112efd351c0"
        },
        "date": 1747841752019,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 211973101371,
            "range": "± 448608238",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "6871f6173327d11f7598a8244ee9c932304f96c9",
          "message": "fix(l1,l2): add load test erc20 rich account to genesis-load-test.json (#2863)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number\n\nCo-authored-by: Tomás Arjovsky <tomas.arjovsky@lambdaclass.com>",
          "timestamp": "2025-05-21T15:37:11Z",
          "tree_id": "3ac85fcf280153478dd48954da72318078de60cb",
          "url": "https://github.com/lambdaclass/ethrex/commit/6871f6173327d11f7598a8244ee9c932304f96c9"
        },
        "date": 1747845055954,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 211013439012,
            "range": "± 822502991",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "44068466+SDartayet@users.noreply.github.com",
            "name": "SDartayet",
            "username": "SDartayet"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "6632b444196cef4e4f1e42e5efc271d14c24924a",
          "message": "refactor(levm): remove clones for account structs (#2684)\n\n**Motivation**\n\nImproving the performance of some cases by avoiding clones where\npossible.\n\n**Description**\n\nMany clones of account structs were removed. This involved changing the\noutput of the get_account and access_account functions of the DB to\nreturn a reference to an account, as well as refactorings of the code\nwhich involved these functions.\n\nResolves [#2611](https://github.com/lambdaclass/ethrex/issues/2611)",
          "timestamp": "2025-05-21T15:54:24Z",
          "tree_id": "1a5b4b17da28e1279bf36b26779e3f2519b7d32e",
          "url": "https://github.com/lambdaclass/ethrex/commit/6632b444196cef4e4f1e42e5efc271d14c24924a"
        },
        "date": 1747846097441,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 209766881646,
            "range": "± 1045219723",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "17429160f3e67e8e377a9f9b574c02c3f9db02c5",
          "message": "ci(l2): fix L2 sp1 prover integration test steps were skipped on merge to main (#2865)\n\n**Motivation**\n\nFix broken ci\n\n**Description**\n\n- Comment conditional running that only run the steps on the merge queue\n- Left comment with TODO to uncomment when we re enable this job in the\nmerge queue",
          "timestamp": "2025-05-21T15:55:59Z",
          "tree_id": "746b79b3607a83946cf3bdf82ed0542e3bd7aa17",
          "url": "https://github.com/lambdaclass/ethrex/commit/17429160f3e67e8e377a9f9b574c02c3f9db02c5"
        },
        "date": 1747846225103,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 210896190171,
            "range": "± 446850687",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "90105443+DiegoCivi@users.noreply.github.com",
            "name": "DiegoC",
            "username": "DiegoCivi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c6a54c2fb71fc708a49951772cd2690d60279103",
          "message": "refactor(l1): move hash from Block to BlockHeader (#2845)\n\n**Motivation**\n\n`Block` had the hash but the `BlockHeader` didn't so they had to be\npassed along together.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\nMove the hash into `BlockHeader`, making it accesible to it and also to\n`Block`\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2841",
          "timestamp": "2025-05-21T18:09:33Z",
          "tree_id": "c3bc3581590268a1d555692e2548944d0e85e580",
          "url": "https://github.com/lambdaclass/ethrex/commit/c6a54c2fb71fc708a49951772cd2690d60279103"
        },
        "date": 1747854250830,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 210760041948,
            "range": "± 432894153",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "171076f9a71b02beb9a852bad96fb062aaca9ee6",
          "message": "fix(levm): fix eip 7702 logic around touched_accounts (#2859)\n\n**Motivation**\n\n- Fix error when executing a transaction of a block when syncing Holesky\nin Prague by chaning behavior of the EVM.\n\n**Description**\n\n- We now set `code_address` and `bytecode` at the end of\n`prepare_execution`. It's necessary because of EIP-7702.\n- We change the place in which we add the delegated account to\n`touched_accounts` → **CORE CHANGE**\n- Change some outdated comments related to EIP7702 functions.\n- Change `get_callee_and_code` to `get_callee` because we don't need the\ncode before `prepare_execution` and this is assigned afterwards.\n- Create `set_code` function to CallFrame so that we calculate jump\ndestinations everytime we want to set the code, because it's always\nnecessary.\n\n\n**In depth explanation: What was wrong with this transaction?**\nThe gas diff was 2000 between LEVM and REVM, but doing some math we\nfound out that the actual gas diff before refunds was 2500. The access\ncost of accessing a COLD Address is 2600 and the cost of accessing a\nWARM address is 100. 2600-100 = 2500. That's the difference between LEVM\nand REVM, but where is it?\nReading EIP-7702 and analyzing our behavior made me realize:\n(Capital Letters here are accounts)\n- Transaction: A → B\n- B had C as delegate account at the beginning of the transaction so we\nadd C to the `touched_accounts`.\n- Transaction authority list sets B to have D as delegate, so that it's\nnot C anymore.\n- During execution we make internal calls to C\n- Our VM thinks C is in `touched_accounts` (that means warm) and\nconsumes 100 gas when accessing it instead of 2600.\n\nSolution? Changing the moment in which we add the delegate account to\n`touched_accounts`, so that we do it after the authorization list was\nprocessed.",
          "timestamp": "2025-05-21T20:53:49Z",
          "tree_id": "e7f6d045a970f8dc5679432499730b674980c601",
          "url": "https://github.com/lambdaclass/ethrex/commit/171076f9a71b02beb9a852bad96fb062aaca9ee6"
        },
        "date": 1747864057259,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 211086403479,
            "range": "± 1561907584",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "francisco.gauna@lambdaclass.com",
            "name": "fedacking",
            "username": "fedacking"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "490cd625706c1f8d70e3a986178f149f4a710c72",
          "message": "fix(l1): added checks to newpayload and forkchoiceupdated (#2831)\n\n**Motivation**\n\nThis should fix some sync and inconsistent behaviour problems with the\nhive engine tests. The problem was happening when a sync process had\nbegun, and a block from that sync process entered the server. Some\nchecks for that scenario have been added.\n\nAlso made some tests in the CI easier to read and edit, while adding a\ncouple of them.\n\n**Description**\n\n- Made the CI tests have 1 by 1.\n- Added some fixed CI tests to \"Paris Engine tests\" and \"Engine\nwithdrawal tests\"\n- Added a check to forkchoiceupdatet for the body to be present before\nforking.\n- Added a check to execute_payload for the body of the parent to be\npresent before executing.\n\nFixes some tests in #1285",
          "timestamp": "2025-05-22T14:56:41Z",
          "tree_id": "89459d91933857f8d155c9eaebc56e7b7466dc1e",
          "url": "https://github.com/lambdaclass/ethrex/commit/490cd625706c1f8d70e3a986178f149f4a710c72"
        },
        "date": 1747929019645,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 213378710035,
            "range": "± 744251123",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "128638963+santiago-MV@users.noreply.github.com",
            "name": "santiago-MV",
            "username": "santiago-MV"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1094c2dbdd37a925fa591b6a9816e319285be18c",
          "message": "fix(l1,l2): solved make install-cli problem (#2873)\n\n**Motivation**\n\nWhile trying to run the `make install-cli` command it failed.\n\n**Description**\n\nThe problem was that the libmdbx crate was trying to install the 0.5.4\n(not the one in the `Cargo.lock` file) version which needs a version of\nrust with the feature \"edition2024\", that is estable after the 1.85.0\nversion (Ethrex is using 1.82.0).\nI found two solutions:\n1. Upgrading the rust version to 1.85.0 in the `.tool-versions` file\n2. Adding `--locked` flag to the makefile command\n\nThe first one may introduce more problems on the code. The second one\nensures that the `cargo install` command, called by `make`, installs the\nversions specified in the `Cargo.lock` file, solving the error.\nWith this change the `make install-cli` command installs the ethrex l2\ncli (As said in the makefile).\n\nCloses #2870",
          "timestamp": "2025-05-22T15:05:54Z",
          "tree_id": "8a032ec52af4e5bae77d3c35b8fdbbbb5eeecaf0",
          "url": "https://github.com/lambdaclass/ethrex/commit/1094c2dbdd37a925fa591b6a9816e319285be18c"
        },
        "date": 1747929642321,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 214976557852,
            "range": "± 821463712",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "rodrigooliveri10@gmail.com",
            "name": "Rodrigo Oliveri",
            "username": "rodrigo-o"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7e49b4bab352ace4b8733dd8001876897dc97ddd",
          "message": "chore(l1): reduce p2p error and info logs (#2885)\n\n**Motivation**\n\nWhen running the node, even without `debug` the logs are pretty\ndifficult to follow, specially due to p2p errors and infos\n\n**Description**\n\nMake every individual peer error use `debug` instead of `error` level\n(except for boradcasting issues) and remove the capabilities negotiated\n`info` level log.\n\n#### Logs Before\n\n\n![image](https://github.com/user-attachments/assets/c99aef44-e02f-494d-bd5c-7a27169be388)\n\n\n#### Logs After\n\n\n![image](https://github.com/user-attachments/assets/8373aab5-3b99-4c35-ae3a-fc32ebc0067f)",
          "timestamp": "2025-05-22T16:01:51Z",
          "tree_id": "c7d55c32e3873527f51915da40ac280d8958c2e0",
          "url": "https://github.com/lambdaclass/ethrex/commit/7e49b4bab352ace4b8733dd8001876897dc97ddd"
        },
        "date": 1747932931177,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 211028602464,
            "range": "± 696217113",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3e81f78fbb4d1cd47792061ea1bff6d85b15ce7a",
          "message": "chore(levm): update state tests and make state use blockchain's tests (#2871)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n- Update blockchain tests from 4.3.0 to 4.5.0\n- Update state tests from pectra-devnet-6 to 4.5.0\n- Remove tests from old forks (Constantinople folder)\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-22T16:15:49Z",
          "tree_id": "628b4809bf03af7da9ffefd81477a85c8e5135ec",
          "url": "https://github.com/lambdaclass/ethrex/commit/3e81f78fbb4d1cd47792061ea1bff6d85b15ce7a"
        },
        "date": 1747933827574,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 212317936276,
            "range": "± 479501841",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "cdbe4c3cd238347a7dfb3239b42e8baee7af8a94",
          "message": "feat(l2): integrate TDX as a prover (#2777)\n\n**Motivation**\n\nIn #2677 an example of a TDX-based prover was made. This uses the\nexample code to add a prover.\n\n**Description**\n\nTDX is added as another prover, and made to use the same API",
          "timestamp": "2025-05-22T17:58:19Z",
          "tree_id": "2c6135aba5bdeafe913896d19b14108ce6481dd6",
          "url": "https://github.com/lambdaclass/ethrex/commit/cdbe4c3cd238347a7dfb3239b42e8baee7af8a94"
        },
        "date": 1747939938942,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 210622538381,
            "range": "± 625186045",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "90105443+DiegoCivi@users.noreply.github.com",
            "name": "DiegoC",
            "username": "DiegoCivi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e4dd54a99730972916d45e30f91a960f05be57ed",
          "message": "refactor(l1): add hiveview creation when running hive tests (#2883)\n\n**Motivation**\n\nRun the hiveview as default when running hive tests for a better\nvisualization\n\n**Description**\n\nNew makefile target that builds and executes the hiveview with the logs\ncreated when running hive tests\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-05-22T18:30:06Z",
          "tree_id": "80b1403e1be01e3578533bf335d7913cf90230af",
          "url": "https://github.com/lambdaclass/ethrex/commit/e4dd54a99730972916d45e30f91a960f05be57ed"
        },
        "date": 1747941858430,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 213865795858,
            "range": "± 411569545",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "689e1834d99a3e8213f882f6473e4486e67b683d",
          "message": "feat(l1): add `mempool_content` rpc endpoint (#2869)\n\n**Motivation**\nAdds an RPC method that allows reading all transactions currently in the\nmempool.\nThis endpoint was based off of Geth's `txpool_content` endpoint\n([doc](https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-txpool#txpool-content))\nand follows the same response logic & format.\nAs we have no notion of `queued` mempool transactions currenlty, this\nfield will be permanently left empty\nThe namescape and endpoint currently uses `txpool` instead of `mempool`\nfor immediate compatibility with components compatible with geth, we\nshould consider changing the name back to `mempool` to reflect our own\ntypes as this is not a standard endpoint and names differ between\nimplementations.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add `Mempool::content` method which returns all transactions\n* Add `mempool_content` rpc endpoint which returns all mempool\ntransactions grouped by sender and indexed by nonce\n* (Misc) `RpcTransaction::build` now supports optional transaction index\n& block number\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2864",
          "timestamp": "2025-05-22T19:25:23Z",
          "tree_id": "7fdf73b3229d752e83bf3d73518f067a4aeb438c",
          "url": "https://github.com/lambdaclass/ethrex/commit/689e1834d99a3e8213f882f6473e4486e67b683d"
        },
        "date": 1747945166194,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 213321919656,
            "range": "± 550308900",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "657ba027088cf61604dde6559b4727f27af5f11c",
          "message": "perf(l2): remove cloning state for limiting batch size (#2825)\n\n**Motivation**\n\nIn this PR we remove the cloning of the context before executing every\ntransaction to check if it doesn't exceed the state diff size limit.\n\n**Description**\n\n* Add new functions specific for the L2 `apply_transaction_l2` and\n`execute_tx_l2`.\n* Now `apply_transaction_l2` returns a CallFrameBackup that is needed\nfor reverting the changes made by the transaction. This revert is\ndifferent from the transaction revert, this has to undo every\nmodification even the pre execute validation changes.\n* Simplify the encoding of the structs `WithdrawalLog`, `DepositLog`,\n`BlockHeader` and `AccountStateDiff` when calculating the StateDiff.\nThis leads to better consistency and being less error prone to future\nchanges.\n* Expose the VM function to restore the state from a `CallFrameBackup`.\n\n**Comparison against main**\nHow to replicate:\nInside `crates/l2`\n- Terminal 1: `init-l1`\n- Terminal 2: `make deploy-l1 update-system-contracts init-l2`\n- Terminal 3: `cargo run --manifest-path ../../cmd/load_test/Cargo.toml\n-- -k ../../test_data/private_keys.txt -t erc20 -N 50 -n\nhttp://localhost:1729`\n\nFor Terminal 3 if necessary run `ulimit -n 65536` before the command.\n\nGigagas comparison:\nmain: `[METRIC] BLOCK BUILDING THROUGHPUT: 0.0028166668076660267\nGigagas/s TIME SPENT: 30733 msecs`\nthis PR: `BLOCK BUILDING THROUGHPUT: 0.3342272162162162 Gigagas/s TIME\nSPENT: 259 msecs`\n\nLoadtest comparision:\nmain: `Load test finished. Elapsed time: 254 seconds`\nthis PR: `Load test finished. Elapsed time: 34 seconds`\n\nCloses #2413 \nCloses #2655\n\n---------\n\nCo-authored-by: Avila Gastón <72628438+avilagaston9@users.noreply.github.com>",
          "timestamp": "2025-05-22T19:38:28Z",
          "tree_id": "28e499a32519baff9ecf2d2196070b3d817ccb60",
          "url": "https://github.com/lambdaclass/ethrex/commit/657ba027088cf61604dde6559b4727f27af5f11c"
        },
        "date": 1747945944618,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 211303410426,
            "range": "± 1101724722",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9899326156309274fcc9c87d7342d99eba76c10a",
          "message": "refactor(l2): remove all based features (#2868)\n\n**Motivation**\n\nWe want to remove all based features in the project\n\n**Description**\n\n* All feature flags `based` were removed.\n* All functions related to specific behavior from based rollups were\nremoved",
          "timestamp": "2025-05-22T20:23:03Z",
          "tree_id": "3aeb6e6f4a7437120359898134d69aac80277ea3",
          "url": "https://github.com/lambdaclass/ethrex/commit/9899326156309274fcc9c87d7342d99eba76c10a"
        },
        "date": 1747948622466,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 212357885815,
            "range": "± 911239814",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "francisco.gauna@lambdaclass.com",
            "name": "fedacking",
            "username": "fedacking"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4c9fcfa179fb41f534e3faec1bd25926adafa266",
          "message": "ci(core): updating hive revision (#2881)\n\n**Motivation**\n\nIn our lambdaclass/hive fork, we have updated upstream. When [that\nPR](https://github.com/lambdaclass/hive/pull/28) is merged, we should\nupdate the branch name here and test it.\n\n**Description**\n\n- Updates the hive revision\n- Also updates \"HIVE_SHALLOW_SINCE\"\n\nCloses #2760",
          "timestamp": "2025-05-22T21:53:50Z",
          "tree_id": "661efb1c7f5fc50738bff485277f2d818b33d71a",
          "url": "https://github.com/lambdaclass/ethrex/commit/4c9fcfa179fb41f534e3faec1bd25926adafa266"
        },
        "date": 1747954078428,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 209919577170,
            "range": "± 354279090",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "90105443+DiegoCivi@users.noreply.github.com",
            "name": "DiegoC",
            "username": "DiegoCivi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "63fd78dc5cad5e912a3320b39fed69d471007f1f",
          "message": "refactor(l1): move AccountUpdate to common crate (#2867)\n\n**Motivation**\n\nReduce coupling between crates ethrex_storage and ethrex_vm\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n- Move `account_update.rs` from `storage` to `common/types`\n- Fix imports\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2852",
          "timestamp": "2025-05-23T13:29:25Z",
          "tree_id": "35ed7c318e0057fc38603007251d6e9ccfe29d44",
          "url": "https://github.com/lambdaclass/ethrex/commit/63fd78dc5cad5e912a3320b39fed69d471007f1f"
        },
        "date": 1748010221282,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 213889778540,
            "range": "± 681049907",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "152b43c2cf6a5b919f4f225c3c73807ca075f8a3",
          "message": "chore(levm): remove unnecessary spurious dragon check when adding blocks in batch (#2890)\n\n**Motivation**\n\n- We don't want to implement anything for forks previous than Paris, so\nthis can be deleted.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-23T14:31:30Z",
          "tree_id": "4256cc77a0942c2223903f710b68b848459a81a7",
          "url": "https://github.com/lambdaclass/ethrex/commit/152b43c2cf6a5b919f4f225c3c73807ca075f8a3"
        },
        "date": 1748014015428,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 220160572423,
            "range": "± 744367666",
            "unit": "ns/iter"
          }
        ]
      }
    ],
    "L1 block proving benchmark": [
      {
        "commit": {
          "author": {
            "name": "lambdaclass",
            "username": "lambdaclass"
          },
          "committer": {
            "name": "lambdaclass",
            "username": "lambdaclass"
          },
          "id": "6cb177c58b31935236ce1570021ed095ba8480d0",
          "message": "feat(l2): bench job",
          "timestamp": "2025-05-06T13:56:32Z",
          "url": "https://github.com/lambdaclass/ethrex/pull/2663/commits/6cb177c58b31935236ce1570021ed095ba8480d0"
        },
        "date": 1746543549179,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1 backend, GPU",
            "value": 0.0007203333174224343,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9faceb7cda8f4317ed9ea465aa2d38a49fe1ca50",
          "message": "fix(l1): support both `data` and `input` fields on `GenericTransaction` as long as they have the same value (#2685)\n\n**Motivation**\nIssue #2665 reported that some tools create transactions with both the\n`data` and `input` fields set to the same value, which is not currently\nsupported by our deserialization which admits only one. Other\nimplementations also support having both fields in their equivalent of\n`GenericTransaction`. This PR handles this case by adding a custom\ndeserialization that can parse both fields and check that they are equal\nif set to prevent unexpected behaviours.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Implement custom field deserialization so that both `input` & `data`\nfields are supported but deserialized as one\n* Add test case for the reported failure case\n* Use a non-trivial input for the current and added deserialization test\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2665",
          "timestamp": "2025-05-13T16:14:39Z",
          "tree_id": "4096c716b0add7c4617dfe56b24f76e6de3b2460",
          "url": "https://github.com/lambdaclass/ethrex/commit/9faceb7cda8f4317ed9ea465aa2d38a49fe1ca50"
        },
        "date": 1747156366508,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007372243771372741,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "cf1b0a811151ef84f5eee3832356fddbdf01b2db",
          "message": "feat(l2): prove deposits (#2737)\n\n> [!NOTE]\n> This is an updated version of #2209  from @xqft \n\n**Motivation**\n\nWe want to prove the L2 deposits in our prover\n\n**Description**\n\n- Add to `ProgramInput` and `ProverInputData` the field\n`deposit_logs_hash` the hash that is created by hashing the concatenated\ntransaction hashes from a batch of blocks to send to the prover\n- Inside the prover add logic to for every batch:\n- Gather the deposit tx hashes for each block from the block's\ntransactions.\n  - Calculate the logs hash the same way the l1_committer does\n  - Compare our resulting hash with the incoming from the `ProgramInput`\n\n\nCloses #2199\n\n---------\n\nCo-authored-by: Estéfano Bargas <estefano.bargas@fing.edu.uy>",
          "timestamp": "2025-05-13T16:45:04Z",
          "tree_id": "a0311c49b1691af7c96d595664f3d13217f2c8dc",
          "url": "https://github.com/lambdaclass/ethrex/commit/cf1b0a811151ef84f5eee3832356fddbdf01b2db"
        },
        "date": 1747159708978,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007419362340216323,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "20262dbd521ff694788b2739087a6965001b0bf8",
          "message": "chore(l2): remove default contract addresses from Makefile (#2769)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nContract addresses change frequently and they need to be changed in the\nMakefile.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nRemove the default values and read the addresses from the `.env` file,\nwhich are written by the deployer in case of using. In case you want to\nuse the `init-l2` flow without the deployer and the `.env` file, you\nhave to set the variables `BRIDGE_ADDRESS` and\n`ON_CHAIN_PROPOSER_ADDRESS` when running the target, else it will fail\nwith an error like `error: a value is required for '--bridge-address\n<ADDRESS>' but none was supplied`. For example:\n\n```sh\nmake init-l2 BRIDGE_ADDRESS=0x8ccf74999c496e4d27a2b02941673f41dd0dab2a ON_CHAIN_PROPOSER_ADDRESS=0x60020c8cc59dac4716a0375f1d30e65da9915d3f\n```\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-05-13T17:26:45Z",
          "tree_id": "90a0c46f8a377e45e8167cb92d9f0d0811c70458",
          "url": "https://github.com/lambdaclass/ethrex/commit/20262dbd521ff694788b2739087a6965001b0bf8"
        },
        "date": 1747163360703,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007379453789731051,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b0cdf7d0aadfc9e88fc204aa7b0c1bbae6221382",
          "message": "refactor(l1): rename ExecutionDB to ProverDB. (#2770)\n\n**Motivation**\nTo have a clearer name.",
          "timestamp": "2025-05-13T17:46:25Z",
          "tree_id": "fc5fe9ab4869c2c5a2ceb7db65e611b5fcfeb0eb",
          "url": "https://github.com/lambdaclass/ethrex/commit/b0cdf7d0aadfc9e88fc204aa7b0c1bbae6221382"
        },
        "date": 1747165596827,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007234411792905081,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "44068466+SDartayet@users.noreply.github.com",
            "name": "SDartayet",
            "username": "SDartayet"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "a1699859576100713a64b17d45ffa66e49597380",
          "message": "refactor(levm): decluttering vm.rs (#2733)\n\n**Motivation**\n\nMaking the code of the vm.rs file cleaner, since it's a bit cluttered\nright now.\n\n**Description**\n\nThe code of vm.rs is a bit messy right now. This PR moves EVM config to\nenvironment, moves a few attributes from environment to substate that\nmake more sense there, and removes the StateBackup struct since it's\nmade unnecessary by this change.\n\nCloses #2731, Closes #2717 \nResolves most of #2718\n\n---------\n\nCo-authored-by: JereSalo <jeresalo17@gmail.com>",
          "timestamp": "2025-05-13T18:45:14Z",
          "tree_id": "3b22d90177c95ac844d95c6f4ae34f98db195cd3",
          "url": "https://github.com/lambdaclass/ethrex/commit/a1699859576100713a64b17d45ffa66e49597380"
        },
        "date": 1747169062021,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007325719902912622,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e92418ed4dc8f915f603be49eadd192aeed78b27",
          "message": "feat(l2): make L1 contracts upgradeable (#2660)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nWe want the L1 contracts to be upgradeable so it's possible to fix bugs\nand introduce new features.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nChanged the contracts to follow the UUPS proxy pattern (from\nOpenZeppelin's library). The deployer binary now deploys both the\nimplementation and the proxy.\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-05-13T22:47:52Z",
          "tree_id": "78298de98b0eafc8acd0b8f9c26b625b05e8da60",
          "url": "https://github.com/lambdaclass/ethrex/commit/e92418ed4dc8f915f603be49eadd192aeed78b27"
        },
        "date": 1747179739395,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007441313116370809,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "bc79391f811cad4e744f294c95580bd48b6d6d5b",
          "message": "feat(l2): signature-based TDX (#2677)\n\n**Motivation**\n\nVerifying TDX attestations on-chain is expensive (~5M gas), so it would\nbe better to avoid them if possible\n\n**Description**\n\nBy generating a private key inside the TDX VM (where the host can't read\nit), attesting it's validity and then using it to sign updates it's\npossible to massively decrease gas usage.",
          "timestamp": "2025-05-14T12:50:56Z",
          "tree_id": "d9a51beed6c4778ec24646ce23d11ce277e5d30b",
          "url": "https://github.com/lambdaclass/ethrex/commit/bc79391f811cad4e744f294c95580bd48b6d6d5b"
        },
        "date": 1747230348293,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007430321516494338,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "garmasholeksii@gmail.com",
            "name": "GarmashAlex",
            "username": "GarmashAlex"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "3b6efc87ee15fb79bdd18f8a3cfb5f3ab55e2e30",
          "message": "refactor(l2): Remove redundant address derivation function in load_test (#2494)\n\n**Motivation**\n\nThis pull request addresses a TODO comment in the load_test code that\nsuggested moving the custom address derivation function to common\nutilities. Instead of duplicating functionality, we should leverage\nexisting code from the SDK to improve maintainability and consistency\nacross the codebase.\n\n**Description**\n\nThis PR removes a redundant implementation of Ethereum address\nderivation in the load_test tool by replacing it with the existing\nget_address_from_secret_key function from the L2 SDK. The changes\ninclude:\n- Removed the custom address_from_pub_key function that was marked with\na TODO comment\n- Added an import for get_address_from_secret_key from ethrex_l2_sdk\n- Updated all usages throughout the code to use the SDK function instead\n- Added proper error handling for the SDK function calls\n\n---------\n\nCo-authored-by: Tomás Paradelo <112426153+tomip01@users.noreply.github.com>\nCo-authored-by: Martin Paulucci <martin.c.paulucci@gmail.com>\nCo-authored-by: Tomás Arjovsky <tomas.arjovsky@lambdaclass.com>",
          "timestamp": "2025-05-14T14:30:11Z",
          "tree_id": "67f931ab8af0a738c16e13d99c109f4b621642bf",
          "url": "https://github.com/lambdaclass/ethrex/commit/3b6efc87ee15fb79bdd18f8a3cfb5f3ab55e2e30"
        },
        "date": 1747236319152,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.000742301180521397,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "77f7dd4e48ad8008818e9067e9e82e99131e109b",
          "message": "refactor(l2): replace prover config toml with CLI flags (#2771)\n\n**Motivation**\n\nWe want to replace the .toml file used to configure the prover with a\ncli\n\n**Description**\n\n- Remove all the code related to reading toml files\n- Implement a struct ProverClientOptions that adds CLI options for the\nprover\n\n**How to test**\n\nIf you are in a dev environment, keep working as usual because under the\nhood, the sequencer initialization is not relying anymore on the\nprover_client_config.toml.\n\nIf you are in a prod environment, inside `crates/l2/prover` run `cargo\nrun --release -- --help` to explore the different configuration flags\nthis PR adds.\n\nCloses #2576",
          "timestamp": "2025-05-14T16:51:47Z",
          "tree_id": "39aa5a67946e692e9d0627237e8ad29578479091",
          "url": "https://github.com/lambdaclass/ethrex/commit/77f7dd4e48ad8008818e9067e9e82e99131e109b"
        },
        "date": 1747244877176,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.000739754068627451,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "onoratomatias@gmail.com",
            "name": "Matías Onorato",
            "username": "mationorato"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "ac0b378a346cbadec43a1a4464f58d1524a93c6d",
          "message": "fix(l2): remove rich wallets from l2 genesis (#2781)\n\n**Motivation**\nRemove no longer needed rich wallets from l2 genesis file\n\n---------\n\nCo-authored-by: Leandro Serra <leandro.serra@lambdaclass.com>\nCo-authored-by: Javier Chatruc <jrchatruc@gmail.com>\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>",
          "timestamp": "2025-05-14T17:09:35Z",
          "tree_id": "283b1c9d6bca4d5952c4808241396bfcb84bdcc3",
          "url": "https://github.com/lambdaclass/ethrex/commit/ac0b378a346cbadec43a1a4464f58d1524a93c6d"
        },
        "date": 1747248308991,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.000738306409001957,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9779033a81150bc1975cf5d8bcab701935fca5c9",
          "message": "refactor(l1): rename incorrect usage of `node_id` to `public_key` (node_id refactor 1/3) (#2778)\n\n**Motivation**\nOur implementation of `Node` stores the node's public key as `node_id`\nwhich is very confusing, as the `node_id` is the keccak256 hash of the\npublic key. This can lead to potential bugs and discrepancies with other\nimplementations where node_id is indeed the keccack hash of the public\nkey.\nFor this PR I left the public key as part of the Node but corrected its\nname to `public_key`, leaving all use cases as is.\nI also renamed some functions that mislabeled public key as node_id to\nbetter reflect what they do. The methods `id2pubkey` and `pubkey2id`\nconvert between the uncompressed (H512) and compressed (PubKey) versions\nof the same data so I renamed them to `compress_pubkey` and\n`decompress_pubkey`.\nI also added the method `node_id` to `Node` which returns the actual\nnode_id (aka the keccak252 hash of the public key).\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Rename various instances of `node_id` to `public_key`\n* Rename methods `id2pubkey` and `pubkey2id` to `compress_pubkey` and\n`decompress_pubkey`.\n* Add `Node` method `node_id`\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n**Potential Follow-Up work**\nCache node_id computation so we don't need to hash the public key on\nevery Kademlia table operation (#2786 + #2789 )\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2774",
          "timestamp": "2025-05-14T17:45:15Z",
          "tree_id": "9946ff2cca57f38af4c8bcfb8f19be9ad3532255",
          "url": "https://github.com/lambdaclass/ethrex/commit/9779033a81150bc1975cf5d8bcab701935fca5c9"
        },
        "date": 1747251624771,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007386677924620656,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e77e18db5b13cc888f1d7e29ec1cd898b3322e1f",
          "message": "fix(core): remove hardcoded gas_limits use eth_estimateGas (#2793)\n\n**Motivation**\n\nGas limit was hardcoded in some cases because we didn't have\neth_estimateGas implemented now we do so we want to use it when possible\n**Description**\n\n- Replace instances of hardcoded gas_limit and remove it as\n`build_xxxx_transaction` functions already estimate gas if the override\ndoes not include it\n- Set nonce to none when estimating the gas so that doesn't fail when\nsending multiple txs at the same time\n\n\nCloses #2782",
          "timestamp": "2025-05-14T20:04:57Z",
          "tree_id": "377ba81f14d36a331cac222a127f75e683e5eb4f",
          "url": "https://github.com/lambdaclass/ethrex/commit/e77e18db5b13cc888f1d7e29ec1cd898b3322e1f"
        },
        "date": 1747256491733,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007415716461916462,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "76521daffea5dfb35562c67903f4cbd028eeb77c",
          "message": "feat(l2): verify state roots (#2784)\n\n**Motivation**\n\nCurrently the OnChainProposer does not verify the initial and final\nstate roots contained in the program output.\n\n**Description**\n\nThe initial and state roots are verified, based on the commitment\nvalues. The genesis state root is added as a 0th block at initialization\ntime.\n\nCloses #2772",
          "timestamp": "2025-05-14T20:35:46Z",
          "tree_id": "41ad4be8fa147cf42bf27a250fb4b48692af9507",
          "url": "https://github.com/lambdaclass/ethrex/commit/76521daffea5dfb35562c67903f4cbd028eeb77c"
        },
        "date": 1747261723730,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007244831012962074,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "44068466+SDartayet@users.noreply.github.com",
            "name": "SDartayet",
            "username": "SDartayet"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b47623fdc8865f8e6f83857fccee1d74f145e03e",
          "message": "docs(levm): update levm readme (#2712)\n\n**Motivation**\n\nKeeping docs updated.\n\n**Description**\n\nThe README was severely out of date, specially the roadmap. This updates\nit to line up with the current project state and goals.\n\nCloses #2704\n\n---------\n\nCo-authored-by: Jeremías Salomón <48994069+JereSalo@users.noreply.github.com>\nCo-authored-by: Martin Paulucci <martin.c.paulucci@gmail.com>",
          "timestamp": "2025-05-14T21:21:08Z",
          "tree_id": "48e8dd7ddc3cfc5cd0de6bda26c06bd70643bd90",
          "url": "https://github.com/lambdaclass/ethrex/commit/b47623fdc8865f8e6f83857fccee1d74f145e03e"
        },
        "date": 1747267041595,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.000726226323387873,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "iovoid@users.noreply.github.com",
            "name": "Lucas Fiegl",
            "username": "iovoid"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "cba42cdcb2efcf1c3ab2fa204ccefffc1d37c5bf",
          "message": "fix(l2): fix indices (#2802)\n\n**Motivation**\n\nThere was an error in verifyPublicData when running with SP1\n\n**Description**\n\nverifyPublicData didn't take into account that SP1 contains a 16 byte\nheader with the length of the data",
          "timestamp": "2025-05-15T14:40:27Z",
          "tree_id": "2d57562e6595c57822ebc83a1859e79da4a8d56d",
          "url": "https://github.com/lambdaclass/ethrex/commit/cba42cdcb2efcf1c3ab2fa204ccefffc1d37c5bf"
        },
        "date": 1747324790549,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007386677924620656,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "francisco.gauna@lambdaclass.com",
            "name": "fedacking",
            "username": "fedacking"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c558c8db13a7f12dffe9cd13e979e0f551fbe6f0",
          "message": "fix(l1): lowered time for periodic tx broadcast interval (#2751)\n\n**Motivation**\n\nA test that involved multiple clients was failing due to the clients not\ncommunicating their transactions between them before the tests asked for\na new block.\n\n**Description**\n\nThis pr reduces the checking time from 5 seconds to 500 miliseconds and\nadds the test to the CI.\n\nFixes \"Blob Transaction Ordering, Multiple Clients\" failing test in\n#1285.",
          "timestamp": "2025-05-15T14:50:55Z",
          "tree_id": "50badb1b21a128e454143540cf788d626270200a",
          "url": "https://github.com/lambdaclass/ethrex/commit/c558c8db13a7f12dffe9cd13e979e0f551fbe6f0"
        },
        "date": 1747328106075,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007372243771372741,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "ce76f6903fc702671d943c5fe9717f08d77fe951",
          "message": "refactor(l1): add `node_id` field to Node (node_id refactor 2/3) (#2786)\n\nBased on #2778 \n**Motivation**\nAvoid constantly hashing the node's public key on kademlia operations by\nadding `node_id` field. Before this PR we would hash the node's public\nkey every time we needed to add, remove or find a node in the kademlia\ntable, which is pretty often.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add `Node` field `node_id`\n* Add `new` method for `Node` which handles node_id computation\n* Use `node_id` for kademlia table (and some other) operations instead\nof the public key so we no longer need to hash it when calculating the\nbucket index (this affects most kademlia table reads/writes)\n\n**Follow-Up Work**\nUse `OnceLock` to cache for `node_id` computation (replacing the field\nadded by this PR) #2789\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-15T15:15:26Z",
          "tree_id": "96bf81f986d995dc5589a52cd3eb5a35ed4e516f",
          "url": "https://github.com/lambdaclass/ethrex/commit/ce76f6903fc702671d943c5fe9717f08d77fe951"
        },
        "date": 1747331400838,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007401168710152035,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomas.arjovsky@lambdaclass.com",
            "name": "Tomás Arjovsky",
            "username": "Arkenan"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "621ac953a3fab3f05efff24aa82db8591fab0bf2",
          "message": "fix(core): timeout due to node inactivity instead of total load test time (#2530)\n\nChanges:\n\n- Timeout is now smarter. Instead of waiting a fixed amount of time\n(e.g. 10 minutes) for the whole load test to happen, which is a bit\nunpredictable, the load test waits at most 1 minute (configurable) of\nno-updates from the node. This way it's less machine dependent and more\nbased on responsiveness.\n- load-test-ci.json is fixed to be similar to perf-ci.json, but in\nprague and with the system smart contracts from l1-dev.json deployed.\n- logs are re-added.\n- Readme si fixed.\n- Re-add flamegraph reporter to CI so they are generated on every push.\n\nCloses #2522",
          "timestamp": "2025-05-15T17:04:16Z",
          "tree_id": "f64c37d48452480f6003549cb7916a399c25f745",
          "url": "https://github.com/lambdaclass/ethrex/commit/621ac953a3fab3f05efff24aa82db8591fab0bf2"
        },
        "date": 1747334902487,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007386677924620656,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "0f9cc95d8cf5fb15b0d5acc37bf9c2264e0ff5db",
          "message": "refactor(l1): cache `node_id` computation (node_id refactor 3/3) (#2789)\n\nBased on #2786 \n**Motivation**\nUse `OnceLock` to cache node_id computation so we only do it once but at\nthe same time don't need to do it unless we will use it. For example,\nwhen we receive a Neighbours message we will decode all received nodes\nbut may not use them all if our kademlia table is full.\nThis PR can be ignored if we consider the cases where we would not need\nto use a node's id scarce enough to not warrant the added complexity of\na cache. For example, the Neighbours case could be handled by using a\nseparate structure (without node_id) to decode the incoming node and\nconverting that to our Node (with node_id) when we insert that node into\nour table.\nThe main consecuente of adding this cache is the `Node` no longer being\ncopy, which affects various areas of the networking codebase\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Convert public `Node` field `node_id: H256` into private field\n`node_id: OnceLock<H256>`\n* Add `Node` method `node_id`\n* Fix code affected by `Node` no longer being `Copy`\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-15T18:40:12Z",
          "tree_id": "7ab0821461058532c135bdaf08ba49e22fa73d0c",
          "url": "https://github.com/lambdaclass/ethrex/commit/0f9cc95d8cf5fb15b0d5acc37bf9c2264e0ff5db"
        },
        "date": 1747338279980,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007437645638245441,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "47ffb22802baaee9c132c4b3e68cc8393b143fff",
          "message": "fix(l2): contract deployer fixes (#2779)\n\n**Motivation**\n\nIf an integration test fails, it's really difficult to debug the\ncontract deployer and know that the problem was there in the first\nplace.\n\n**Description**\n\n- removes spinner\n- adds clearer logs and traces\n- make ethrex_l2 container depend on the deployer terminating\nsuccessfuly (so flow stops if deployer failed)",
          "timestamp": "2025-05-15T18:57:07Z",
          "tree_id": "dc79c11341afae3ba40d1e7f85e51ed842600a9c",
          "url": "https://github.com/lambdaclass/ethrex/commit/47ffb22802baaee9c132c4b3e68cc8393b143fff"
        },
        "date": 1747341735975,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007408435444280806,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c3c01438d5bdbd8f7e2f0203d670613a2a821c15",
          "message": "fix(l1, levm): propagate error that we were ignoring when getting account (#2813)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n- We shouldn't ignore the case in which there's a StoreError or a\nTrieError when trying to get an account's info. It is something that\nprobably doesn't happen very often but I think it's a mistake to ignore\nit as we've been doing.",
          "timestamp": "2025-05-15T19:34:48Z",
          "tree_id": "edfe8cac6b4cda4e1fad038f6d41e59cd198bff2",
          "url": "https://github.com/lambdaclass/ethrex/commit/c3c01438d5bdbd8f7e2f0203d670613a2a821c15"
        },
        "date": 1747345085201,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007375847018572825,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "manuel.bilbao@lambdaclass.com",
            "name": "Manuel Iñaki Bilbao",
            "username": "ManuelBilbao"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "19097eeba57defb13af215cf50adb39d6eada412",
          "message": "chore(l2): separate address initialization (#2809)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\nDeploy proxy contracts without instant initialization is considered\ninsecure.\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nChange OnChainProposer contract so it can be initialized and then the\nowner can set (only once) the bridge address\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-05-15T19:47:53Z",
          "tree_id": "aa0dfc08af20716fab5374f5f6d7aacbf355b1fa",
          "url": "https://github.com/lambdaclass/ethrex/commit/19097eeba57defb13af215cf50adb39d6eada412"
        },
        "date": 1747348509355,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.000734354403892944,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "56402156+fkrause98@users.noreply.github.com",
            "name": "Francisco Krause Arnim",
            "username": "fkrause98"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e1394a3058c308047c733289e917fb41e3552277",
          "message": "ci(l1,l2): run \"main-prover-l1\" only on merge to main (#2815)\n\n**Motivation**\n\nThis is not a required check anymore, so we only will run it on a merge\nto main instead of each PR.\n**Description**\n\n- Simply make the yml worklfow run on a merge to main",
          "timestamp": "2025-05-15T20:09:59Z",
          "tree_id": "321c0ba74181e40108d72208066a32e99250d2e6",
          "url": "https://github.com/lambdaclass/ethrex/commit/e1394a3058c308047c733289e917fb41e3552277"
        },
        "date": 1747350776358,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.000726226323387873,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e7a4a038c19709c129cdf7e3c93d9a6240a4481c",
          "message": "ci(l1): comment flaky devp2p test Findnode/UnsolicitedNeighbors (#2817)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\nCommenting the test until it's fixed, just the one that's flaky\nOpened issue: https://github.com/lambdaclass/ethrex/issues/2818\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number",
          "timestamp": "2025-05-15T20:34:43Z",
          "tree_id": "c13fc5b333fd0ce4619fa309398ef1e83e550aa3",
          "url": "https://github.com/lambdaclass/ethrex/commit/e7a4a038c19709c129cdf7e3c93d9a6240a4481c"
        },
        "date": 1747352990284,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.000726226323387873,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "martin.c.paulucci@gmail.com",
            "name": "Martin Paulucci",
            "username": "mpaulucci"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "6efc8891ed386e1410a747995d793c4e9442586f",
          "message": "chore(core): fix block producer logs. (#2806)\n\n**Motivation**\nLogs say v3, pero it is sending v4.",
          "timestamp": "2025-05-15T20:44:08Z",
          "tree_id": "45a01330683f0da442fd7f61d4d44d67dbf73dc6",
          "url": "https://github.com/lambdaclass/ethrex/commit/6efc8891ed386e1410a747995d793c4e9442586f"
        },
        "date": 1747355218762,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007272762891566265,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "56402156+fkrause98@users.noreply.github.com",
            "name": "Francisco Krause Arnim",
            "username": "fkrause98"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d4d34595443f68a9f44c27d0d9db4a2ba67b9b1f",
          "message": "chore(l1,l2): ordered genesis files (#2713)\n\n**Motivation**\n\nOrdered genesis files make it easy to diff with one another.\n\n**Description**\n\n- Add function to write a Genesis json file with its keys ordered.\n- Genesis files are now ordered by key.\n\n\nCloses #2706.",
          "timestamp": "2025-05-15T21:07:01Z",
          "tree_id": "a99724ca368c79f6c2a29142ed03c84a6b70413e",
          "url": "https://github.com/lambdaclass/ethrex/commit/d4d34595443f68a9f44c27d0d9db4a2ba67b9b1f"
        },
        "date": 1747357420204,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007265759749638902,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e39ccb875c18b50fdb5b524c802d7e9cc469d619",
          "message": "fix(l2): failed compilation in crate prover/bench (#2830)\n\n**Motivation**\n\nThe ci is broken\n\n**Description**\n\n- Clone the access list as tx.access_list() now returns a reference\n- Fix all the warnings the prover crate had\n- Make the l2 lint ci run in every PR",
          "timestamp": "2025-05-19T17:45:20Z",
          "tree_id": "562110989686e0e4b0052021a50e9b4a7a1e1902",
          "url": "https://github.com/lambdaclass/ethrex/commit/e39ccb875c18b50fdb5b524c802d7e9cc469d619"
        },
        "date": 1747679518504,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007269259633911368,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "30327624+mechanix97@users.noreply.github.com",
            "name": "Mechardo",
            "username": "mechanix97"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2fcf668a5c84b1dede8e868d1ad63c0d9474deab",
          "message": "feat(l1): properly calculate `enr` sequence field (#2679)\n\n**Motivation**\n\nThe seq field in the node record was hardcoded with the unix time. \n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\nThe enr_seq field is updated by one when the node_record is changed. The\nping/pong messages are sent with the enr_seq in it, so the peer knows\nwhen an update is made in the node_record. Since we don't modify the\nnode_record yet, the enr_seq is not being updated. There is a new PR\nincoming (#2654) which is using this funtionality to inform the peers\nabout changes in the node_record.\n\nA reference was added to the p2pcontext in order to be able to access\nthe current NodeRecord seq in several parts of the code.\n\nSome functions firms were changed to accept this improvement.\n\nA new config struct has been built to persist the enr seq field and also\nstore the known peers in the same file.\n\nThe test discv4::server::tests::discovery_enr_message checks this\nfeature\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\n[enr](https://github.com/ethereum/devp2p/blob/master/enr.md)\n\nCloses #1756",
          "timestamp": "2025-05-19T17:53:25Z",
          "tree_id": "7ca4ce20efe9f03f712421e6f8ff15159dfa376d",
          "url": "https://github.com/lambdaclass/ethrex/commit/2fcf668a5c84b1dede8e868d1ad63c0d9474deab"
        },
        "date": 1747681743023,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007272762891566265,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "9ba8270b2edadec13496080446025cd3b0eabf80",
          "message": "fix(levm): fix last blockchain tests for LEVM (#2842)\n\n**Motivation**\n\n- Fix remaining blockchain tests for Prague with LEVM.\n\n**Description**\n\n- Precompiles shouldn't be executed in case they are delegation target\nof the same transaction in which they are being called.\n- It also fixes a problem in the transfer of value in CALL. (It just\nmoves the place where the value transfer is performed)\n\nAfter this there are no more `blockchain` tests we need to fix.\n\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCo-authored-by: @DiegoCivi",
          "timestamp": "2025-05-19T19:55:34Z",
          "tree_id": "f402baf6112c7625c0542bd74bb503df650c4d04",
          "url": "https://github.com/lambdaclass/ethrex/commit/9ba8270b2edadec13496080446025cd3b0eabf80"
        },
        "date": 1747687327311,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007269259633911368,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c716b18ae0ee577eb9cc3889f70d152eb48e535c",
          "message": "fix(l1): add deposit request layout validations + return invalid deposit request error (#2832)\n\n**Motivation**\nCurrently, when we fail to parse a deposit request we simply ignore it\nand keep the rest of the deposits, relying on the request hash check\nafterwards to notice the missing deposit request. This PR handles the\nerror earlier and returns the appropriate `InvalidDepositRequest Error`.\nThis will provide better debugging information and also more accurate\ntesting via tools such as `execution-spec-tests` which rely on specific\nerror returns.\nWe also were not correctly validating the layout according to the\n[EIP](https://eips.ethereum.org/EIPS/eip-6110), as we were only checking\nthe total size and not the size and offset of each request field\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Check that the full layout of deposit requests is valid (aka the\ninternal sizes and offsets of the encoded data)\n* Handle errors when parsing deposit requests\n* Check log topic matches deposit topic before parsing a request as a\ndeposit request\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nAllows us to address review comment made on execution-specs-test PR\nhttps://github.com/ethereum/execution-spec-tests/pull/1607 + also closes\n#2132",
          "timestamp": "2025-05-19T21:11:46Z",
          "tree_id": "2de9920ba534f744b1f08be38261693601826892",
          "url": "https://github.com/lambdaclass/ethrex/commit/c716b18ae0ee577eb9cc3889f70d152eb48e535c"
        },
        "date": 1747691902183,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007290329951690821,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "99273364+fmoletta@users.noreply.github.com",
            "name": "fmoletta",
            "username": "fmoletta"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d73297f8624033d59c07ba887a007fe20071702c",
          "message": "feat(l1): add rpc endpoint admin_peers (#2732)\n\n**Motivation**\nSupport rpc endpoint `admin_peers`\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n* Add rpc endpoint `admin_peers`\n* Track inbound connections \n* Store peer node version when starting a connection\n* Add `peer_handler: PeerHandler` field to `RpcContext` so we can access\npeers from the rpc\n* (Misc) `Syncer` & `SyncManager` now receive a `PeerHandler` upon\ncreation instead of a `KademliaTable`\n* (Misc) Fix common typo across the project\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\nData missing compared to geth implementation:\n* The local address of each connection\n* Whether a connection is trusted, static (we have no notion of this\nyet)\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2671",
          "timestamp": "2025-05-20T13:40:51Z",
          "tree_id": "1b839813ccf9db83001f1616c569634442f3aee3",
          "url": "https://github.com/lambdaclass/ethrex/commit/d73297f8624033d59c07ba887a007fe20071702c"
        },
        "date": 1747751252598,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007272762891566265,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "90105443+DiegoCivi@users.noreply.github.com",
            "name": "DiegoC",
            "username": "DiegoCivi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f691b847aff49587887b0e45c513a659f01875af",
          "message": "feat(l1): add eest hive tests to daily report (#2792)\n\n**Motivation**\n\nHave a better way to visualize the results from the execution of the EF\nblockchain tests using Hive.\n\n**Description**\n\nHive daily report now also runs the simulators\n`ethereum/eest/consume-engine` and `ethereum/eest/consume-rlp` with the\nblockchain fixtures of the `execution-spec-tests`. The version of the\nfixtures is taken from `cmd/ef_tests/blockchain/.fixtures_url`.\nThis was also talked in #2474. \n\nCloses #2746 and part of #1988",
          "timestamp": "2025-05-20T14:12:09Z",
          "tree_id": "5b0908e689956af280c60bb0a78562d489cc5fd0",
          "url": "https://github.com/lambdaclass/ethrex/commit/f691b847aff49587887b0e45c513a659f01875af"
        },
        "date": 1747753465678,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007283292953667954,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "75658dc1e810b6f8712d44c4cdee3634367e7e20",
          "message": "chore(l2): don't init metrics for l1 when using make init (#2849)\n\n**Motivation**\n\nWhen starting l1 with `make init` or `make restart` the l1 node started\n2 more containers for prometheus + graphana. We don't care for the l1\nmetrics neither in development nor in production for l2 so we want to\nremove it\n\n**Description**\n\n- Build \"dev\" docker image without metrics feature\n- Remove include of `../metrics/docker-compose-metrics.yaml` file in\n`docker-compose-dev.yaml`\n- Remove metrics port from `docker-compose-dev.yaml`\n- Delete `docker-compose-metrics-l1-dev.overrides.yaml` file\n- Remove `docker-compose-metrics-l1-dev.overrides.yaml` from makefile\n\n\nCloses #2554",
          "timestamp": "2025-05-20T14:26:32Z",
          "tree_id": "a006830bcc4c1ba2927f6e276fd247fc0e5d97da",
          "url": "https://github.com/lambdaclass/ethrex/commit/75658dc1e810b6f8712d44c4cdee3634367e7e20"
        },
        "date": 1747755695334,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007255280288461539,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "git@edgl.dev",
            "name": "Edgar",
            "username": "edg-l"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8afdb49fb6d357fa14dffd14e094d545e25a633c",
          "message": "chore(l1,l2): remove double Arc and Mutex from metrics (#2847)\n\n**Motivation**\n\nThe underlying Gauges are already thread safe and behind Arcs\ninternally, so the used Arc and Mutex wrapper were useless overhead.\n\n<!-- Why does this pull request exist? What are its goals? -->\n\nThe types in the library derive from\n\n```\npub struct GenericCounter<P: Atomic> {\n    v: Arc<Value<P>>,\n}\n```\n\nWhich is clone safe, furthermore P is atomic so it doesnt need a lock.\n\n**Description**\n\nRemove unused Mutex and Arc\n\nCloses #issue_number",
          "timestamp": "2025-05-20T14:56:34Z",
          "tree_id": "17ed1717dd6dcf7dd880049a12dcbf92ec4add4a",
          "url": "https://github.com/lambdaclass/ethrex/commit/8afdb49fb6d357fa14dffd14e094d545e25a633c"
        },
        "date": 1747757914892,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007276269527483124,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a49cb6c6ff7f1e852a73b360553a17ee91d812e6",
          "message": "feat(core): add fallback url for EthClient (#2826)\n\n**Motivation**\n\nIn case the first rpc endpoint fails we want to have a second option. \n\n**Description**\n\n- Parse `eth-rpc-url` as a list of comma separated urls\n- Add logic to EthClient to retry with all rpc-urls if a request fails\n\n**How to test**\n\n```\ncargo run --release --manifest-path ../../Cargo.toml --bin ethrex --features \"l2,rollup_storage_libmdbx,metrics\" -- \\\n\tl2 init \\\n\t--eth-rpc-url \"http://aaaaaa\" \"http://localhost:8545\"  \\\n\t--watcher.block-delay 0 \\\n\t--network ../../test_data/genesis-l2.json \\\n\t--http.port 1729 \\\n\t--http.addr 0.0.0.0 \\\n\t--evm levm \\\n\t--datadir dev_ethrex_l2 \\\n\t--bridge-address 0x13a07379d93a0cf8c0c84e8e9cc31deab0da3ef0 \\\n\t--on-chain-proposer-address 0x628bb559d2bc6fdb402f7f1293f5aba689586189 \\\n\t--proof-coordinator-listen-ip 127.0.0.1\n```\n\n---------\n\nCo-authored-by: Manuel Iñaki Bilbao <manuel.bilbao@lambdaclass.com>",
          "timestamp": "2025-05-20T16:06:23Z",
          "tree_id": "3732e74370007342aebc2f6f520997d2c25d6e0c",
          "url": "https://github.com/lambdaclass/ethrex/commit/a49cb6c6ff7f1e852a73b360553a17ee91d812e6"
        },
        "date": 1747760139296,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007272762891566265,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "git@edgl.dev",
            "name": "Edgar",
            "username": "edg-l"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "415a46dacc1ff5a9609e82df661643f9e1c05ee6",
          "message": "fix(core): fix load test not running properly (#2851)\n\n**Motivation**\n\nDue to changes to gas estimation the load test had to call estimage gas\na lot which slowed downn the load test \"setup\". Also increased the\nmax_fee_per_gas which was lowered in recent commits by mistake.",
          "timestamp": "2025-05-20T16:23:12Z",
          "tree_id": "74b4b1d6f118e8394b6eba3e1477c95a7c035326",
          "url": "https://github.com/lambdaclass/ethrex/commit/415a46dacc1ff5a9609e82df661643f9e1c05ee6"
        },
        "date": 1747762367835,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007272762891566265,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "estefano.bargas@fing.edu.uy",
            "name": "Estéfano Bargas",
            "username": "xqft"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "252d67040cc232e6f440f89daf5c4fc9f437ccd6",
          "message": "feat(l2): hardcode SP1 verification key (#2708)\n\n**Motivation**\n\nInstead of sending it as a parameter, it will be set as a contract\nstatic variable.\n\nAlso makes sp1 build in docker for reproducibility (and so the key\ndoesn't change depending on the platform we're building)\n\n---------\n\nCo-authored-by: ilitteri <ilitteri@fi.uba.ar>\nCo-authored-by: Ivan Litteri <67517699+ilitteri@users.noreply.github.com>\nCo-authored-by: Javier Rodríguez Chatruc <49622509+jrchatruc@users.noreply.github.com>\nCo-authored-by: Manuel Iñaki Bilbao <manuel.bilbao@lambdaclass.com>",
          "timestamp": "2025-05-20T16:43:49Z",
          "tree_id": "34aca3ca7e81d3b11445d24e932f5b35b63ffeb6",
          "url": "https://github.com/lambdaclass/ethrex/commit/252d67040cc232e6f440f89daf5c4fc9f437ccd6"
        },
        "date": 1747764868148,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007361455121951219,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c47725143e35457f53d360c0fa5b28524a954b45",
          "message": "feat(l2): add cli option to compute genesis state root (#2843)\n\n**Motivation**\n\nAdd a subcommand to compute a state root given a genesis file path\n\n**Description**\n\n* Add new variant to `Subcommand` struct called `ComputeStateRoot`\n* It has a required argument for the file path\n* Calls the existing function `pub fn compute_state_root(&self) -> H256`\n\n**How to use**\n\nrun:\n`cargo run --bin ethrex --release -- compute-state-root --path\ntest_data/genesis-l2.json`",
          "timestamp": "2025-05-20T17:22:33Z",
          "tree_id": "f848b297ae239f9faf7cd29924fb693b26ad7486",
          "url": "https://github.com/lambdaclass/ethrex/commit/c47725143e35457f53d360c0fa5b28524a954b45"
        },
        "date": 1747767269703,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.000739754068627451,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "30327624+mechanix97@users.noreply.github.com",
            "name": "Mechardo",
            "username": "mechanix97"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7c00fdc269a97c28fcdf849a01e73d424dce188f",
          "message": "feat(l1): capability negotation (#2840)\n\n**Motivation**\n\nMultiple version of the same protocol can be used when a connection is\nestablished(eth/68 and eth/69 for example). At the moment, we can only\nuse one protocol version.\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\nA vec of capability is used to pass multiple versions of the protocol to\nsome functions.\n\nThe struct RLPxConnection now stores capabilities struct instead of\nnumbers.\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->",
          "timestamp": "2025-05-20T17:59:33Z",
          "tree_id": "2b5317048d54657af96870ce3ef27eafcf16643c",
          "url": "https://github.com/lambdaclass/ethrex/commit/7c00fdc269a97c28fcdf849a01e73d424dce188f"
        },
        "date": 1747769680656,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007361455121951219,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "e9b7de232230f24a6632d495b08dcf50d47f5c69",
          "message": "fix(l2): correct private key for load test account (#2837)\n\n**Motivation**\n\nAfter the changes introduced in #2781. The rich account needed for the\nload test no longer has funds to make the deploy and the transactions.\n\n**Description**\n\nChange the private key to one of the rich accounts that is used on the\ninitial deposit in the deployment of the L2\n\n**How to test**\n\nRunning: `cargo run --manifest-path ../../cmd/load_test/Cargo.toml -- -k\n../../test_data/private_keys.txt -t erc20 -N 50 -n\nhttp://localhost:1729`\n\nThis won't lead to panic.\n\nBut in main we get:\n```\nERC20 Load test starting\nDeploying ERC20 contract...\nthread 'main' panicked at cmd/load_test/src/main.rs:358:18:\nFailed to deploy ERC20 contract: eth_sendRawTransaction request error: Invalid params: Account does not have enough balance to cover the tx cost\n\nCaused by:\n    Invalid params: Account does not have enough balance to cover the tx cost\n```",
          "timestamp": "2025-05-20T18:51:24Z",
          "tree_id": "d4100a43ca2cfb2a1430792e48679a5b19938fcb",
          "url": "https://github.com/lambdaclass/ethrex/commit/e9b7de232230f24a6632d495b08dcf50d47f5c69"
        },
        "date": 1747772074366,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007354280214424951,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "tomas.arjovsky@lambdaclass.com",
            "name": "Tomás Arjovsky",
            "username": "Arkenan"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "ee21522c5b196f07b3703a6d0b857d52cd4c094d",
          "message": "fix(core): remove eager rpc calls calls from eth client (#2862)\n\nThe eth client was calling gas price and max gas price even if the\noverrides where set. That heavily impacted load test in particular, but\nit also made overrides pointless. With this small change, the RPC calls\nare only called in the case that overrides are not provided.",
          "timestamp": "2025-05-21T11:56:05Z",
          "tree_id": "6a1798b38ae4a9f3891000a01ca100b75cc34c28",
          "url": "https://github.com/lambdaclass/ethrex/commit/ee21522c5b196f07b3703a6d0b857d52cd4c094d"
        },
        "date": 1747831539810,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007357865919063872,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "onoratomatias@gmail.com",
            "name": "Matías Onorato",
            "username": "mationorato"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "2dc43bdb26b36745beee89bbe2cf650ba3017e88",
          "message": "fix(l2): change the reentrancyguard for its upgradable version. (#2861)\n\n**Motivation**\nThis pr is needed to pass all the verification that foundry runs for\nupgradable contracts.",
          "timestamp": "2025-05-21T12:58:26Z",
          "tree_id": "dbba6063e5fba6a6d8c41afec6ce51666d4706e6",
          "url": "https://github.com/lambdaclass/ethrex/commit/2dc43bdb26b36745beee89bbe2cf650ba3017e88"
        },
        "date": 1747835285583,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.000734354403892944,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "90105443+DiegoCivi@users.noreply.github.com",
            "name": "DiegoC",
            "username": "DiegoCivi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1b9f5ddafebe57842533688a304c9112efd351c0",
          "message": "fix(l1,l2): fix Succint dependency error on cargo check (#2835)\n\n**Motivation**\n\nWe were excluding `ethrex-prover-bench` when doing `cargo check\n--workspace` because it failed when `succinct` was not instaled.\n\n**Description**\n\n- `sp1` feature was removed from the default features of\n`ethrex-prover-bench`.\n- After doing the step above, `cargo check --workspace` could be ran and\nsome errors and warnings appeared and they were fixed.\n- '--exclude ethrex-prover-bench' was removed from the L1 ci job\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2807",
          "timestamp": "2025-05-21T14:40:45Z",
          "tree_id": "59764f890d4872bf4fd2da6be07cd003cea8f0df",
          "url": "https://github.com/lambdaclass/ethrex/commit/1b9f5ddafebe57842533688a304c9112efd351c0"
        },
        "date": 1747841480870,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007307982082324456,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49622509+jrchatruc@users.noreply.github.com",
            "name": "Javier Rodríguez Chatruc",
            "username": "jrchatruc"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "6871f6173327d11f7598a8244ee9c932304f96c9",
          "message": "fix(l1,l2): add load test erc20 rich account to genesis-load-test.json (#2863)\n\n**Motivation**\n\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #issue_number\n\nCo-authored-by: Tomás Arjovsky <tomas.arjovsky@lambdaclass.com>",
          "timestamp": "2025-05-21T15:37:11Z",
          "tree_id": "3ac85fcf280153478dd48954da72318078de60cb",
          "url": "https://github.com/lambdaclass/ethrex/commit/6871f6173327d11f7598a8244ee9c932304f96c9"
        },
        "date": 1747844863571,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007286809753742153,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "44068466+SDartayet@users.noreply.github.com",
            "name": "SDartayet",
            "username": "SDartayet"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "6632b444196cef4e4f1e42e5efc271d14c24924a",
          "message": "refactor(levm): remove clones for account structs (#2684)\n\n**Motivation**\n\nImproving the performance of some cases by avoiding clones where\npossible.\n\n**Description**\n\nMany clones of account structs were removed. This involved changing the\noutput of the get_account and access_account functions of the DB to\nreturn a reference to an account, as well as refactorings of the code\nwhich involved these functions.\n\nResolves [#2611](https://github.com/lambdaclass/ethrex/issues/2611)",
          "timestamp": "2025-05-21T15:54:24Z",
          "tree_id": "1a5b4b17da28e1279bf36b26779e3f2519b7d32e",
          "url": "https://github.com/lambdaclass/ethrex/commit/6632b444196cef4e4f1e42e5efc271d14c24924a"
        },
        "date": 1747847314672,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007237881534772182,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "46695152+LeanSerra@users.noreply.github.com",
            "name": "LeanSerra",
            "username": "LeanSerra"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "17429160f3e67e8e377a9f9b574c02c3f9db02c5",
          "message": "ci(l2): fix L2 sp1 prover integration test steps were skipped on merge to main (#2865)\n\n**Motivation**\n\nFix broken ci\n\n**Description**\n\n- Comment conditional running that only run the steps on the merge queue\n- Left comment with TODO to uncomment when we re enable this job in the\nmerge queue",
          "timestamp": "2025-05-21T15:55:59Z",
          "tree_id": "746b79b3607a83946cf3bdf82ed0542e3bd7aa17",
          "url": "https://github.com/lambdaclass/ethrex/commit/17429160f3e67e8e377a9f9b574c02c3f9db02c5"
        },
        "date": 1747851221236,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007203333174224343,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "90105443+DiegoCivi@users.noreply.github.com",
            "name": "DiegoC",
            "username": "DiegoCivi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c6a54c2fb71fc708a49951772cd2690d60279103",
          "message": "refactor(l1): move hash from Block to BlockHeader (#2845)\n\n**Motivation**\n\n`Block` had the hash but the `BlockHeader` didn't so they had to be\npassed along together.\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n\nMove the hash into `BlockHeader`, making it accesible to it and also to\n`Block`\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2841",
          "timestamp": "2025-05-21T18:09:33Z",
          "tree_id": "c3bc3581590268a1d555692e2548944d0e85e580",
          "url": "https://github.com/lambdaclass/ethrex/commit/c6a54c2fb71fc708a49951772cd2690d60279103"
        },
        "date": 1747855408919,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007196463042441583,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "48994069+JereSalo@users.noreply.github.com",
            "name": "Jeremías Salomón",
            "username": "JereSalo"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "171076f9a71b02beb9a852bad96fb062aaca9ee6",
          "message": "fix(levm): fix eip 7702 logic around touched_accounts (#2859)\n\n**Motivation**\n\n- Fix error when executing a transaction of a block when syncing Holesky\nin Prague by chaning behavior of the EVM.\n\n**Description**\n\n- We now set `code_address` and `bytecode` at the end of\n`prepare_execution`. It's necessary because of EIP-7702.\n- We change the place in which we add the delegated account to\n`touched_accounts` → **CORE CHANGE**\n- Change some outdated comments related to EIP7702 functions.\n- Change `get_callee_and_code` to `get_callee` because we don't need the\ncode before `prepare_execution` and this is assigned afterwards.\n- Create `set_code` function to CallFrame so that we calculate jump\ndestinations everytime we want to set the code, because it's always\nnecessary.\n\n\n**In depth explanation: What was wrong with this transaction?**\nThe gas diff was 2000 between LEVM and REVM, but doing some math we\nfound out that the actual gas diff before refunds was 2500. The access\ncost of accessing a COLD Address is 2600 and the cost of accessing a\nWARM address is 100. 2600-100 = 2500. That's the difference between LEVM\nand REVM, but where is it?\nReading EIP-7702 and analyzing our behavior made me realize:\n(Capital Letters here are accounts)\n- Transaction: A → B\n- B had C as delegate account at the beginning of the transaction so we\nadd C to the `touched_accounts`.\n- Transaction authority list sets B to have D as delegate, so that it's\nnot C anymore.\n- During execution we make internal calls to C\n- Our VM thinks C is in `touched_accounts` (that means warm) and\nconsumes 100 gas when accessing it instead of 2600.\n\nSolution? Changing the moment in which we add the delegate account to\n`touched_accounts`, so that we do it after the authorization list was\nprocessed.",
          "timestamp": "2025-05-21T20:53:49Z",
          "tree_id": "e7f6d045a970f8dc5679432499730b674980c601",
          "url": "https://github.com/lambdaclass/ethrex/commit/171076f9a71b02beb9a852bad96fb062aaca9ee6"
        },
        "date": 1747865020832,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007357865919063872,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": false,
          "id": "657ba027088cf61604dde6559b4727f27af5f11c",
          "message": "perf(l2): remove cloning state for limiting batch size (#2825)\n\n**Motivation**\n\nIn this PR we remove the cloning of the context before executing every\ntransaction to check if it doesn't exceed the state diff size limit.\n\n**Description**\n\n* Add new functions specific for the L2 `apply_transaction_l2` and\n`execute_tx_l2`.\n* Now `apply_transaction_l2` returns a CallFrameBackup that is needed\nfor reverting the changes made by the transaction. This revert is\ndifferent from the transaction revert, this has to undo every\nmodification even the pre execute validation changes.\n* Simplify the encoding of the structs `WithdrawalLog`, `DepositLog`,\n`BlockHeader` and `AccountStateDiff` when calculating the StateDiff.\nThis leads to better consistency and being less error prone to future\nchanges.\n* Expose the VM function to restore the state from a `CallFrameBackup`.\n\n**Comparison against main**\nHow to replicate:\nInside `crates/l2`\n- Terminal 1: `init-l1`\n- Terminal 2: `make deploy-l1 update-system-contracts init-l2`\n- Terminal 3: `cargo run --manifest-path ../../cmd/load_test/Cargo.toml\n-- -k ../../test_data/private_keys.txt -t erc20 -N 50 -n\nhttp://localhost:1729`\n\nFor Terminal 3 if necessary run `ulimit -n 65536` before the command.\n\nGigagas comparison:\nmain: `[METRIC] BLOCK BUILDING THROUGHPUT: 0.0028166668076660267\nGigagas/s TIME SPENT: 30733 msecs`\nthis PR: `BLOCK BUILDING THROUGHPUT: 0.3342272162162162 Gigagas/s TIME\nSPENT: 259 msecs`\n\nLoadtest comparision:\nmain: `Load test finished. Elapsed time: 254 seconds`\nthis PR: `Load test finished. Elapsed time: 34 seconds`\n\nCloses #2413 \nCloses #2655\n\n---------\n\nCo-authored-by: Avila Gastón <72628438+avilagaston9@users.noreply.github.com>",
          "timestamp": "2025-05-22T19:38:28Z",
          "tree_id": "28e499a32519baff9ecf2d2196070b3d817ccb60",
          "url": "https://github.com/lambdaclass/ethrex/commit/657ba027088cf61604dde6559b4727f27af5f11c"
        },
        "date": 1747954444944,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007404800294406281,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "112426153+tomip01@users.noreply.github.com",
            "name": "Tomás Paradelo",
            "username": "tomip01"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9899326156309274fcc9c87d7342d99eba76c10a",
          "message": "refactor(l2): remove all based features (#2868)\n\n**Motivation**\n\nWe want to remove all based features in the project\n\n**Description**\n\n* All feature flags `based` were removed.\n* All functions related to specific behavior from based rollups were\nremoved",
          "timestamp": "2025-05-22T20:23:03Z",
          "tree_id": "3aeb6e6f4a7437120359898134d69aac80277ea3",
          "url": "https://github.com/lambdaclass/ethrex/commit/9899326156309274fcc9c87d7342d99eba76c10a"
        },
        "date": 1747958157916,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007354280214424951,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "francisco.gauna@lambdaclass.com",
            "name": "fedacking",
            "username": "fedacking"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4c9fcfa179fb41f534e3faec1bd25926adafa266",
          "message": "ci(core): updating hive revision (#2881)\n\n**Motivation**\n\nIn our lambdaclass/hive fork, we have updated upstream. When [that\nPR](https://github.com/lambdaclass/hive/pull/28) is merged, we should\nupdate the branch name here and test it.\n\n**Description**\n\n- Updates the hive revision\n- Also updates \"HIVE_SHALLOW_SINCE\"\n\nCloses #2760",
          "timestamp": "2025-05-22T21:53:50Z",
          "tree_id": "661efb1c7f5fc50738bff485277f2d818b33d71a",
          "url": "https://github.com/lambdaclass/ethrex/commit/4c9fcfa179fb41f534e3faec1bd25926adafa266"
        },
        "date": 1747961879118,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007365047828208882,
            "unit": "Mgas/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "90105443+DiegoCivi@users.noreply.github.com",
            "name": "DiegoC",
            "username": "DiegoCivi"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "63fd78dc5cad5e912a3320b39fed69d471007f1f",
          "message": "refactor(l1): move AccountUpdate to common crate (#2867)\n\n**Motivation**\n\nReduce coupling between crates ethrex_storage and ethrex_vm\n<!-- Why does this pull request exist? What are its goals? -->\n\n**Description**\n- Move `account_update.rs` from `storage` to `common/types`\n- Fix imports\n<!-- A clear and concise general description of the changes this PR\nintroduces -->\n\n<!-- Link to issues: Resolves #111, Resolves #222 -->\n\nCloses #2852",
          "timestamp": "2025-05-23T13:29:25Z",
          "tree_id": "35ed7c318e0057fc38603007251d6e9ccfe29d44",
          "url": "https://github.com/lambdaclass/ethrex/commit/63fd78dc5cad5e912a3320b39fed69d471007f1f"
        },
        "date": 1748009994853,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "SP1, RTX A6000",
            "value": 0.0007272762891566265,
            "unit": "Mgas/s"
          }
        ]
      }
    ]
  }
}