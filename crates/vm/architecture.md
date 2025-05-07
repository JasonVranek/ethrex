# LEVM Architecture Overview: A Developer's Guide

This document provides an in-depth overview of the LEVM (Lambda Ethereum Virtual Machine) architecture within the `vm` crate. It's designed to help developers quickly understand how the EVM implementation works, the execution flow, and how to effectively navigate and extend the codebase.

## 1. Overall Architecture

The `vm` crate provides a modular approach to Ethereum Virtual Machine execution, allowing for pluggable EVM implementations.

- **Entry Point:** [`crates/vm/lib.rs`](./lib.rs) defines the main module structure and public interfaces.
  ```rust
  pub use backends::{BlockExecutionResult, Evm, EvmEngine};
  pub use db::{ExecutionDB, StoreWrapper, ToExecDB};
  pub use errors::{EvmError, ExecutionDBError};
  pub use execution_result::ExecutionResult;
  ```

- **Backend Selection:** The [`Evm` enum](./backends/mod.rs#L55) is a crucial abstraction allowing the system to switch between different EVM implementations:
  ```rust
  pub enum Evm {
      REVM { state: EvmState },
      LEVM { db: GeneralizedDatabase },
  }
  ```

- **Engine Type:** The [`EvmEngine` enum](./backends/mod.rs#L27) defines the available EVM backend types:
  ```rust
  pub enum EvmEngine {
      #[default]
      REVM,
      LEVM,
  }
  ```

- **Unified Interface:** The `Evm` enum implementation provides a common interface for both backends, with methods such as:
  - `execute_block()`: Processes a full block of transactions
  - `execute_tx()`: Executes a single transaction 
  - `get_state_transitions()`: Extracts state changes after execution

- **Dispatch Pattern:** Based on the selected engine, methods automatically route calls to either the LEVM or REVM implementation:
  ```rust
  match self {
      Evm::REVM { state } => { /* REVM implementation */ },
      Evm::LEVM { db } => { /* LEVM implementation */ }
  }
  ```

### Relationship to Other Components

The VM crate sits at the heart of the Ethereum execution layer, interacting with:
- **Storage Layer**: Persistent blockchain state access
- **Block Processing**: Transaction and block execution
- **L2 Extensions**: Layer 2 customizations for rollups (when enabled)

## 2. High-Level Flow (LEVM)

The LEVM backend implements the execution flow for Ethereum transactions and blocks, with a clean separation between the interface layer and the core VM logic.

### Primary Entry Points

- **LEVM Wrapper:** [`crates/vm/backends/levm/mod.rs`](./backends/levm/mod.rs) acts as an adapter between the generic `Evm` interface and the internal LEVM implementation.

- **Block Processing Flow:**
  ```
  LEVM::execute_block()
    ├── [Optional] beacon_root_contract_call()    // For Cancun fork+
    ├── [Optional] process_block_hash_history()   // For Prague fork+
    ├── For each transaction:
    │   └── execute_tx()
    ├── [Optional] process_withdrawals()          // If withdrawals present
    └── get_state_transitions()                   // Collect final state changes
  ```

- **Transaction Processing:**  
  [`LEVM::execute_tx`](./backends/levm/mod.rs#L148) handles a single transaction execution:
  ```rust
  // Key steps in transaction execution:
  1. Configure the environment (gas price, coinbase, etc.)
  2. Check balance and nonce requirements
  3. Create VM instance with initial call frame
  4. Execute the transaction through VM::execute()
  5. Process execution output (gas refund, state changes)
  6. Return execution report
  ```

- **State Management:**  
  [`LEVM::get_state_transitions`](./backends/levm/mod.rs#L215) converts the EVM's internal state representation into the format expected by the storage layer:
  ```
  Changed accounts → Collection of AccountUpdate structs
  ```

### Fork Handling

LEVM contains special handling for different Ethereum protocol upgrades ("forks"):

- Pre-Cancun processing
- Cancun-specific logic (beacon roots)
- Prague-specific features (block hash history)

### L2 Integration Points

When built with the `l2` feature flag, LEVM integrates with Layer 2 functionality:

```rust
cfg_if::cfg_if! {
    if #[cfg(not(feature = "l2"))] {
        // L1 specific processing for beacon roots
    } else {
        // L2 specific path
    }
}
```

## 3. Core VM Loop

The heart of LEVM execution resides in the `VM` struct, which implements the core EVM logic - the actual bytecode execution and state manipulation.

### VM Structure and Lifecycle

- **VM Struct Definition:** Defined in [`crates/vm/levm/src/vm.rs`](./levm/src/vm.rs#L161), the VM maintains:
  ```rust
  pub struct VM<'a> {
      pub call_frames: Vec<CallFrame>,       // Stack of execution contexts
      pub env: Environment,                  // Block context (timestamp, coinbase, etc.)
      pub accrued_substate: Substate,        // Tracked state changes for this tx
      pub db: &'a mut GeneralizedDatabase,   // State access layer
      pub tx_kind: TxKind,                   // Call or Create
      pub access_list: AccessList,           // EIP-2930 access list
      pub authorization_list: Option<AuthorizationList>, // EIP-3074 authorization
      pub hooks: Vec<Arc<dyn Hook>>,         // Extension points
      pub cache_backup: CacheDB,             // Original state backup
  }
  ```

- **VM Initialization:** [`VM::new`](./levm/src/vm.rs#L186) performs crucial setup:
  1. Creates initial touched accounts set (sender, recipient, precompiles)
  2. Handles access list entries by warming up accounts/slots
  3. Configures a default hook
  4. Sets up the first call frame based on transaction type:
     - `TxKind::Call` - Sets up a call to an existing contract
     - `TxKind::Create` - Sets up contract creation context

- **Transaction Execution Flow:**
  ```
  VM::execute()
   ├── Restore state from backup (if needed)
   ├── Get initial call frame
   ├── prepare_execution() Hook - Custom pre-execution logic
   ├── Handle CREATE transaction setup (if applicable)
   ├── run_execution() - Core EVM loop
   ├── finalize_execution() Hook - Custom post-execution logic
   └── Return execution report
  ```

- **Core Execution Loop:** [`VM::run_execution`](./levm/src/vm.rs#L301) is where opcodes are processed:
  ```rust
  // Simplified version of the execution loop
  loop {
      let opcode = current_call_frame.next_opcode();
      
      let op_result = self.handle_current_opcode(opcode, current_call_frame);
      
      match op_result {
          Ok(OpcodeResult::Continue { pc_increment }) => {
              current_call_frame.increment_pc_by(pc_increment)?
          }
          Ok(OpcodeResult::Halt) => {
              return self.handle_opcode_result(current_call_frame, backup)
          }
          Err(error) => return self.handle_opcode_error(error, current_call_frame, backup),
      }
  }
  ```

### Execution Context Management

- **Call Frames:** Each `CallFrame` represents one execution context (function call or contract creation)
  - Contains memory, stack, program counter, and other execution data
  - The `call_frames` vector simulates the call stack during contract execution

- **Stateless Execution:** [`VM::stateless_execute`](./levm/src/vm.rs#L367) allows execution without committing state changes:
  ```rust
  let cache_backup = self.db.cache.clone();
  let report = self.execute()?;
  // Restore the cache to its original state
  self.db.cache = cache_backup;
  ```

### Extension Points

- **Hook System:** The [`Hook`](./levm/src/hooks/hook.rs) trait provides a powerful extension mechanism:
  ```rust
  pub trait Hook: Debug + Send + Sync {
      fn prepare_execution(&self, vm: &mut VM, initial_call_frame: &mut CallFrame) -> Result<(), VMError> { Ok(()) }
      fn finalize_execution(&self, vm: &mut VM, initial_call_frame: &CallFrame, report: &mut ExecutionReport) -> Result<(), VMError> { Ok(()) }
      // Other hook points...
  }
  ```

- **Key Hook Points:**
  - `prepare_execution`: Called before transaction execution begins
  - `finalize_execution`: Called after execution completes before returning results
  - `handle_current_opcode`: Can override default opcode behavior (for L2 systems)

## 4. Opcode Dispatch & Handlers

Opcodes are the fundamental building blocks of EVM execution, and LEVM implements a clean dispatch system to handle them efficiently.

### Dispatch Mechanism

- **Opcode Extraction:** Inside the main execution loop, opcodes are extracted from bytecode:
  ```rust
  let opcode = current_call_frame.next_opcode();
  let op_result = self.handle_current_opcode(opcode, current_call_frame);
  ```

- **Dispatch Table:** [`handle_current_opcode`](./levm/src/execution_handlers.rs#L30) in [`execution_handlers.rs`](./levm/src/execution_handlers.rs) implements a match statement that maps each opcode to its handler:
  ```rust
  pub fn handle_current_opcode(&mut self, opcode: u8, call_frame: &mut CallFrame) -> Result<OpcodeResult, VMError> {
      match opcode {
          opcodes::STOP => self.handle_stop(),
          opcodes::ADD => self.handle_add(call_frame),
          opcodes::MUL => self.handle_mul(call_frame),
          // ... handlers for all other opcodes
      }
  }
  ```

### Opcode Implementation Strategy

- **Handler Organization:** Opcode handlers are organized by functional categories:
  - Arithmetic operations (ADD, SUB, MUL, etc.)
  - Memory operations (MLOAD, MSTORE, etc.)
  - Storage operations (SLOAD, SSTORE)
  - Control flow (JUMP, JUMPI)
  - Environmental operations (ADDRESS, BALANCE, etc.)

- **Gas Accounting:** Each handler handles its own gas accounting:
  ```rust
  pub fn handle_add(&mut self, call_frame: &mut CallFrame) -> Result<OpcodeResult, VMError> {
      // Charge gas for operation
      call_frame.use_gas(gas_cost::G_VERYLOW)?;
      
      // Execute the operation
      let a = call_frame.stack_pop()?;
      let b = call_frame.stack_pop()?;
      let c = a.overflowing_add(b).0;
      call_frame.stack_push(c)?;
      
      // Return OpcodeResult with PC increment
      Ok(OpcodeResult::Continue { pc_increment: 1 })
  }
  ```

- **Return Types:** Handlers return `OpcodeResult` which can be:
  - `OpcodeResult::Continue { pc_increment }` - Execution continues with PC increased
  - `OpcodeResult::Halt` - Execution stops for this call frame

### Fork-Specific Behavior

- **Fork Awareness:** Some opcodes have different behavior depending on the active fork:
  ```rust
  // Example of fork-dependent behavior
  if self.env.config.fork >= Fork::London {
      // London+ behavior (e.g., EIP-3529 gas refund changes)
  } else {
      // Pre-London behavior
  }
  ```

- **EIP Implementation:** The codebase tracks which EIPs affect each opcode, making it clear which changes were introduced in which fork.

### Extending Opcode Behavior

- **Hook Point:** The VM provides a hook point for opcode handling:
  ```rust
  for hook in &self.hooks {
      if let Some(result) = hook.handle_current_opcode(self, opcode, call_frame)? {
          return Ok(result);
      }
  }
  ```

  This allows L2 implementations to override or extend specific opcode behaviors, such as adding L2-specific operations or modifying gas costs.

## 5. Gas Accounting & Costs

Gas accounting is crucial to the EVM's economic model, providing a measure of computational resource usage and preventing infinite loops or resource exhaustion attacks.

### Gas Cost Model

- **Cost Constants:** [`gas_cost.rs`](./levm/src/gas_cost.rs) defines the base costs for all operations:
  ```rust
  // Base operation costs
  pub const G_ZERO: u64 = 0;
  pub const G_JUMPDEST: u64 = 1;
  pub const G_BASE: u64 = 2;
  pub const G_VERYLOW: u64 = 3;
  // ...more cost constants
  ```

- **Dynamic Cost Calculations:** Some operations have variable costs:
  ```rust
  // Memory expansion cost
  pub fn memory_gas_cost(size_in_words: u64) -> Result<u64, VMError> {
      // (size_in_words * size_in_words) / 512 + (3 * size_in_words)
      let size_in_words_squared = size_in_words
          .checked_mul(size_in_words)
          .ok_or(VMError::OutOfGas(InternalError::GasOverflow))?;
      // ...calculation continues
  }
  ```

- **Fork-Dependent Costs:** Gas costs change across forks to reflect protocol upgrades:
  ```rust
  pub fn sstore_gas_cost(
      original: U256,
      current: U256,
      new: U256,
      fork: Fork,
      is_cold: bool,
  ) -> Result<(u64, i64), VMError> {
      match fork {
          fork if fork >= Fork::Berlin => {
              // Berlin+ EIP-2929 pricing
          }
          fork if fork >= Fork::Istanbul => {
              // Istanbul EIP-2200 pricing
          }
          // ...other fork implementations
      }
  }
  ```

### Transaction Pricing

- **Floor Gas Price (EIP-7623):** [`VM::get_floor_gas_price`](./levm/src/vm.rs#L336) calculates the minimum required gas based on calldata:
  ```rust
  pub fn get_floor_gas_price(&self, initial_call_frame: &CallFrame) -> Result<u64, VMError> {
      // Get calldata based on transaction type
      let calldata = if self.is_create() {
          &initial_call_frame.bytecode
      } else {
          &initial_call_frame.calldata
      };

      // Calculate tokens in calldata
      let tokens_in_calldata: u64 = gas_cost::tx_calldata(calldata, self.env.config.fork)?
          .checked_div(STANDARD_TOKEN_COST)?;

      // floor_gas_price = TX_BASE_COST + TOTAL_COST_FLOOR_PER_TOKEN * tokens_in_calldata
      let floor_gas_price = tokens_in_calldata * TOTAL_COST_FLOOR_PER_TOKEN + TX_BASE_COST;
      
      Ok(floor_gas_price)
  }
  ```

### Gas Accounting Implementation

- **Gas Tracking:** Each `CallFrame` maintains a running gas counter that's updated with each operation
  
- **Gas Refunds:** Certain operations (like clearing storage) generate gas refunds, tracked in `Environment.refunded_gas`

- **Out of Gas Handling:** When operations would exceed available gas:
  ```rust
  pub fn use_gas(&mut self, amount: u64) -> Result<(), VMError> {
      if self.gas_remaining < amount {
          return Err(VMError::OutOfGas(InternalError::NotEnoughGasRemaining(
              self.gas_remaining,
              amount,
          )));
      }
      self.gas_remaining -= amount;
      Ok(())
  }
  ```

### Optimization Considerations

- **Access Lists (EIP-2930):** The VM implements warm/cold storage access accounting:
  ```rust
  // [EIP-2929] Check if storage slot is "warm" (previously accessed)
  let mut storage_slot_was_cold = false;
  if self.env.config.fork >= Fork::Berlin {
      storage_slot_was_cold = self.accrued_substate
          .touched_storage_slots
          .entry(address)
          .or_default()
          .insert(key);
  }
  ```
  
- **Gas Metering Precision:** Gas calculations handle overflow checking carefully to prevent exploits

## 6. Precompiles

Precompiled contracts offer efficient implementations of complex cryptographic operations.

- **Identification:** [`is_precompile`](./levm/src/precompiles.rs#L30) checks if a target address corresponds to a precompiled contract.
- **Invocation:** Within [`VM::run_execution`](./levm/src/vm.rs#L308), if the target is a precompile, [`execute_precompile`](./levm/src/precompiles.rs#L44) is called.
- **Implementation:** [`crates/vm/levm/src/precompiles.rs`](./levm/src/precompiles.rs) contains the logic for executing each supported precompile based on the active fork.

## 7. State Management

Managing the Ethereum state efficiently and correctly is crucial.

- **Database Interaction:**
    - [`GeneralizedDatabase`](./levm/src/vm.rs#L170): Wraps the persistent store (`dyn Database`) and the in-memory cache (`CacheDB`).
    - [`CacheDB`](./levm/src/db/cache.rs#L15): An in-memory cache (`HashMap<Address, Account>`) holding accounts and their storage slots accessed during the transaction. It sits on top of the persistent `Database`.
- **Substate & Snapshots:**
    - [`Substate`](./levm/src/vm.rs#L37): Tracks transient changes within a transaction or call context (e.g., touched accounts/storage, self-destructs).
    - [`StateBackup`](./levm/src/vm.rs#L48): Used to snapshot the `CacheDB`, `Substate`, gas refund counter, and transient storage before a sub-call, allowing reversion if the call fails. [`VM::restore_state`](./levm/src/vm.rs#L329) applies the backup.

## 8. Storage Access

Interaction with account storage follows specific rules.

- **Read:** [`VM::access_storage_slot`](./levm/src/vm.rs#L431) retrieves a storage slot value, potentially loading it from the persistent store into the cache and marking it as accessed in the `Substate`.
- **Write:** [`VM::update_account_storage`](./levm/src/vm.rs#L474) modifies a storage slot's `current_value` within the cached `Account`.

## 9. Utilities & Helpers

Common functions assist in VM operations.

- **General Utilities:** [`crates/vm/levm/src/utils.rs`](./levm/src/utils.rs) contains various helper functions (e.g., address calculation, byte manipulation).
- **Account Loading:** [`get_account`](./levm/src/utils.rs#L10) and [`get_account_mut_vm`](./levm/src/utils.rs#L36) provide convenient ways to access account data, handling the cache lookup and potential loading from the persistent store.

## 10. Comparison with REVM

LEVM is one backend; REVM is another popular Rust EVM implementation used for comparison and as an alternative.

- **REVM Wrapper:** [`crates/vm/backends/revm/mod.rs`](./backends/revm/mod.rs) provides the integration layer for REVM.
- **Key Difference:** While both implement the `EvmEngine` trait, the internal execution logic and state management differ. A notable difference is how state transitions are collected: compare [`REVM::get_state_transitions`](./backends/revm/mod.rs#L178) with [`LEVM::get_state_transitions`](./backends/levm/mod.rs#L215).

## 11. Benchmarks & Tests

Ensuring correctness and performance is vital.

- **EF Tests:** The Ethereum Foundation tests are run via Makefiles ([`crates/vm/levm/Makefile`](./levm/Makefile) and [`cmd/ef_tests`](../../cmd/ef_tests)) to validate correctness against specifications.
- **Benchmarks:** [`crates/vm/levm/bench/revm_comparison/src/lib.rs`](./levm/bench/revm_comparison/src/lib.rs) contains benchmarks comparing LEVM performance against REVM for specific operations. Performance metrics are tracked in the [LEVM README](./levm/README.md#performance-metrics).

## 12. Extensibility (Hooks & L2)

LEVM is designed with extensibility in mind, particularly for Layer 2 solutions.

- **Hooks:** The [`Hook`](./levm/src/hooks/hook.rs) trait is the primary mechanism for customization, allowing external code (like L2 system contracts) to modify VM behavior at specific points.
- **L2 Integration:** [`generic_system_contract_levm`](./backends/levm/mod.rs#L253) is an example of how hooks can be used to integrate L2-specific functionality (like pre-deploys or special transaction types).
