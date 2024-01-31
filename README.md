# 🔥 Napalm Package: napalm-base
This is an automatically generated report on the detectors in this package.

Some quick stats:
  - 3 collections
  - 19 detectors

## optimisations modules:
  | ID | Description | Severity |
  | ------ | ----------- | -------- |
  | storage-variable-bool | Using bool as a storage variable is more expensive than uint256 or other types that fill a whole 256 bit word. | INFO |
  | cache-array-length-loop | The compiler will re-execute each instance of .length for each loop iteration. Caching the length will reduce the amount of sloads necessary to perform the operation. | INFO |
  | initialize-default-value | Initializing variables with their default value leads to unnecessary gas expenditure | INFO |

## indicators modules:
  | ID | Description | Severity |
  | ------ | ----------- | -------- |
  | math-in-unsafe-block | Mathematical operators in unsafe blocks are not checked for under flows or overflows. | INFO |
  | use-of-privilege-to-protect-sensitive-functions | It's necessary to implement proper controls on wallet security when  privileged functions are used to protect sensitive functions. | INFO |
  | import-safetransfer-solmate | Solmate's SafeTransferLib doesn't perform the same checks SafeERC20 does, in particular it doesn't check if a contract exists leading to potential vulnerabilities. | INFO |
  | block-number-l2 | Solidity's block.number semantics are not consistent on L2s, leading to potential vulnerabilities. | INFO |
  | push-0-solc-version | Your solidity version uses PUSH0 which is not supported by all chains. | INFO |

## detectors modules:
  | ID | Description | Severity |
  | ------ | ----------- | -------- |
  | int-cast-block-timestamp | Casting block.timestamp can lead to reduced precision and unexpected behavior, consider not casting instead. | WARNING |
  | use-of-unsafe-erc20-functions | The ERC20 implementation does not automatically include checks that ensure the success of the operation. Using the OpenZeppelin's SafeERC20 library is recommended. | INFO |
  | block-timestamp-swap | Passing block.timestamp as the deadline effectively removes the deadline functionality which prevents malicious validators from holding back transactions to execute them at a later time. | WARNING |
  | dos-push-array-loop | Potential Denial of Service when users can push to an array that's irreducible and looped over. | HIGH |
  | chainlink-circuit-breaker | Vulnerable to exploitation in case of a Chainlink circuit breaker event. | HIGH |
  | unchecked-create-2 | Unchecked return value for CREATE2 call. | MEDIUM |
  | unchecked-approve | Unchecked token approve | HIGH |
  | unchecked-equation-modifier | Potential lack of input control due to missing requires checks. | HIGH |
  | erc721-transfer-from-stuck | transferFrom call on ERC721 can lead to stuck tokens | HIGH |
  | erc721-mint-stuck | _mint call on ERC721 can lead to stuck tokens | HIGH |
  | erc20-approve-call | Potential Denial of Service when tokens don't implement approve() consistently ( e.g. USDT ). | HIGH |
