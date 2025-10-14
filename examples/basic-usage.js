require('dotenv').config({
	path: '../.env'
})

const {
	Interface,
	hexlify,
	toUtf8Bytes
} = require('ethers')

const {
	Fireblocks,
	TransactionOperation,
	TransferPeerPathType
} = require('..')

const ExampleCounterAbi = require('./abis/ExampleCounter.json')
const dotenv = require('dotenv')

function findSignerSummary(signers, vaultId) {
	if (!vaultId) {
		return null
	}
	return signers.find((entry) => String(entry.id) === String(vaultId)) || null
}

async function callViewFunction(provider, contractInterface, contractAddress, fragment, args = []) {
	if (!provider) {
		throw new Error('A provider is required to call contract view functions')
	}
	const data = contractInterface.encodeFunctionData(fragment, args)
	const response = await provider.call({
		to: contractAddress,
		data
	})
	return contractInterface.decodeFunctionResult(fragment, response)
}

async function demonstrateRawMessageSignature(client, adminVaultId) {
	console.log('\n▶ Signing a raw message...')

	const response = await client.createTransaction({
		transactionRequest: {
			note: 'Example raw message request',
			operation: TransactionOperation.Raw,
			source: adminVaultId
				? {
					type: TransferPeerPathType.VaultAccount,
					id: adminVaultId
				}
				: undefined,
			extraParameters: {
				rawMessageData: {
					messages: [
						{
							content: hexlify(toUtf8Bytes('Hello from Firemocks!'))
						}
					]
				}
			}
		}
	})

	response.data.signedMessages.forEach((message, index) => {
		console.log(`  Message #${index + 1}:`, message.content)
		console.log('  Signature:', message.signature.fullSig)
	})

	return response.data.id
}

async function ensureOperatorRole(client, contractInterface, contractAddress, adminVaultId, operatorSummary) {
	if (!operatorSummary) {
		return null
	}

	const provider = client.provider || client.signer.provider
	const [operatorRole] = await callViewFunction(
		provider,
		contractInterface,
		contractAddress,
		'OPERATOR_ROLE'
	)
	const [hasRole] = await callViewFunction(
		provider,
		contractInterface,
		contractAddress,
		'hasRole',
		[operatorRole, operatorSummary.address]
	)

	if (hasRole) {
		console.log(`  Operator already has role assignment (${operatorSummary.address}).`)
		return null
	}

	console.log(`  Granting operator role to ${operatorSummary.address}...`)
	const grantOperatorCalldata = contractInterface.encodeFunctionData('grantOperator', [operatorSummary.address])

	const response = await client.createTransaction({
		transactionRequest: {
			note: 'Grant operator role',
			operation: TransactionOperation.ContractCall,
			source: {
				type: TransferPeerPathType.VaultAccount,
				id: adminVaultId
			},
			to: contractAddress,
			extraParameters: {
				contractCallData: grantOperatorCalldata
			},
			gasLimit: '250000'
		}
	})

	console.log('    Grant transaction hash:', response.data.txHash)
	return response.data.txHash
}

async function demonstrateRoleManagedContractCalls(client, contractAddress, adminVaultId, operatorVaultId) {
	console.log('\n▶ Managing contract roles and interactions...')

	const contractInterface = new Interface(ExampleCounterAbi)
	const provider = client.provider || client.signer.provider
	if (!provider) {
		throw new Error('A provider is required for contract interactions. Set RPC_URL or pass rpcUrl to Fireblocks.')
	}

	const adminSummary = findSignerSummary(client.signerSummaries, adminVaultId)
	const operatorSummary = findSignerSummary(client.signerSummaries, operatorVaultId)

	if (!adminSummary) {
		throw new Error(`Admin signer with vault id "${adminVaultId}" was not found. Check your SIGNER_PRIVATE_KEY or SIGNER_PRIVATE_KEY_${adminVaultId} environment variables.`)
	}

	if (!operatorSummary) {
		console.warn('⚠️  Skipping operator interactions because no operator signer is configured. Set SIGNER_PRIVATE_KEY_<operator vault id> to enable this example.')
		return {
			grantTxHash: null,
			incrementTxHash: null,
			resetTxHash: null
		}
	}

	const [adminRole] = await callViewFunction(provider, contractInterface, contractAddress, 'ADMIN_ROLE')
	const [operatorRole] = await callViewFunction(provider, contractInterface, contractAddress, 'OPERATOR_ROLE')

	console.log('  Role identifiers:')
	console.log('    ADMIN_ROLE:', adminRole)
	console.log('    OPERATOR_ROLE:', operatorRole)

	const [currentValueBefore] = await callViewFunction(provider, contractInterface, contractAddress, 'value')
	console.log('  Current counter value:', currentValueBefore.toString())

	const grantTxHash = await ensureOperatorRole(client, contractInterface, contractAddress, adminVaultId, operatorSummary)

	console.log(`  Operator (${operatorSummary.address}) incrementing counter...`)
	const incrementCalldata = contractInterface.encodeFunctionData('increment', [1n])
	const incrementResponse = await client.createTransaction({
		transactionRequest: {
			note: 'Increment counter as operator',
			operation: TransactionOperation.ContractCall,
			source: {
				type: TransferPeerPathType.VaultAccount,
				id: operatorVaultId
			},
			to: contractAddress,
			extraParameters: {
				contractCallData: incrementCalldata
			},
			gasLimit: '250000'
		}
	})

	console.log('    Increment transaction hash:', incrementResponse.data.txHash)

	console.log(`  Admin (${adminSummary.address}) resetting counter...`)
	const resetCalldata = contractInterface.encodeFunctionData('reset')
	const resetResponse = await client.createTransaction({
		transactionRequest: {
			note: 'Reset counter as admin',
			operation: TransactionOperation.ContractCall,
			source: {
				type: TransferPeerPathType.VaultAccount,
				id: adminVaultId
			},
			to: contractAddress,
			extraParameters: {
				contractCallData: resetCalldata
			},
			gasLimit: '250000'
		}
	})

	console.log('    Reset transaction hash:', resetResponse.data.txHash)

	const [currentValueAfter] = await callViewFunction(provider, contractInterface, contractAddress, 'value')
	console.log('  Counter value after reset:', currentValueAfter.toString())

	return {
		grantTxHash,
		incrementTxHash: incrementResponse.data.txHash,
		resetTxHash: resetResponse.data.txHash
	}
}

async function demonstrateTransfer(client, recipientAddress, sourceVaultId) {
	console.log('\n▶ Sending a transfer transaction...')

	const response = await client.createTransaction({
		transactionRequest: {
			note: 'Send 0.0001 ETH to a recipient',
			operation: TransactionOperation.Transfer,
			source: {
				type: TransferPeerPathType.VaultAccount,
				id: sourceVaultId
			},
			destination: {
				type: TransferPeerPathType.OneTimeAddress,
				oneTimeAddress: {
					address: recipientAddress
				}
			},
			amount: '0.0001'
		}
	})

	console.log('  Transaction hash:', response.data.txHash)
	console.log('  Receipt status:', response.data.receipt?.status)

	return response.data.txHash
}

async function main() {
	const client = new Fireblocks({
		chain: process.env.FIREBLOCKS_CHAIN || 'base-sepolia',
		rpcUrl: process.env.RPC_URL || 'https://sepolia.base.org'
	})

	console.log('Using signer address:', client.signerAddress)
	console.log('Available vault accounts:', client.signerSummaries)

	const defaultAdminId = process.env.ADMIN_VAULT_ID
                || process.env.FIREBLOCKS_ADMIN_VAULT_ID
                || process.env.FIREBLOCKS_VAULT_ACCOUNT_ID
                || (client.signerSummaries[0]?.id ?? '0')
	const operatorFallback = client.signerSummaries.find((summary) => String(summary.id) !== String(defaultAdminId))
	const defaultOperatorId = process.env.OPERATOR_VAULT_ID
                || process.env.FIREBLOCKS_OPERATOR_VAULT_ID
                || (operatorFallback ? operatorFallback.id : null)

	console.log('Admin vault id:', defaultAdminId)
	console.log('Operator vault id:', defaultOperatorId || '(not configured)')

	const rawTxId = await demonstrateRawMessageSignature(client, defaultAdminId)
	console.log('  Raw message transaction ID:', rawTxId)

	const contractAddress = process.env.COUNTER_CONTRACT_ADDRESS
	if (contractAddress) {
		const {
			grantTxHash,
			incrementTxHash,
			resetTxHash
		} = await demonstrateRoleManagedContractCalls(client, contractAddress, defaultAdminId, defaultOperatorId)
		if (grantTxHash) {
			console.log('  Grant operator transaction hash:', grantTxHash)
		}
		if (incrementTxHash) {
			console.log('  Operator increment transaction hash:', incrementTxHash)
		}
		if (resetTxHash) {
			console.log('  Admin reset transaction hash:', resetTxHash)
		}
	} else {
		console.warn('\n⚠️  Skipping contract call example. Set COUNTER_CONTRACT_ADDRESS to run it.')
	}

	const recipient = process.env.TRANSFER_RECIPIENT || client.signerAddress
	const transferHash = await demonstrateTransfer(client, recipient, defaultAdminId)
	console.log('  Transfer transaction hash:', transferHash)

	console.log('\nAll example transactions completed.')
}

main().catch((error) => {
	console.error('Example execution failed:', error)
	process.exitCode = 1
})
