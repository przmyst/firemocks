require('dotenv').config()

const {
	randomUUID
} = require('crypto')
const {
	Wallet,
	JsonRpcProvider,
	getAddress,
	getBytes,
	isHexString,
	hexlify,
	parseEther,
	keccak256
} = require('ethers')

const chainConfigData = require('./chain-config.json')

const DEFAULT_CHAIN_KEY = chainConfigData.defaultChainKey
        || Object.keys(chainConfigData.chains || {
        })[0]
        || 'base-sepolia'

const CHAIN_CONFIGURATIONS = Object.freeze(Object.fromEntries(
	Object.entries(chainConfigData.chains || {
	}).map(([key, value]) => [
		key,
		Object.freeze({
			...value,
			nativeCurrency: value.nativeCurrency
				? Object.freeze({
					...value.nativeCurrency
				})
				: null
		})
	])
))

const CHAIN_ALIAS_LOOKUP = (() => {
	const map = new Map()
	Object.keys(CHAIN_CONFIGURATIONS).forEach((key) => {
		const normalized = normalizeChainKey(key)
		if (normalized) {
			map.set(normalized, key)
		}
		const compact = normalized.replace(/-/g, '')
		if (compact && !map.has(compact)) {
			map.set(compact, key)
		}
	})
	Object.entries(chainConfigData.aliases || {
	}).forEach(([alias, target]) => {
		const normalized = normalizeChainKey(alias)
		if (!normalized || !CHAIN_CONFIGURATIONS[target]) {
			return
		}
		if (!map.has(normalized)) {
			map.set(normalized, target)
		}
		const compact = normalized.replace(/-/g, '')
		if (compact && !map.has(compact)) {
			map.set(compact, target)
		}
	})
	return map
})()

const DEFAULT_CHAIN_CONFIGURATION = CHAIN_CONFIGURATIONS[DEFAULT_CHAIN_KEY]
        || Object.values(CHAIN_CONFIGURATIONS)[0]
        || null

function normalizeChainKey(value) {
	if (value == null) {
		return ''
	}
	const trimmed = String(value).trim().toLowerCase()
	if (!trimmed) {
		return ''
	}
	if (/^[0-9]+$/.test(trimmed)) {
		return trimmed
	}
	return trimmed
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-+|-+$/g, '')
}

function findKnownChainByChainId(chainId) {
	const numeric = Number(chainId)
	if (!Number.isFinite(numeric)) {
		return null
	}
	return Object.values(CHAIN_CONFIGURATIONS).find((entry) => entry.chainId === numeric) || null
}

function tryParseJson(value) {
	if (typeof value !== 'string') {
		return null
	}
	const trimmed = value.trim()
	if (!trimmed) {
		return null
	}
	if (!/^[\[{]/.test(trimmed)) {
		return null
	}
	try {
		return JSON.parse(trimmed)
	} catch (err) {
		return null
	}
}

function cloneChainConfiguration(config) {
	if (!config) {
		return null
	}
	return {
		...config,
		nativeCurrency: config.nativeCurrency
			? {
				...config.nativeCurrency
			}
			: null
	}
}

function coerceChainConfiguration(candidate) {
	if (!candidate) {
		return null
	}
	if (typeof candidate === 'string') {
		const parsed = tryParseJson(candidate)
		if (parsed) {
			return coerceChainConfiguration(parsed)
		}
		const normalized = normalizeChainKey(candidate)
		if (!normalized) {
			return null
		}
		if (/^[0-9]+$/.test(normalized)) {
			const byId = findKnownChainByChainId(normalized)
			if (byId) {
				return cloneChainConfiguration(byId)
			}
		}
		const alias = CHAIN_ALIAS_LOOKUP.get(normalized)
		if (alias && CHAIN_CONFIGURATIONS[alias]) {
			return cloneChainConfiguration(CHAIN_CONFIGURATIONS[alias])
		}
		return null
	}
	if (typeof candidate === 'number') {
		const byId = findKnownChainByChainId(candidate)
		if (byId) {
			return cloneChainConfiguration(byId)
		}
		return null
	}
	if (typeof candidate === 'object') {
		const chainLike = candidate.chain
                || candidate.key
                || candidate.id
                || candidate.name
                || candidate.network
		if (chainLike) {
			const normalized = normalizeChainKey(chainLike)
			const alias = CHAIN_ALIAS_LOOKUP.get(normalized)
			if (alias && CHAIN_CONFIGURATIONS[alias]) {
				return {
					...cloneChainConfiguration(CHAIN_CONFIGURATIONS[alias]),
					...candidate,
					key: alias,
					id: alias
				}
			}
		}
		if (candidate.chainId != null) {
			const byId = findKnownChainByChainId(candidate.chainId)
			if (byId) {
				return {
					...cloneChainConfiguration(byId),
					...candidate,
					key: byId.key,
					id: byId.id
				}
			}
		}
		if (candidate.rpcUrl) {
			const keyCandidate = normalizeChainKey(
				candidate.key
                                || candidate.id
                                || candidate.name
                                || candidate.chain
                                || candidate.network
                                || 'custom'
			)
			return {
				key: keyCandidate || 'custom',
				id: candidate.id || keyCandidate || 'custom',
				name: candidate.name || candidate.displayName || candidate.shortName || keyCandidate || 'Custom',
				displayName: candidate.displayName || candidate.name || candidate.shortName || candidate.id || candidate.chain || candidate.network || 'Custom',
				shortName: candidate.shortName || candidate.name || candidate.displayName || candidate.id || candidate.chain || candidate.network || 'Custom',
				chainId: candidate.chainId != null ? Number(candidate.chainId) : null,
				rpcUrl: candidate.rpcUrl,
				explorerUrl: candidate.explorerUrl || candidate.blockExplorerUrl || candidate.blockExplorer || null,
				nativeCurrency: candidate.nativeCurrency ? {
					...candidate.nativeCurrency
				} : null
			}
		}
		return null
	}
	return null
}

function resolveRpcOverride(preferences = {
}, env = process.env, chainKey) {
	if (preferences.rpcUrl) {
		return preferences.rpcUrl
	}
	if (preferences.providerUrl) {
		return preferences.providerUrl
	}
	if (preferences.rpcEndpoint) {
		return preferences.rpcEndpoint
	}
	const source = env || process.env || {
	}
	if (source.RPC_URL) {
		return source.RPC_URL
	}
	if (chainKey) {
		const upper = String(chainKey).toUpperCase().replace(/[^A-Z0-9]+/g, '_')
		const candidates = [
			`${upper}_RPC_URL`,
			`${upper}_RPC_ENDPOINT`,
			`${upper}_RPC`
		]
		for (const key of candidates) {
			if (source[key]) {
				return source[key]
			}
		}
	}
	return null
}

function finalizeChainConfiguration(config, preferences = {
}, env = process.env) {
	const base = cloneChainConfiguration(config)
	const overrideRpc = resolveRpcOverride(preferences, env, base?.key)
	if (overrideRpc) {
		base.rpcUrl = overrideRpc
	}
	return Object.freeze(base)
}

function resolveChainConfiguration(preferences = {
}, env = process.env) {
	const attempts = []
	if (preferences.chainConfig) {
		attempts.push(preferences.chainConfig)
	}
	if (preferences.chainConfiguration) {
		attempts.push(preferences.chainConfiguration)
	}
	if (preferences.chain) {
		attempts.push(preferences.chain)
	}
	if (preferences.network) {
		attempts.push(preferences.network)
	}
	if (preferences.chainId != null) {
		attempts.push(preferences.chainId)
	}
	if (preferences.networkId != null) {
		attempts.push(preferences.networkId)
	}
	const source = env || process.env || {
	}
	const envCandidates = [
		source.FIREBLOCKS_CHAIN_CONFIGURATION,
		source.FIREBLOCKS_CHAIN_CONFIG,
		source.CHAIN_CONFIGURATION,
		source.CHAIN_CONFIG,
		source.FIREBLOCKS_CHAIN,
		source.CHAIN,
		source.NETWORK,
		source.FIREBLOCKS_CHAIN_ID,
		source.CHAIN_ID,
		source.NETWORK_ID
	]
	envCandidates.forEach((candidate) => {
		if (candidate != null && candidate !== '') {
			attempts.push(candidate)
		}
	})
	for (const candidate of attempts) {
		const config = coerceChainConfiguration(candidate)
		if (config) {
			return finalizeChainConfiguration(config, preferences, source)
		}
	}
	if (!DEFAULT_CHAIN_CONFIGURATION) {
		throw new Error('No chain configurations available')
	}
	return finalizeChainConfiguration(DEFAULT_CHAIN_CONFIGURATION, preferences, source)
}

const BasePath = Object.freeze({
	US: 'US',
	EU: 'EU',
	APAC: 'APAC',
	SGP: 'SGP'
})

const TransactionOperation = Object.freeze({
	Raw: 'RAW',
	Transfer: 'TRANSFER',
	ContractCall: 'CONTRACT_CALL'
})

const TransferPeerPathType = Object.freeze({
	VaultAccount: 'VAULT_ACCOUNT',
	OneTimeAddress: 'ONE_TIME_ADDRESS',
	ExternalWallet: 'EXTERNAL_WALLET',
	Unknown: 'UNKNOWN'
})

function normalizePrivateKey(rawKey) {
	console.log(rawKey)
	if (!rawKey) {
		throw new Error('Fireblocks client requires a signing private key')
	}
	const trimmed = String(rawKey).trim()
	if (/^0x[0-9a-fA-F]{64}$/.test(trimmed)) {
		return trimmed
	}
	if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
		return `0x${trimmed}`
	}
	throw new Error('Fireblocks client private key must be 64 hex characters')
}

function ensureHex(value) {
	if (value == null) {
		return null
	}
	if (typeof value === 'string') {
		const trimmed = value.trim()
		if (!trimmed) {
			return null
		}
		return trimmed.startsWith('0x') ? trimmed : `0x${trimmed}`
	}
	return hexlify(value)
}

function parseAmount(value) {
	if (value == null) {
		return 0n
	}
	if (typeof value === 'bigint') {
		return value
	}
	if (typeof value === 'number') {
		if (!Number.isFinite(value)) {
			throw new Error('Amount must be a finite number')
		}
		return parseAmount(value.toString())
	}
	const stringValue = String(value).trim()
	if (!stringValue) {
		return 0n
	}
	if (/^0x[0-9a-fA-F]+$/.test(stringValue)) {
		return BigInt(stringValue)
	}
	if (/^[0-9]+$/.test(stringValue)) {
		return BigInt(stringValue)
	}
	return parseEther(stringValue)
}

function parseQuantity(value) {
	if (value == null || value === '') {
		return undefined
	}
	if (typeof value === 'bigint') {
		return value
	}
	const stringValue = String(value).trim()
	if (!stringValue) {
		return undefined
	}
	if (/^0x[0-9a-fA-F]+$/.test(stringValue)) {
		return BigInt(stringValue)
	}
	if (/^[0-9]+$/.test(stringValue)) {
		return BigInt(stringValue)
	}
	return parseEther(stringValue)
}

function initializeSigners(options = {
}, sharedProvider) {
	const definitions = collectSignerDefinitions(options)
	if (!definitions.length) {
		return {
			primarySigner: null,
			signersById: new Map(),
			signersByAddress: new Map(),
			signerSummaries: []
		}
	}

	const byId = new Map()
	const byAddress = new Map()
	const summaries = []
	let primary = null

	definitions.forEach((definition, index) => {
		const privateKey = normalizePrivateKey(definition.privateKey)
		const signer = new Wallet(privateKey, sharedProvider)
		const vaultId = definition.id ?? String(index)
		if (!byId.has(vaultId)) {
			byId.set(vaultId, signer)
		}
		byAddress.set(getAddress(signer.address), signer)
		const existingIndex = summaries.findIndex((entry) => entry.id === vaultId)
		if (existingIndex >= 0) {
			summaries[existingIndex] = {
				id: vaultId,
				address: signer.address
			}
		} else {
			summaries.push({
				id: vaultId,
				address: signer.address
			})
		}
		if (!primary || definition.isPrimary) {
			primary = signer
		}
	})

	if (!primary) {
		primary = byId.values().next().value
	}

	return {
		primarySigner: primary,
		signersById: byId,
		signersByAddress: byAddress,
		signerSummaries: summaries
	}
}

function collectSignerDefinitions(options = {
}) {
	const definitions = []
	const seenIds = new Set()

	function addDefinition(id, privateKey, isPrimary = false) {
		if (!privateKey) return
		const normalizedId = id != null ? String(id) : undefined
		if (normalizedId && seenIds.has(normalizedId)) {
			const existingIndex = definitions.findIndex((def) => def.id === normalizedId)
			if (existingIndex >= 0) {
				definitions[existingIndex] = {
					id: normalizedId,
					privateKey,
					isPrimary: definitions[existingIndex].isPrimary || isPrimary
				}
				return
			}
		}
		if (normalizedId) {
			seenIds.add(normalizedId)
		}
		definitions.push({
			id: normalizedId,
			privateKey,
			isPrimary
		})
	}

	const defaultVaultId = process.env.FIREBLOCKS_VAULT_ACCOUNT_ID || '0'

	if (process.env.SIGNER_PRIVATE_KEY) {
		addDefinition(defaultVaultId, process.env.SIGNER_PRIVATE_KEY, true)
	}
	
	if(process.env.SIGNER_PRIVATE_KEYS) {
		parseSignerDefinitions(process.env.SIGNER_PRIVATE_KEYS).forEach((entry) => {
			addDefinition(entry.id, entry.privateKey, entry.isPrimary)
		})
	}

	Object.keys(process.env)
		.filter((key) => key.startsWith('SIGNER_PRIVATE_KEY_'))
		.sort()
		.forEach((key) => {
			const id = key.replace('SIGNER_PRIVATE_KEY_', '')
			addDefinition(id, process.env[key])
		})

	return definitions
}

function parseSignerDefinitions(value) {
	if (value == null) return []
	if (typeof value === 'string') {
		return parseSignerPrivateKeysEnv(value)
	}

	try {
		return parseSignerPrivateKeysEnv(JSON.stringify(value))
	} catch (err) {
		if (Array.isArray(value)) {
			return value.flatMap((item, index) => {
				if (!item) return []
				if (typeof item === 'string') {
					return [{
						id: String(index),
						privateKey: item
					}]
				}
				if (typeof item === 'object') {
					const id = item.id ?? item.vaultId ?? item.vault_id ?? String(index)
					const privateKey = item.privateKey ?? item.key ?? item.secretKey ?? item.secret
					if (privateKey) {
						return [{
							id,
							privateKey,
							isPrimary: Boolean(item.isPrimary || item.primary)
						}]
					}
				}
				return []
			})
		}
	}

	if (typeof value === 'object') {
		if (value.privateKey || value.secretKey || value.key) {
			const id = value.id ?? value.vaultId ?? value.vault_id
			const privateKey = value.privateKey ?? value.secretKey ?? value.key
			return privateKey
				? [{
					id: id != null ? String(id) : undefined,
					privateKey,
					isPrimary: Boolean(value.isPrimary || value.primary)
				}]
				: []
		}

		return Object.entries(value).flatMap(([id, item]) => {
			if (!item) return []
			if (typeof item === 'string') {
				return [{
					id: String(id),
					privateKey: item
				}]
			}
			if (typeof item === 'object') {
				const privateKey = item.privateKey ?? item.key ?? item.secretKey ?? item.secret
				if (privateKey) {
					return [{
						id: String(id),
						privateKey,
						isPrimary: Boolean(item.isPrimary || item.primary)
					}]
				}
			}
			return []
		})
	}

	return []
}

function parseSignerPrivateKeysEnv(rawValue) {
	const entries = []
	const trimmed = String(rawValue || '').trim()
	if (!trimmed) return entries

	const tryJson = (() => {
		try {
			return JSON.parse(trimmed)
		} catch (err) {
			return undefined
		}
	})()

	if (tryJson) {
		if (Array.isArray(tryJson)) {
			tryJson.forEach((item, index) => {
				if (!item) return
				if (typeof item === 'string') {
					const parsed = parseDelimitedSignerEntry(item, index)
					if (parsed) entries.push(parsed)
					return
				}
				if (typeof item === 'object') {
					const id = item.id ?? item.vaultId ?? item.vault_id
					const privateKey = item.privateKey ?? item.key ?? item.secret
					if (privateKey) {
						entries.push({
							id: id != null ? String(id) : undefined,
							privateKey,
							isPrimary: Boolean(item.isPrimary || item.primary)
						})
					}
				}
			})
		} else if (typeof tryJson === 'object') {
			Object.entries(tryJson).forEach(([id, value]) => {
				if (!value) return
				if (typeof value === 'string') {
					entries.push({
						id: String(id),
						privateKey: value
					})
				} else if (typeof value === 'object' && value.privateKey) {
					entries.push({
						id: String(id),
						privateKey: value.privateKey,
						isPrimary: Boolean(value.isPrimary || value.primary)
					})
				}
			})
		}

		return entries
	}

	trimmed
		.split(/[\n,]/)
		.map((segment) => segment.trim())
		.filter(Boolean)
		.forEach((segment, index) => {
			const parsed = parseDelimitedSignerEntry(segment, index)
			if (parsed) entries.push(parsed)
		})

	return entries
}

function parseDelimitedSignerEntry(segment, index) {
	if (!segment) return null
	const delimiterMatch = segment.match(/[:=]/)
	if (delimiterMatch) {
		const [id, key] = [
			segment.slice(0, delimiterMatch.index).trim(),
			segment.slice(delimiterMatch.index + 1).trim()
		]
		if (!key) return null
		return {
			id: id || undefined,
			privateKey: key
		}
	}
	return {
		id: String(index),
		privateKey: segment
	}
}

function resolveProvider(options = {
}, chainConfig) {
	if (options.provider) {
		return options.provider
	}
	const rpcUrl = options.rpcUrl
        || options.providerUrl
        || options.rpcEndpoint
        || process.env.RPC_URL
        || chainConfig?.rpcUrl
	if (!rpcUrl) {
		return undefined
	}
	const networkish = chainConfig?.chainId != null ? chainConfig.chainId : undefined
	return new JsonRpcProvider(rpcUrl, networkish)
}

function normalizeOperation(rawOperation) {
	if (!rawOperation) {
		return null
	}
	const normalized = String(rawOperation).trim().toUpperCase()
	if (normalized === TransactionOperation.ContractCall) {
		return TransactionOperation.ContractCall
	}
	if (normalized === TransactionOperation.Raw) {
		return TransactionOperation.Raw
	}
	if (normalized === TransactionOperation.Transfer) {
		return TransactionOperation.Transfer
	}
	return normalized
}

class Fireblocks {
	constructor(options = {
	}) {
		this.apiKey = options.apiKey || null
		this.basePath = options.basePath || BasePath.US
		this.chainConfig = resolveChainConfiguration(options)
		this.chain = this.chainConfig.key
		this.chainId = this.chainConfig.chainId ?? null
		this.provider = resolveProvider(options, this.chainConfig)
		const {
			primarySigner,
			signersById,
			signersByAddress,
			signerSummaries
		} = initializeSigners(options, this.provider)

		if (!primarySigner) {
			throw new Error('Fireblocks client requires at least one signer private key')
		}

		this.signer = primarySigner
		this.signerAddress = this.signer.address
		this._signersById = signersById
		this._signersByAddress = signersByAddress
		this.signerSummaries = signerSummaries

		if (options.signerAddress) {
			const expected = getAddress(options.signerAddress)
			if (getAddress(this.signer.address) !== expected) {
				throw new Error('Fireblocks client signer private key does not match the provided signer address')
			}
		}

		this.transactions = {
			createTransaction: (params) => this.createTransaction(params),
			getTransaction: (params) => this.getTransaction(params)
		}

		this._transactions = new Map()
	}

	async createTransaction(params = {
	}) {
		const {
			transactionRequest
		} = params
		if (!transactionRequest || typeof transactionRequest !== 'object') {
			throw new Error('transactionRequest is required')
		}

		const operation = normalizeOperation(transactionRequest.operation)
		const rawMessageData = transactionRequest?.extraParameters?.rawMessageData
            || transactionRequest?.rawMessageData

		if (operation === TransactionOperation.Raw || (rawMessageData && Array.isArray(rawMessageData.messages))) {
			return await this._handleRawMessageTransaction(transactionRequest, rawMessageData)
		}

		if (operation === TransactionOperation.ContractCall || transactionRequest?.extraParameters?.contractCallData) {
			return await this._handleContractCallTransaction(transactionRequest)
		}

		if (operation === TransactionOperation.Transfer) {
			return await this._handleTransferTransaction(transactionRequest)
		}

		throw new Error(`Unsupported transaction operation: ${transactionRequest.operation}`)
	}

	async getTransaction(params = {
	}) {
		const {
			txId
		} = params
		if (!txId) {
			throw new Error('txId is required')
		}
		const record = this._transactions.get(txId)
		if (record) {
			return {
				data: record
			}
		}

		if (this.signer.provider) {
			const receipt = await this.signer.provider.getTransactionReceipt(txId).catch(() => null)
			if (receipt) {
				const derivedRecord = {
					id: txId,
					status: receipt.status === 1 ? 'COMPLETED' : 'FAILED',
					chain: this.chain,
					chainId: this.chainId,
					createdAt: new Date().toISOString(),
					signedMessages: [],
					receipt,
					transactionRequest: null,
					txHash: txId
				}
				this._transactions.set(txId, derivedRecord)
				return {
					data: derivedRecord
				}
			}
		}

		throw new Error(`Transaction ${txId} not found`)
	}

	async _handleRawMessageTransaction(transactionRequest, rawMessageData = {
	}) {
		const txId = randomUUID()
		const createdAt = new Date().toISOString()
		const messages = Array.isArray(rawMessageData.messages) ? rawMessageData.messages : []

		const signer = this._getSignerForTransaction(transactionRequest)

		const signedMessages = []
		for (const msg of messages) {
			const content = ensureHex(msg?.content)
			if (!content || !isHexString(content)) {
				throw new Error('Fireblocks client expected raw message content to be a hex string')
			}

			const messageBytes = getBytes(content)
			const digest = messageBytes.length === 32 ? messageBytes : keccak256(messageBytes)
			const signature = await signer.signingKey.sign(digest)
			signedMessages.push({
				content,
				signature: {
					fullSig: signature.serialized,
					r: signature.r,
					s: signature.s,
					v: signature.v
				}
			})
		}

		const record = {
			id: txId,
			status: 'COMPLETED',
			chain: this.chain,
			chainId: this.chainId,
			createdAt,
			note: transactionRequest.note || null,
			signedMessages,
			transactionRequest,
			receipt: null,
			txHash: null
		}

		this._transactions.set(txId, record)

		return {
			data: record
		}
	}

	async _handleContractCallTransaction(transactionRequest) {
		const signer = this._getSignerForTransaction(transactionRequest)

		if (!signer.provider) {
			throw new Error('Fireblocks client requires a provider to submit contract call transactions')
		}

		const to = this._resolveDestinationAddress(transactionRequest)
		const data = this._resolveContractCallData(transactionRequest)
		if (!data) {
			throw new Error('Contract call transaction requires calldata')
		}

		const value = parseAmount(transactionRequest.amount)
		const gasLimit = parseQuantity(transactionRequest.gasLimit || transactionRequest.gas)
		const maxFeePerGas = parseQuantity(transactionRequest.maxFeePerGas)
		const maxPriorityFeePerGas = parseQuantity(transactionRequest.maxPriorityFeePerGas)
		const gasPrice = parseQuantity(transactionRequest.gasPrice)

		const txRequest = {
			to,
			data,
			value
		}

		if (gasLimit != null) {
			txRequest.gasLimit = gasLimit
		}

		if (gasPrice != null) {
			txRequest.gasPrice = gasPrice
		} else {
			if (maxFeePerGas != null) {
				txRequest.maxFeePerGas = maxFeePerGas
			}
			if (maxPriorityFeePerGas != null) {
				txRequest.maxPriorityFeePerGas = maxPriorityFeePerGas
			}
		}

		const txResponse = await signer.sendTransaction(txRequest)
		const receipt = await txResponse.wait()

		const record = {
			id: txResponse.hash,
			status: receipt.status === 1 ? 'COMPLETED' : 'FAILED',
			chain: this.chain,
			chainId: this.chainId,
			createdAt: new Date().toISOString(),
			note: transactionRequest.note || null,
			signedMessages: [],
			transactionRequest,
			receipt,
			txHash: txResponse.hash
		}

		this._transactions.set(record.id, record)

		return {
			data: record
		}
	}

	async _handleTransferTransaction(transactionRequest) {
		const signer = this._getSignerForTransaction(transactionRequest)

		if (!signer.provider) {
			throw new Error('Fireblocks client requires a provider to submit transfer transactions')
		}

		const destination = this._resolveDestinationAddress(transactionRequest)
		const value = parseAmount(transactionRequest.amount)
		const gasLimit = parseQuantity(transactionRequest.gasLimit || transactionRequest.gas)
		const gasPrice = parseQuantity(transactionRequest.gasPrice)
		const maxFeePerGas = parseQuantity(transactionRequest.maxFeePerGas)
		const maxPriorityFeePerGas = parseQuantity(transactionRequest.maxPriorityFeePerGas)

		const txRequest = {
			to: destination,
			value
		}

		if (gasLimit != null) {
			txRequest.gasLimit = gasLimit
		}
		if (gasPrice != null) {
			txRequest.gasPrice = gasPrice
		} else {
			if (maxFeePerGas != null) {
				txRequest.maxFeePerGas = maxFeePerGas
			}
			if (maxPriorityFeePerGas != null) {
				txRequest.maxPriorityFeePerGas = maxPriorityFeePerGas
			}
		}

		const txResponse = await signer.sendTransaction(txRequest)
		const receipt = await txResponse.wait()

		const record = {
			id: txResponse.hash,
			status: receipt.status === 1 ? 'COMPLETED' : 'FAILED',
			chain: this.chain,
			chainId: this.chainId,
			createdAt: new Date().toISOString(),
			note: transactionRequest.note || null,
			signedMessages: [],
			transactionRequest,
			receipt,
			txHash: txResponse.hash
		}

		this._transactions.set(record.id, record)

		return {
			data: record
		}
	}

	_resolveDestinationAddress(transactionRequest) {
		const destination = transactionRequest.destination
		if (destination?.type === TransferPeerPathType.OneTimeAddress && destination.oneTimeAddress?.address) {
			return getAddress(destination.oneTimeAddress.address)
		}
		if (destination?.type === TransferPeerPathType.ExternalWallet && destination.externalWallet?.address) {
			return getAddress(destination.externalWallet.address)
		}
		if (transactionRequest.destinationAddress) {
			return getAddress(transactionRequest.destinationAddress)
		}
		if (transactionRequest.to) {
			return getAddress(transactionRequest.to)
		}
		throw new Error('Destination address is required for Fireblocks contract call transactions')
	}

	_resolveContractCallData(transactionRequest) {
		if (transactionRequest?.extraParameters?.contractCallData) {
			const raw = transactionRequest.extraParameters.contractCallData
			if (typeof raw === 'string') {
				return ensureHex(raw)
			}
			if (raw && typeof raw === 'object' && raw.calldata) {
				return ensureHex(raw.calldata)
			}
		}
		if (transactionRequest.contractCallData) {
			if (typeof transactionRequest.contractCallData === 'string') {
				return ensureHex(transactionRequest.contractCallData)
			}
			if (transactionRequest.contractCallData?.calldata) {
				return ensureHex(transactionRequest.contractCallData.calldata)
			}
		}
		if (transactionRequest.data) {
			return ensureHex(transactionRequest.data)
		}
		return null
	}

	_getSignerForTransaction(transactionRequest) {
		const source = transactionRequest?.source
		if (source?.type === TransferPeerPathType.VaultAccount && source.id != null) {
			const signer = this._signersById.get(String(source.id))
			if (signer) {
				return signer
			}
		}

		const fromAddress = transactionRequest?.from
            || transactionRequest?.fromAddress
            || transactionRequest?.sourceAddress
		if (fromAddress) {
			try {
				const signer = this._signersByAddress.get(getAddress(fromAddress))
				if (signer) {
					return signer
				}
			} catch (err) {
				// ignore invalid
			}
		}

		return this.signer
	}
}

module.exports = {
	Fireblocks,
	BasePath,
	TransactionOperation,
	TransferPeerPathType,
	ChainConfigurations: CHAIN_CONFIGURATIONS,
	resolveChainConfiguration,
	normalizeChainKey,
	coerceChainConfiguration
}
