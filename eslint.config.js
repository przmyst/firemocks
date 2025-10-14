module.exports = {
	rules: {
		'quote-props': ['error', 'as-needed'],
		semi: ['error', 'never'],
		quotes: ['error', 'single'],
		indent: ['error', 'tab'],
		'comma-dangle': ['error', 'never'],
		'array-element-newline': ['error', {
			ArrayExpression: 'consistent',
			ArrayPattern: {
				minItems: 3
			}
		}],
		'object-property-newline': ['error', {
			allowAllPropertiesOnSameLine: false
		}],
		'no-multiple-empty-lines': ['error', {
			max: 1,
			maxEOF: 1
		}],
		'object-curly-newline': ['error', 'always'],
		'no-multi-spaces': ['error', {
			ignoreEOLComments: false
		}]
	}
}
