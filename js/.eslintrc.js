module.exports = {
  extends: [
    'eslint:recommended',
  ],
  ignorePatterns: [
    'dist/*'
  ],
  parser: '@typescript-eslint/parser',
  "parserOptions": {
      "ecmaVersion": 2018
  },
  "plugins": [
    "import",
    "simple-import-sort",
    "testing-library",
    '@typescript-eslint'
  ],
  "env": {
    "browser": true,
    "node": true,
    "jest": true,
  },
  "globals": {
    "__DEV__": "readonly",
    "__TEST__": "readonly",
    "__PROD__": "readonly",
    "$": "writable",
  },
  "rules": {
    "linebreak-style": [
      "error",
      "unix"
    ],
    "constructor-super": [
      "error"
    ],
    "no-var": [
      "error"
    ],
    "no-unused-vars": 0,
    "no-useless-constructor": 0,
    "no-mixed-spaces-and-tabs": [
      "error"
    ],
    "brace-style": [
      "error"
    ],
    "spaced-comment": 0,
    "no-trailing-spaces": 0,
    "key-spacing": 0,
    "max-len": "off",
    "object-curly-spacing": [
      2,
      "always"
    ],
    "eol-last": 2,
    "unicode-bom": "off",
    "padded-blocks": "off",
    "@typescript-eslint/no-unused-vars": [
      "error",
      {
        "args": "after-used",
        "ignoreRestSiblings": true,
        "argsIgnorePattern": "^(_|(args|props|event|e)$)",
        "varsIgnorePattern": "^_"
      }
    ],
    "no-multiple-empty-lines": "off",
    "no-restricted-imports": [
      "error",
      {
        "patterns": [
          "components/examples/*",
          "components/display/Glyph",
          "enzyme"
        ]
      }
    ],
    "no-restricted-globals": [
      "error",
      "location"
    ],
    "no-throw-literal": "off",
    "camelcase": [
      "error",
      {
        "allow": [
          "advertising_token",
          "identity_expires",
          "refresh_expires",
          "refresh_from",
          "refresh_token",
          "refresh_response_key",
        ]
      }
    ],
    "eqeqeq": [
      "error",
      "smart"
    ],
    "arrow-body-style": "off",
    "function-call-argument-newline": "off",
    "lines-between-class-members": "off",
    "prefer-arrow-callback": [
      "error",
      {
        "allowNamedFunctions": true,
        "allowUnboundThis": false
      }
    ],
    "import/first": "error",
    "import/newline-after-import": "error",
    "import/no-duplicates": "error",
    "simple-import-sort/imports": [
      "error",
      {
        "groups": [
          [
            "^\\u0000"
          ],
          [
            "^@?\\w"
          ],
          [
            "^components/"
          ],
          [
            "^models/"
          ],
          [
            "^util/"
          ],
          [
            "^\\."
          ],
          [
            "^\\u0000.*\\.s?css$"
          ]
        ]
      }
    ],
    "simple-import-sort/exports": "error",
    "testing-library/consistent-data-testid": [
      "error",
      {
        "testIdPattern": "([a-z][a-z\\-]*)+[a-z]",
        "testIdAttribute": [
          "data-testid"
        ]
      }
    ]
  },
  "overrides": [
    {
      "files": [
        "*.js",
      ],
      "rules": {
        "@typescript-eslint/no-unused-vars": [
          "error",
          {
            "args": "after-used",
            "ignoreRestSiblings": true,
            "argsIgnorePattern": "^(_|(args|props|event|e)$)",
            "varsIgnorePattern": "^_"
          }
        ]
      }
    },
    {
      "files": [
        "uid2-sdk-*.js",
      ],
      "rules": {
        "@typescript-eslint/no-unused-vars": [
          "error",
          {
            "args": "after-used",
            "ignoreRestSiblings": true,
            "argsIgnorePattern": "^(_|(args|props|event|e)$)",
            "varsIgnorePattern": "^(_|(IdentityStatus)$)"
          }
        ]
      }
    },
    {
      "files": ["*.ts"],
      extends: [
        'plugin:@typescript-eslint/eslint-recommended',
        'plugin:@typescript-eslint/recommended',
        'plugin:@typescript-eslint/recommended-requiring-type-checking'    
      ],
      parserOptions: {
        project: [
          './tsconfig.json'
        ]
      }
    },
    {
      "files": ["*.spec.ts", "*.test.ts"],
      "rules": {
        "@typescript-eslint/no-unsafe-call": 0,
        "@typescript-eslint/no-explicit-any": 0,
        "@typescript-eslint/no-unsafe-member-access": 0,
        "@typescript-eslint/no-unsafe-assignment": 0,
        "@typescript-eslint/no-unsafe-return": 0,
        "@typescript-eslint/no-empty-function": 0,
        "@typescript-eslint/no-unsafe-argument": 0,
      }
    }
  ]
};
