# authorization-signature

## 1.0.3

### Patch Changes

- 4ec9f9f: package.json exports now only has types and default keys, and no longer has an import key that points to a ts file, which could break some importers

## 1.0.2

### Patch Changes

- 199d9fa: change tsconfig.json from target=esnext to target es2017 or es2018 to increase compatibility with runtimes that don't support private class members
