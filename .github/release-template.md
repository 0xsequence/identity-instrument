<details open>
<summary>Production</summary>
### Build

```
make VERSION={{ .prod_version }} eif
```

### Enclave Measurements

- **PCR0: `{{ .prod_pcr0 }}`**
- PCR1: `{{ .prod_pcr1 }}`
- PCR2: `{{ .prod_pcr2 }}`

### Sha256 Checksum
```
{{ .prod_checksum }}
```
</details>

<details>
<summary>Next</summary>
### Build

```
make ENV=next VERSION={{ .next_version }} eif
```

### Enclave Measurements

- **PCR0: `{{ .next_pcr0 }}`**
- PCR1: `{{ .next_pcr1 }}`
- PCR2: `{{ .next_pcr2 }}`

### Sha256 Checksum
```
{{ .next_checksum }}
```
</details>
