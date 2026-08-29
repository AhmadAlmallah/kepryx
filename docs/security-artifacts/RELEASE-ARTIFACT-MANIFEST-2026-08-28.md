# Kepryx release artifact manifest

Evidence date: 2026-08-28 | Candidate: staged v0.9.0 community preview

This manifest binds the exact local image IDs, tool versions, and external artifact hashes used in
the release review. The JSON files remain outside the source tree because they are machine-specific
scan output. Attach the exact files and this manifest to the private GitHub release review, or
regenerate them from the exact release commit and replace the hashes below.

## Tools and scope

| Tool | Version | Scope |
|---|---|---|
| Trivy | 0.67.2 | Vulnerability scanner, `HIGH,CRITICAL`, `--ignore-unfixed=false`, `vuln` scanner |
| Syft | 1.51.1 | CycloneDX JSON SBOM generator |

## Image identity

| Image | Local image ID |
|---|---|
| `kepryx-api:0.9.0` | `sha256:2cc0449be6935efc38607ca6a1e9ac6346e01a6a31c51533ce5584463654c826` |
| `kepryx-worker-enrich` | `sha256:e46f30724c92dda639063e42d89e085c636abadd2719477ab73c13d1c689ac42` |
| `kepryx-worker-recon` | `sha256:b1363b9a0a53b294e5ef6a56455f8f3db782968df35010ae39952a27541086d2` |
| `kepryx-worker-selfsec` | `sha256:be7937052d8e552cc94c68476047be180bcc9336b060f3e331e5113859af8019` |
| `kepryx-worker-scanner` | `sha256:3adc1c1424e09c76ba76ca6b7d28f1de044ac0b2a4e73377cd47dd38eb8f1394` |
| `kepryx-beat` | `sha256:27152ddc8f6e139205188b1108d0e16ffd1dffe8a101f5867d2b7ec808ed6ab4` |
| `kepryx-caddy` | `sha256:f0c1185094b4d9fcdc435811c7c3ae3df73b730c492786971501bce519b246b5` |
| `kepryx-postgres` | `sha256:dea4ce8eabf76d743b1a81aa45e8c8d70395c2246d2152af0bff1fbd4916e2ec` |
| `kepryx-asset-source-mock` | `sha256:b4c5b0c9badd7cc61a107248ab2f7ddc62ff4105181902ad2ce08976f92edbbd` |

## SBOM hashes

Directory: `C:\Temp\kepryx-sbom-2026-08-28\`

| File | Bytes | SHA-256 |
|---|---:|---|
| `api.cdx.json` | 664251 | `3B8076DF816AA42FB2A430D3BE5A938699A70C6BF7428B8E9EC67A5DD49A906C` |
| `asset-source-mock.cdx.json` | 331581 | `254D89DF225EB3F184877DB0072B2452F502F6AF464838CDDE2B8354C1F86FDF` |
| `beat.cdx.json` | 666186 | `BFD3E955833D1BC93015C27B840AE3BDDAFCF9051ABB1158412BEDC08CBD1105` |
| `caddy.cdx.json` | 447263 | `0F1B5EE4A70E4E1D6A199ECDBD0FA28560E8E33BC59D7D53B2CBB5811A86357F` |
| `postgres.cdx.json` | 320190 | `A58D7DBA3087B65F3DD06DF3DC306D5ED6FDEC5AB13BCAF781CB99865CDA7DDB` |
| `worker-enrich.cdx.json` | 666204 | `8CEB113ECA7D08DAA7C1B7B27630746A4446A6FBD243738F7C725A89ACCF3DB3` |
| `worker-recon.cdx.json` | 666202 | `5F700932F627EB16441C8D38009F7C79ECBFEFBA1C08E45B4D8F90F630F985C0` |
| `worker-scanner-final.cdx.json` | 696299 | `E4AF1130B9C0C39584FA1574B678D402FD79C78A3C8790FCF2945E088F81A92A` |
| `worker-selfsec.cdx.json` | 666206 | `C3CBDD4AC3F5E4C7E35C3FB76308E56DA45E8D9AE09D5172F93056E262F7225A` |

## Trivy JSON hashes

Directory: `C:\Temp\kepryx-trivy-2026-08-28-final\`

| File | Bytes | SHA-256 | HIGH | CRITICAL |
|---|---:|---|---:|---:|
| `api.json` | 157251 | `1B881ED1FD1F94D3CB722D45B1E96903E6E2BC5FBA7E3EABA0A26C25EB1AEB16` | 0 | 0 |
| `asset-source-mock.json` | 99458 | `86A40CB97F172AFFCF67D792F2882B30909C0DB039FC9B6BBD56D8C534258307` | 0 | 0 |
| `beat.json` | 156125 | `4E32963E649281FF47BAB82DAA9452CDC8ACE6465FD0207B3ACE5B6D5944ABE4` | 0 | 0 |
| `caddy.json` | 161895 | `8988DDC6A1AD061A52B513DD3FAF49127C3BC9BDD9E6B395B9EDBDEF27DE2696` | 0 | 0 |
| `postgres.json` | 103162 | `5C9897DBF4D593187CAE738A329B3DD6FECA1BAE09D34FFB0AE43FFD2D7C44AE` | 0 | 0 |
| `worker-enrich.json` | 156170 | `8A91F86AB2E45D1782BE1CDA95E319473D04EA535493D4A8D1BA722E9F71BEF3` | 0 | 0 |
| `worker-recon.json` | 156165 | `7BC8034C9725AE8BC6AC95648F93C71B3D3BA323F9AFF5F916F1E498058A965F` | 0 | 0 |
| `worker-scanner.json` | 167739 | `4A22A9567646042C8E712538A735565A8D91966E8B73B1578AFD921323CD741A` | 0 | 0 |
| `worker-selfsec.json` | 156175 | `1B9D1B22E7FEB837247A440AADBADA76EAA00C7706BB771416BF55CCCCFD3C92` | 0 | 0 |

The PostgreSQL hash above is copied from the local artifact record and should be verified with the
provided script before attachment. The image scan result itself is the release gate; this manifest
does not replace a fresh scan for a new commit.
