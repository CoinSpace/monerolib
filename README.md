# monerolib

```
npm i monerolib
```

## Common

* `p` - private/secret key, it is scalar
* `P` - public key, it is point
* `pV` - private/secret view key
* `PV` - public view key
* `pS` - private/secret spend key
* `PS` - public spend key
* `HS()` - convert hash to scalar `hashToScalar`
* `G` - is the base point

Key derivation `generateKeyDerivation` means:

```
derivation = P * p * 8
```

## Subaddress

```
pSi = pS + HS(pV | i)
pVi = pV * pSi
```

```
PSi = PS + HS(pV | i) * G
PVi = pV * PSi

PSi = (pS + HS(pV | i)) * G
PVi = pV * (pS + HS(pV | i)) * G
```

## Outputs

* `r` - is the transaction private/secret key
* `R` - is the transaction public key, `txPubKey`
* `X` - is the stealth address or one time address `targetKey`

Fro address:
```
// Address (it is public key)
R = r * G

// Subaddress (it is some public data)
R = r * PSi
```

Sending:
```
// Address
X = Hs(r * PV | i)G + PS

// Subaddress
X = Hs(r * PVi | i)G + PSi
```

Receiving:
```
// Address
X = Hs(R * pV|i)G + PS

// Subaddress
X = Hs(R * pV|i)G + PSi
```

It is equal because:
```
// Address
R * pV = r * G * pV = r * PV 

// Subaddress
R * pV = r * PSi * pV = r * PVi
```

`r * PV` and `R * pV` is a key derivation

## Inputs

* `Hp()` - convert hash to point `hashToPoint` or more correctly `hashToEc`
* `x` - private/secret key of **stealth address** O_o
* `J` - is the key image `keyImage`

```
x = Hs(r * PV|i) + pS
x = Hs(R * pV|i) + pS
```

Key image is:
```
J = x * Hp(X)
```
