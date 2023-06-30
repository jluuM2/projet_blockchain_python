# Récupération de clé publique ECDSA

Ce code fournit une implémentation en C++ pour récupérer une clé publique à partir d'un message signé en utilisant ECDSA (Elliptic Curve Digital Signature Algorithm). Le code utilise la bibliothèque OpenSSL et inclut les fichiers d'en-tête nécessaires.

## Dépendances

- `iostream`
- `stdexcept`
- `openssl/ecdsa.h`
- `openssl/obj_mac.h`
- `openssl/bn.h`
- `pybind11/pybind11.h`

Assurez-vous d'avoir installé ces dépendances avant de compiler le code.

## Fonction : recover_public_key

La fonction `recover_public_key` permet de récupérer une clé publique à partir d'un message signé en utilisant ECDSA. Voici les détails de la fonction :

```cpp
std::string recover_public_key(const std::string& signature, const std::string& message)
```
# Récupération de clé publique ECDSA

Ce code fournit une implémentation en C++ pour récupérer une clé publique à partir d'un message signé en utilisant ECDSA (Elliptic Curve Digital Signature Algorithm). Le code utilise la bibliothèque OpenSSL et inclut les fichiers d'en-tête nécessaires.

## Paramètres

- `signature` : La signature du message signé.
- `message` : Le message d'origine.

## Valeur de retour

La fonction renvoie la clé publique récupérée sous forme de chaîne de caractères.

## Exceptions

La fonction peut générer une exception `std::runtime_error` si la récupération de la clé publique échoue.

## Module Pybind11 : public_key

Ce code inclut également une définition de module Pybind11, permettant d'exposer la fonction `recover_public_key` à Python. Le module est nommé "ecdsa_publickey_recovery".

## Utilisation en Python

```python
import public_key
```
recovered_key = public_key.recover_public_key(signature, message)
La fonction `recover_public_key` peut être appelée depuis Python en fournissant les arguments `signature` et `message`, et elle renverra la clé publique récupérée.

## Lancement du projet
```bash
openssl ecparam -genkey -name secp256k1 -noout -out private.pem

openssl ec -in private.pem -pubout -out public.pem

echo "Hello, World!" > message.txt

openssl dgst -sha256 -sign private.pem -out signature.der message.txt

openssl dgst -sha256 -verify public.pem -signature signature.der message.txt

xxd -p -c 256 signature.der > signature.hex

xxd -p -c 256 public.pem > public.hex

make
bash
Copy code
