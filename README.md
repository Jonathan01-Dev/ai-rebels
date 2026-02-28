                       ARCHIPEL 
Protocole P2P Chiffré et Décentralisé à Zéro-Connexion 


** Installer les dépendances:
pip install -r requirements.txt


** Génération des clés :
python3 scripts/gen_keys.py

Archipel - Sprint 0 (Base technique validée)


1) Choix du langage principal + justification

Langage choisi
- Python 3.11+

Justification
- Développement rapide pour un hackathon court.
- Excellentes bibliothèques crypto (`PyNaCl`, `cryptography`).
- Code lisible et simple à maintenir en équipe.
- Bon support asynchrone pour réseau local (`asyncio`).

2) Choix de la technologie de transport local

Choix retenu (pratique et fiable)
- Découverte des pairs: UDP Multicast (`239.255.42.99:6000`)
- **Transport des données: TCP (port par défaut `7777`)

Pourquoi ce choix
- UDP multicast est simple et rapide pour annoncer sa présence.
- TCP apporte fiabilité, ordre et contrôle pour messages/fichiers.
- Stack robuste et réaliste pour une démo LAN.

3) Format de paquet binaire (header + payload + checksum)

Format retenu

┌──────────────────────────────────────────────────────────────┐
│                      ARCHIPEL PACKET v1                     							 
│                                                                                 │
├──────────┬──────────┬───────────┬───────────────────────────┤
│  MAGIC   │  TYPE    │  NODE_ID  │       PAYLOAD_LEN          │
│                                                              │
│  4 bytes │  1 byte  │ 32 bytes  │ 4 bytes (uint32_BE)        │
├──────────┴──────────┴───────────┴───────────────────────────┤
│                                                              │
│  NONCE (12 bytes)                                            │
│  SEQ   (8 bytes, uint64_BE)                                  │
│  CIPHERTEXT (variable length)                                │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│  HMAC-SHA256 SIGNATURE (32 bytes)                            │
└──────────────────────────────────────────────────────────────┘### Types de paquets (référence)
- `0x01 HELLO`
- `0x02 PEER_LIST`
- `0x03 MSG`
- `0x04 CHUNK_REQ`
- `0x05 CHUNK_DATA`
- `0x06 MANIFEST`
- `0x07 ACK`

---

4) Architecture du système (vue simple et claire)

Archipel est une application P2P locale (LAN) sans serveur central.
Chaque machine (nœud) exécute les mêmes modules.

Schéma ASCII

text
                        LAN (UDP Multicast + TCP)
+------------------- Node A -------------------+      +------------------- Node B -------------------+
|                                               |      |                                               |
|  +------+     +------+     +-----------+      |      |  +------+     +------+     +-----------+     |
|  | CLI  | --> | Core | --> | Discovery | --UDP HELLO/PEER_LIST-->   | Discovery | <-- | Core | <-- | CLI |
|  +------+     +------+     +-----------+      |      |  +------+     +------+     +-----------+     |
|                    |            |              |      |       |             |                        |
|                    v            v              |      |       v             v                        |
|               +---------+   +-----------+      |      |  +---------+   +-----------+               |
|               | Crypto  |<->| Transport | <----TCP MSG/CHUNK----->| Transport |<->| Crypto  |      |
|               +---------+   +-----------+      |      |  +---------+   +-----------+               |
|                    |            |              |      |       |             |                        |
|                    v            v              |      |       v             v                        |
|               +-----------------------+        |      |  +-----------------------+                   |
|               | Transfer + Store      |        |      |  | Transfer + Store      |                   |
|               | chunks / manifest /db |        |      |  | chunks / manifest /db |                   |
|               +-----------------------+        |      |  +-----------------------+                   |
+-----------------------------------------------+      +-----------------------------------------------+

Rôle de chaque module
- `CLI`: interface utilisateur.
- `Core`: orchestrateur des actions.
- `Discovery`: découverte des pairs en UDP.
- `Transport`: échanges fiables en TCP.
- `Crypto`: signature, vérification, chiffrement.
- `Transfer`: découpage/réassemblage des fichiers.
- `Store`: persistance locale (identité, chunks, index).

5) Flux principaux (pas à pas)

Flux A: découverte d'un pair
1. Le nœud démarre (`archipel start`).
2. `Discovery` envoie un `HELLO` en UDP multicast.
3. Les autres nœuds reçoivent `HELLO` et mettent à jour leur table de pairs.
4. `archipel peers` affiche les pairs connus.

Flux B: message chiffré
1. L'utilisateur lance `archipel msg <node_id> "Bonjour"`.
2. `Core` prépare l'envoi.
3. `Crypto` chiffre et signe.
4. `Transport` envoie sur TCP.
5. Côté receveur: `Transport` reçoit, `Crypto` vérifie/déchiffre, puis affichage.

Flux C: transfert de fichier
1. L'utilisateur lance `archipel send <node_id> <fichier>`.
2. `Transfer` crée le manifest et découpe en chunks.
3. Les chunks sont envoyés via `Transport` (TCP), protégés par `Crypto`.
4. Le receveur vérifie chaque hash chunk, stocke, puis réassemble.
5. Le hash final doit être identique au fichier source.

**Test de communication **
python .\network\node.py
