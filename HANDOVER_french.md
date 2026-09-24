# UC2 — Proofpoint TRAP Incident Triage — Paquet de transfert (déploiement air-gapped)

Généré le 2026-09-24 15:52 UTC à partir de `proofpoint_trap` (environnement source : `soar8`).

Ce paquet est autonome — tout ce qu'il faut pour déployer ce cas d'usage manuellement
dans un environnement sans accès réseau vers ce dépôt ni vers `soar8`.

*(Version anglaise : `HANDOVER.md` dans ce même dossier.)*

## Contenu

| Chemin | Contenu |
|--------|---------|
| `connectors/` | Paquet(s) applicatif(s) connecteur : proofpoint_trap-v1.0.34.tgz |
| `connectors/source/` | Même(s) connecteur(s), extrait(s) — pour lecture, pas pour import |
| `playbooks/*.tgz` (CF) | proofpoint_trap_extract_incident_id |
| `playbooks/*.tgz` (PB) | proofpoint_trap_detail, proofpoint_trap_triage, proofpoint_trap_attachments, proofpoint_trap_acknowledge, proofpoint_trap_close, proofpoint_trap_isolation_notify, proofpoint_trap_recheck |
| `playbooks/source/` | Mêmes CF/playbooks, extraits — pour lecture, pas pour import |
| `assets/*.json` | Modèles de configuration d'assets (identifiants masqués — voir ci-dessous) |
| `custom_lists/*.json` | Schéma de la/les liste(s) personnalisée(s) (en-têtes uniquement — voir la section dédiée ci-dessous) |
| `docs/` | Document de plan d'implémentation, pour le contexte de conception complet |

## Ordre d'installation

1. **Installer l'application/les applications connecteur** — Apps > Install App, charger
   chaque fichier de `connectors/`.
   (`connectors/source/` est le même code extrait pour lecture — ne pas importer depuis ce
   dossier, l'interface a besoin du `.tgz`.)
2. **Configurer les assets à partir des modèles dans `assets/`** — Apps > Configure New Asset
   pour chacun. Les champs listés dans le `redacted_fields` d'un modèle sont des espaces
   réservés (`<<SET ME...>>`) — **vous devez les renseigner vous-même** ; ils n'ont jamais
   été exportés avec des valeurs utilisables. Deux raisons distinctes apparaissent dans
   cette liste, et chaque espace réservé précise laquelle s'applique :

   - **Secrets** (mots de passe, clés d'API, certificats/clés) — à reprendre depuis votre
     propre coffre-fort (vault)/CMDB. SOAR chiffre les champs de type `password` au repos,
     le processus d'export ne peut donc pas les relire sous une forme utilisable, même en
     principe.
   - **Identités et adresses** (noms d'utilisateur, client/app id, URL des points de
     terminaison) — non secrètes, mais elles appartenaient à l'environnement source et
     n'ont aucun sens ici. Saisissez les valeurs attendues par *votre* système cible.
     **Une identité doit correspondre au justificatif saisi à côté d'elle** — un vrai mot
     de passe associé à un nom d'utilisateur résiduel de l'environnement source ne
     s'authentifie auprès de rien et renvoie une erreur HTTP 401.
3. **Créer la/les liste(s) personnalisée(s)** à partir de `custom_lists/*.json` — chaque
   fichier contient le tableau `content` exact (ligne d'en-tête seule, jamais les lignes de données de la source) à
   envoyer en POST vers `/rest/decided_list` :
   ```bash
   curl -sk -u '<user>:<password>' -X POST https://<target>:<port>/rest/decided_list \
     -H 'Content-Type: application/json' \
     -d @custom_lists/<list_name>.json
   ```
   (la structure de premier niveau du fichier est `{"name": ..., "content": [...]}` —
   correspond directement au payload REST attendu.)
4. **Importer les fonctions personnalisées, puis les playbooks** (dans cet ordre — les
   playbooks référencent les CF) depuis `playbooks/*.tgz`, via Apps/Playbooks > Import dans
   l'interface SOAR cible.
   (`playbooks/source/` est le même code extrait pour lecture — ne pas importer depuis
   ce dossier, l'interface a besoin du `.tgz`.)
5. **Activer les playbooks d'automatisation** (`proofpoint_trap_detail`, `proofpoint_trap_triage`, `proofpoint_trap_attachments`, `proofpoint_trap_recheck`) et définir leur utilisateur
   **Run As** selon le guide d'installation du document de plan d'implémentation
   (voir `docs/`).

## Listes personnalisées appartenant à ce cas d'usage

Ces listes constituent **l'état interne des playbooks** : créez-les vides (étape
ci-dessus), puis n'y touchez plus. Le playbook les remplit et les entretient lui-même ;
une ligne saisie à la main est relue comme un état réel et le fera réagir à des
événements qui n'ont jamais eu lieu.

- `proofpoint_trap_recheck_state` : `incident_id, signature` — écrite par le playbook, pas par vous.

Consultez le document de plan d'implémentation dans `docs/` pour savoir ce que le
playbook y stocke et à quel moment.

## Vérification

Une fois tout importé et les playbooks d'automatisation activés, déclenchez une exécution
manuelle (par ex. le poll manuel de l'asset Timer, ou selon la section de déclenchement du
document de plan d'implémentation)
et vérifiez : qu'un container est créé, que le(s)
playbook(s) enfant(s) attendu(s) s'exécute(nt), et que la/les liste(s) personnalisée(s)
reflète(nt) un résultat réel. Consultez `spawn.log`/`decided.log`/`actiond.log` sur l'hôte
SOAR cible si quelque chose ne se déclenche pas comme prévu.

## Ce qui n'a volontairement PAS été exporté

- Les valeurs réelles des identifiants pour tout champ de configuration de type `password`
  (voir l'étape 2 ci-dessus).
- Les véritables assets cibles de rotation de l'environnement source — ce sont des assets de
  test spécifiques à ce labo, pas votre infrastructure. Suivez plutôt la section Amorçage
  ci-dessus.
- Tout ce qui n'est pas explicitement listé dans Contenu ci-dessus.
