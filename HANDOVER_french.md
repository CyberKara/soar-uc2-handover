# UC2 — Proofpoint TRAP Incident Triage — Paquet de transfert (déploiement air-gapped)

Généré le 2026-09-29 11:25 UTC à partir de `proofpoint_trap` (environnement source : `soar8`).

Ce paquet est autonome — tout ce qu'il faut pour déployer ce cas d'usage manuellement
dans un environnement sans accès réseau vers ce dépôt ni vers `soar8`.

*(Version anglaise : `HANDOVER.md` dans ce même dossier.)*

## Contenu

| Chemin | Contenu |
|--------|---------|
| `connectors/` | Paquet(s) applicatif(s) connecteur : proofpoint_trap-v1.0.36.tgz |
| `connectors/source/` | Même(s) connecteur(s), extrait(s) — pour lecture, pas pour import |
| `playbooks/*.tgz` (CF) | proofpoint_trap_extract_incident_id |
| `playbooks/*.tgz` (PB) | proofpoint_trap_detail, proofpoint_trap_triage, proofpoint_trap_attachments, proofpoint_trap_acknowledge, proofpoint_trap_close, proofpoint_trap_isolation_notify, proofpoint_trap_recheck, proofpoint_trap_summary |
| `playbooks/source/` | Mêmes CF/playbooks, extraits — pour lecture, pas pour import |
| `assets/*.json` | Modèles de configuration d'assets (identifiants masqués — voir ci-dessous) |
| `custom_lists/*.json` | Schéma de la/les liste(s) personnalisée(s) (en-têtes uniquement — voir la section dédiée ci-dessous) |
| `docs/` | Document de plan d'implémentation, pour le contexte de conception complet |

## [!] Mise à niveau d'une installation existante — à lire en premier

Ne concerne que le cas où cette application est déjà installée sur la cible
depuis un paquet précédent. Sur une cible vierge, passez à l'ordre
d'installation.

- **Le connecteur v1.0.36 corrige `download mime body`, qui échouait sur chaque événement face à une vraie appliance TRAP** (les versions v1.0.34 et antérieures appelaient un point d'accès que TRAP ne possède pas ; la v1.0.35 échouait aussi sur chaque événement lancée depuis le panneau d'actions de l'actif, qui n'a pas de conteneur où stocker l'e-mail — elle télécharge et vérifie désormais chaque e-mail à cet endroit, en affichant sa taille et son objet, sans le stocker). Installez-le par-dessus l'application Proofpoint TRAP existante : mise à jour normale, sur place. L'actif (asset), sa clé d'API et tous les playbooks restent tels quels — rien à réimporter, rien à ressaisir. **Les incidents traités avant la mise à jour restent sans leurs e-mails :** `proofpoint_trap_detail` les a marqués `Enrichment Complete` bien que le téléchargement des e-mails ait échoué, et il ne s'exécute plus sur un conteneur déjà traité. Les nouveaux incidents, ainsi que tout incident dont `proofpoint_trap_recheck` détecte une modification, reçoivent normalement leurs e-mails et pièces jointes. Pour récupérer à la main les e-mails d'un incident antérieur, lancez `download mime body` sur son conteneur avec l'identifiant de l'incident : les fichiers `.eml` arrivent dans les fichiers (Vault) du conteneur, mais aucun artefact `MIME Body` n'est créé, donc `proofpoint_trap_attachments` ne les traite pas.

- **`proofpoint_trap_detail` doit être réimporté (2026-09-28) — contrairement à la mise à jour du connecteur ci-dessus.** Il résiste désormais à un enregistrement dans le VPE et ses réexécutions ne publient que les nouveaux artefacts. Réimportez-le depuis `playbooks/` — la nouvelle copie remplace la vôtre, y compris tout bloc renommé avec `_0` par un enregistrement antérieur — puis réactivez-le. Après l'import, vous pouvez rediriger ses blocs d'action vers vos propres noms d'assets et enregistrer : il ne casse plus. Deux blocs changent de nom (`build_artifact_list`, `dispatch_artifact_list`). Une réexécution, que `proofpoint_trap_recheck` déclenche à chaque modification d'un incident, ne publie plus que les artefacts absents du conteneur au lieu de toute la liste, et la note de détail indique « N new, M already on the container ». L'artefact `Enrichment Complete` ajoute `alertCount` (alertes traitées), `eventCount` (le décompte de TRAP) et `artifactsAlreadyPresent` ; `artifactsCreated` ne compte plus que les nouveaux artefacts.

- **Chaque playbook UC2 résiste désormais à un enregistrement dans le VPE, et `proofpoint_trap_summary` est nouveau (2026-09-28).** Réimportez tous les playbooks depuis `playbooks/` (les nouvelles copies remplacent les vôtres) et réactivez ceux d'automatisation (`proofpoint_trap_detail`, `proofpoint_trap_triage`, `proofpoint_trap_attachments`, `proofpoint_trap_recheck`). Ensuite, vous pouvez rediriger n'importe quel bloc d'action vers vos propres noms d'assets et enregistrer. Ce qui change : `proofpoint_trap_acknowledge` et `proofpoint_trap_close` sollicitent le propriétaire du conteneur, ou `soar_local_admin` si le conteneur n'a pas de propriétaire (comme avant, mais ce repli résiste désormais à un enregistrement) ; une demande de clôture restée sans réponse écrit quand même sa note ; `proofpoint_trap_attachments` n'accède plus au système de fichiers (le validateur de SOAR le signalait) et lit et enregistre les fichiers du Vault via l'API REST de SOAR ; sa note `Email Content` par e-mail affiche désormais le corps sous forme de texte sûr (liens avec leur vraie cible, neutralisés et non cliquables, alerte quand le texte d'un lien désigne un autre site, images et scripts retirés, texte caché et formulaires signalés). Les notes d'acquittement, de clôture, d'isolation et de pièces jointes sont désormais enregistrées en markdown : leur texte en gras et leurs titres s'affichent correctement. `proofpoint_trap_summary` se lance à la main depuis un conteneur : il écrit une note `TRAP Summary` avec un tableau par type d'artefact et réécrit cette même note à chaque exécution.

- **Réimportez à nouveau la fonction personnalisée et tous les playbooks (2026-09-29).** Importez `proofpoint_trap_extract_incident_id` avec *Import Custom Function* (étape 4), pas avec l'import de playbook : son en-tête correspond désormais à celui que génère l'éditeur de SOAR 8.6, l'éditeur ne la signale donc plus comme modifiée hors de l'éditeur et elle s'enregistre comme fonction publiée au lieu d'un brouillon. Réimportez ensuite chaque playbook et réactivez ceux d'automatisation. Ce qui change : `proofpoint_trap_triage` ajoute une note `TRAP Triage - Severity` qui indique la sévérité appliquée, la valeur TRAP d'origine, et quand une valeur inconnue a été ramenée à `low`. Les playbooks lancés à la main n'affichent plus leur bloc Start ou End comme « Unconfigured » dans le VPE : ils acceptent des entrées facultatives (`proofpoint_trap_acknowledge` et `proofpoint_trap_close` : `approver`, `respond_in_mins` ; `proofpoint_trap_summary` : `max_rows` ; laissées vides, le comportement reste inchangé) et renvoient une sortie `status` avec l'identifiant de l'incident et un résultat clé. Chaque playbook porte désormais les marqueurs de version qu'écrit l'éditeur de SOAR 8.6.

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

   **Les playbooks sont livrés pointant vers les noms d'assets ci-dessous.** Créez vos
   assets avec ces noms, ou gardez vos propres noms et redirigez les blocs d'action de
   chaque playbook vers vos assets dans le VPE, puis enregistrez : chaque playbook de ce
   paquet est conçu pour résister à un enregistrement. (Un enregistrement rend un playbook
   lancé à la main disponible sur tous les libellés de conteneur ; le réimporter rétablit
   le libellé.)

   | Nom de l'asset | Application | Utilisé par | Modèle |
   |---|---|---|---|
   | `proofpoint_trap_mock` | Proofpoint TRAP | `proofpoint_trap_acknowledge`, `proofpoint_trap_close`, `proofpoint_trap_detail`, `proofpoint_trap_recheck` | `assets/proofpoint_trap_mock.json` |
   | `smtp` | SMTP | `proofpoint_trap_isolation_notify` | `assets/smtp.json` |
   | `soar8` | Phantom | `proofpoint_trap_detail` | `assets/soar8.json` |

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
   playbooks référencent les CF). `playbooks/` contient les deux, et chacun passe par son
   propre import :
   - **Fonctions personnalisées** — `playbooks/proofpoint_trap_extract_incident_id.tgz` : dans l'onglet Custom Functions de la
     page Playbooks, le bouton d'envoi dont l'infobulle indique *Import Custom Function*.
     L'import de playbook refuse une archive de CF (« failed to identify the import as a
     playbook »). Si la CF apparaît ensuite en brouillon, ouvrez-la dans l'éditeur et
     enregistrez-la.
   - **Playbooks** — tous les autres `playbooks/*.tgz` : *Import Playbook* sur la page Playbooks.
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
