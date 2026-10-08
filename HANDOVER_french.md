# UC2 — Proofpoint TRAP Incident Triage — Paquet de transfert (déploiement air-gapped)

Généré le 2026-10-08 22:35 UTC à partir de `proofpoint_trap` (environnement source : `soar8`).

Ce paquet est autonome — tout ce qu'il faut pour déployer ce cas d'usage manuellement
dans un environnement sans accès réseau vers ce dépôt ni vers `soar8`.

*(Version anglaise : `HANDOVER.md` dans ce même dossier.)*

## Contenu

| Chemin | Contenu |
|--------|---------|
| `connectors/` | Paquet(s) applicatif(s) connecteur : proofpoint_trap-v1.0.39.tgz |
| `connectors/source/` | Même(s) connecteur(s), extrait(s) — pour lecture, pas pour import |
| `playbooks/*.tgz` (CF) | proofpoint_trap_extract_incident_id |
| `playbooks/*.tgz` (PB) | proofpoint_trap_detail, proofpoint_trap_triage, proofpoint_trap_attachments, proofpoint_trap_acknowledge, proofpoint_trap_close, proofpoint_trap_isolation_notify, proofpoint_trap_recheck, proofpoint_trap_summary, proofpoint_trap_orchestrator |
| `playbooks/source/` | Mêmes CF/playbooks, extraits — pour lecture, pas pour import |
| `assets/*.json` | Modèles de configuration d'assets (identifiants masqués — voir ci-dessous) |
| `custom_lists/*.json` | Liste(s) personnalisée(s) — les lignes définies par ce paquet, jamais les lignes de données de la source (voir la section dédiée ci-dessous) |
| `docs/` | Document de plan d'implémentation, pour le contexte de conception complet |

## [!] Mise à niveau d'une installation existante — à lire en premier

Ne concerne que le cas où cette application est déjà installée sur la cible
depuis un paquet précédent. Sur une cible vierge, passez à l'ordre
d'installation.

- **Le connecteur v1.0.36 corrige `download mime body`, qui échouait sur chaque événement face à une vraie appliance TRAP** (les versions v1.0.34 et antérieures appelaient un point d'accès que TRAP ne possède pas ; la v1.0.35 échouait aussi sur chaque événement lancée depuis le panneau d'actions de l'actif, qui n'a pas de conteneur où stocker l'e-mail — elle télécharge et vérifie désormais chaque e-mail à cet endroit, en affichant sa taille et son objet, sans le stocker). Installez-le par-dessus l'application Proofpoint TRAP existante : mise à jour normale, sur place. L'actif (asset), sa clé d'API et tous les playbooks restent tels quels — rien à réimporter, rien à ressaisir. **Les incidents traités avant la mise à jour restent sans leurs e-mails :** `proofpoint_trap_detail` les a marqués `Enrichment Complete` bien que le téléchargement des e-mails ait échoué, et il ne s'exécute plus sur un conteneur déjà traité. Les nouveaux incidents, ainsi que tout incident dont `proofpoint_trap_recheck` détecte une modification, reçoivent normalement leurs e-mails et pièces jointes. Pour récupérer à la main les e-mails d'un incident antérieur, lancez `download mime body` sur son conteneur avec l'identifiant de l'incident : les fichiers `.eml` arrivent dans les fichiers (Vault) du conteneur, mais aucun artefact `MIME Body` n'est créé, donc `proofpoint_trap_attachments` ne les traite pas.

- **`proofpoint_trap_detail` doit être réimporté (2026-09-28) — contrairement à la mise à jour du connecteur ci-dessus.** Il résiste désormais à un enregistrement dans le VPE et ses réexécutions ne publient que les nouveaux artefacts. Réimportez-le depuis `playbooks/` — la nouvelle copie remplace la vôtre, y compris tout bloc renommé avec `_0` par un enregistrement antérieur — puis réactivez-le. Après l'import, vous pouvez rediriger ses blocs d'action vers vos propres noms d'assets et enregistrer : il ne casse plus. Deux blocs changent de nom (`build_artifact_list`, `dispatch_artifact_list`). Une réexécution, que `proofpoint_trap_recheck` déclenche à chaque modification d'un incident, ne publie plus que les artefacts absents du conteneur au lieu de toute la liste, et la note de détail indique « N new, M already on the container ». L'artefact `Enrichment Complete` ajoute `alertCount` (alertes traitées), `eventCount` (le décompte de TRAP) et `artifactsAlreadyPresent` ; `artifactsCreated` ne compte plus que les nouveaux artefacts.

- **Chaque playbook UC2 résiste désormais à un enregistrement dans le VPE, et `proofpoint_trap_summary` est nouveau (2026-09-28).** Réimportez tous les playbooks depuis `playbooks/` (les nouvelles copies remplacent les vôtres) et réactivez ceux d'automatisation (`proofpoint_trap_detail`, `proofpoint_trap_triage`, `proofpoint_trap_attachments`, `proofpoint_trap_recheck`). Ensuite, vous pouvez rediriger n'importe quel bloc d'action vers vos propres noms d'assets et enregistrer. Ce qui change : `proofpoint_trap_acknowledge` et `proofpoint_trap_close` sollicitent le propriétaire du conteneur, ou `soar_local_admin` si le conteneur n'a pas de propriétaire (comme avant, mais ce repli résiste désormais à un enregistrement) ; une demande de clôture restée sans réponse écrit quand même sa note ; `proofpoint_trap_attachments` n'accède plus au système de fichiers (le validateur de SOAR le signalait) et lit et enregistre les fichiers du Vault via l'API REST de SOAR ; sa note `Email Content` par e-mail affiche désormais le corps sous forme de texte sûr (liens avec leur vraie cible, neutralisés et non cliquables, alerte quand le texte d'un lien désigne un autre site, images et scripts retirés, texte caché et formulaires signalés). Les notes d'acquittement, de clôture, d'isolation et de pièces jointes sont désormais enregistrées en markdown : leur texte en gras et leurs titres s'affichent correctement. `proofpoint_trap_summary` se lance à la main depuis un conteneur : il écrit une note `TRAP Summary` avec un tableau par type d'artefact et réécrit cette même note à chaque exécution.

- **Réimportez à nouveau la fonction personnalisée et tous les playbooks (2026-09-29).** Importez `proofpoint_trap_extract_incident_id` avec *Import Custom Function* (étape 4), pas avec l'import de playbook : son en-tête correspond désormais à celui que génère l'éditeur de SOAR 8.6, l'éditeur ne la signale donc plus comme modifiée hors de l'éditeur et elle s'enregistre comme fonction publiée au lieu d'un brouillon. Réimportez ensuite chaque playbook et réactivez ceux d'automatisation. Ce qui change : `proofpoint_trap_triage` ajoute une note `TRAP Triage - Severity` qui indique la sévérité appliquée, la valeur TRAP d'origine, et quand une valeur inconnue a été ramenée à `low`. Les playbooks lancés à la main n'affichent plus leur bloc Start ou End comme « Unconfigured » dans le VPE : ils acceptent des entrées facultatives (`proofpoint_trap_acknowledge` et `proofpoint_trap_close` : `approver`, `respond_in_mins` ; `proofpoint_trap_summary` : `max_rows` ; laissées vides, le comportement reste inchangé) et renvoient une sortie `status` avec l'identifiant de l'incident et un résultat clé. Chaque playbook porte désormais les marqueurs de version qu'écrit l'éditeur de SOAR 8.6.

- **Correctif (2026-09-29) : les paquets du 2026-09-28 et du 2026-09-29 livraient quatre playbooks sans leur Global Custom Code** — `proofpoint_trap_attachments`, `proofpoint_trap_acknowledge`, `proofpoint_trap_isolation_notify` et `proofpoint_trap_recheck`. Le code figurait dans le `.py` de chaque archive, donc les playbooks s'exécutaient, mais pas dans son `.json`, à partir duquel le VPE construit le playbook : *Validate Python* signalait ses fonctions utilitaires comme non définies (par exemple `_email_html_to_markdown`), et enregistrer l'un de ces playbooks les supprimait, après quoi il échoue à l'exécution. Ce paquet contient le code dans les deux fichiers. Réimportez les quatre — obligatoire si vous en avez enregistré un après l'import d'un paquet antérieur — et réactivez `proofpoint_trap_attachments` et `proofpoint_trap_recheck`.

- **`proofpoint_trap_summary` s'exécute désormais seul, et `proofpoint_trap_attachments` traite désormais les e-mails de chaque nouvel incident (2026-09-29).** Réimportez `proofpoint_trap_detail`, `proofpoint_trap_triage` et `proofpoint_trap_summary`, puis **activez `proofpoint_trap_summary`** — c'est désormais un playbook d'automatisation, sans entrées ; un analyste n'a plus besoin de le lancer. Quand `proofpoint_trap_detail` termine un conteneur, son artefact `Enrichment Complete` relance maintenant les playbooks d'automatisation. Auparavant, `proofpoint_trap_attachments` ne s'exécutait qu'à la création du conteneur, avant tout téléchargement d'e-mail : il ne traitait les e-mails d'un nouvel incident qu'après que `proofpoint_trap_recheck` avait détecté une modification de l'incident. Sur ce même déclenchement, `proofpoint_trap_summary` écrit ou réécrit la note `TRAP Summary` (250 lignes au plus par tableau), et `proofpoint_trap_triage` réapplique la sévérité du conteneur : les nouveaux artefacts arrivent avec la sévérité par défaut de SOAR, `medium`, et remontaient à `medium` tout incident associé à `low`. Sa note de sévérité n'est ajoutée que lorsque la sévérité issue de TRAP change. Les pièces jointes extraites lors de ce passage peuvent n'apparaître dans le résumé qu'à sa mise à jour suivante.

- **Noms des conteneurs, un commentaire dans TRAP et un lien vers TRAP (2026-09-29).** Installez le connecteur v1.0.37 par-dessus l'application Proofpoint TRAP existante (mise à jour normale, sur place : `get incident` renvoie aussi la page web de l'incident dans TRAP), réimportez `proofpoint_trap_detail` et réactivez-le, puis créez la liste personnalisée `proofpoint_trap_excluded_senders` (voir « Listes personnalisées à remplir »). Ce qui change : un conteneur dont l'incident TRAP n'a pas de résumé est nommé `TRAP-<id>: <premier expéditeur absent de cette liste>` au lieu de `TRAP-<id>: No summary` ; à la première extraction d'un incident, SOAR ajoute sur l'incident TRAP un commentaire qui le signale, avec un lien vers le cas SOAR ; et la note `TRAP Detail` contient un lien `Open in TRAP` vers l'incident. Le lien vers SOAR utilise l'URL de base de SOAR (Administration > Company Settings) : vérifiez qu'il s'agit de l'adresse à laquelle les analystes ouvrent SOAR, port compris.

- **Les notes longues sont découpées au lieu d'être tronquées (2026-09-29).** Une note SOAR n'affiche ici qu'environ 22 000 caractères au plus, donc aucune note ne dépasse 20 000 : une note `Email Content` ou `Attachment Extraction` plus longue de `proofpoint_trap_attachments` devient des parties `... (1/N)`, `... (2/N)`, et le `TRAP Summary` de `proofpoint_trap_summary` devient `TRAP Summary (1/N)`... (un tableau qui continue répète son en-tête ; les parties sont réécrites à chaque mise à jour). Réimportez ces deux playbooks et réactivez-les. Le corps d'un e-mail reste raccourci après 20 000 caractères ; le message complet est le `.eml` dans les fichiers du conteneur.

- **`proofpoint_trap_isolation_notify` liste ses liens dans la note du conteneur, et chaque description de playbook commence par son type et son numéro (2026-09-29).** La note `TRAP Isolation Notify` affiche chaque lien du navigateur d'isolation envoyé par e-mail (la cible en texte, seul le lien du navigateur d'isolation est cliquable). Les descriptions indiquent `Automation playbook (PBn)` / `Data playbook (PBn)`. Réimportez `proofpoint_trap_isolation_notify` ; les autres playbooks prennent les nouvelles descriptions à leur prochaine réimportation.

- **Un conteneur associé à `low` reste désormais `low` (2026-09-30).** `proofpoint_trap_triage` fixe la sévérité du conteneur d'après celle de TRAP, mais un artefact créé ou mis à jour sans sévérité est `medium` et relève un conteneur plus bas : `proofpoint_trap_attachments`, en marquant chaque `MIME Body` comme traité, remettait chaque conteneur `low` à `medium`. Les playbooks écrivent désormais leurs artefacts en `low`, ce qui n'abaisse jamais un conteneur `high` ou `medium`. Par ailleurs, `proofpoint_trap_acknowledge`, `proofpoint_trap_close` et `proofpoint_trap_isolation_notify` ne signalent plus comme `not run` une étape que SOAR a refusé de lancer : la note indique `failed - not dispatched`, et la raison figure dans les actions de l'exécution du playbook. Réimportez ces cinq playbooks — `proofpoint_trap_attachments`, `proofpoint_trap_recheck`, `proofpoint_trap_acknowledge`, `proofpoint_trap_close`, `proofpoint_trap_isolation_notify` — et réactivez les deux premiers. Un conteneur déjà relevé à `medium` revient à sa sévérité associée la prochaine fois que `proofpoint_trap_recheck` voit son incident changer.

- **Un orchestrateur lance les playbooks dans l'ordre (2026-09-30).** Les playbooks d'automatisation démarraient ensemble sur le même déclencheur et entraient en concurrence : les pièces jointes cherchaient des e-mails que `proofpoint_trap_detail` n'avait pas encore téléchargés, le résumé manquait ce que les autres écrivaient encore. Le nouveau playbook d'automatisation `proofpoint_trap_orchestrator` (label `proofpoint_trap`) lance désormais `proofpoint_trap_detail`, `proofpoint_trap_attachments`, `proofpoint_trap_triage` et `proofpoint_trap_summary` l'un après l'autre, chacun attendant la fin du précédent. Importez-le et activez-le ; réimportez ces quatre playbooks et **désactivez-les** — cela remplace toute étape « réactivez » les concernant dans les notes ci-dessus. `proofpoint_trap_recheck` reste actif. L'artefact `Enrichment Complete` ne lance plus l'automatisation. Si vous avez créé vous-même un `proofpoint_trap_orchestrator`, l'import le remplace. Également dans `proofpoint_trap_detail` : une adresse d'expéditeur de la liste personnalisée `proofpoint_trap_excluded_senders` n'a plus d'artefact `Sender Email`, ni son domaine d'artefact `Sender Domain` (sauf si un autre expéditeur le partage) ; les artefacts déjà présents sur un conteneur restent.

- **`status` résiste à un enregistrement dans l'éditeur de playbooks (2026-10-01).** Après un enregistrement dans l'éditeur de SOAR 8.6, `proofpoint_trap_acknowledge`, `proofpoint_trap_close` et `proofpoint_trap_isolation_notify` renvoyaient une liste vide au lieu de `failed` quand une exécution s'arrêtait tôt, et chaque sortie non renseignée revenait sous forme de liste vide au lieu d'être vide. Faire pointer leurs blocs d'action vers les noms de vos actifs est un tel enregistrement. Réimportez ces trois playbooks (playbooks de données : rien à activer) ; refaites pointer les noms d'actifs si vous les aviez modifiés.

- **`proofpoint_trap_close` garde sa note quand l'invite n'est pas approuvée (2026-10-01).** Après un enregistrement dans l'éditeur de SOAR 8.6, une fermeture dont l'invite avait expiré ou été refusée se terminait sans note et avec le statut `failed` : l'éditeur faisait attendre la note de fermeture après le commentaire TRAP, qui ne s'exécute que pour une fermeture approuvée. Ce chemin a désormais son propre bloc, **add expired note**. Réimportez `proofpoint_trap_close` (playbook de données : rien à activer) et refaites pointer ses noms d'actifs si vous les aviez modifiés ; l'enregistrer est sans risque.

- **Le commentaire TRAP fonctionne sur l'appliance ; la liste des expéditeurs écartés est renommée et gagne des colonnes (2026-10-01).** Sur l'appliance, l'étape de commentaire de `proofpoint_trap_detail` (**comment on trap incident**) échouait avec `HTTP 500 -- java.lang.NullPointerException: Null detail` : TRAP exige le `detail` d'un commentaire bien que sa documentation d'API le dise facultatif. Le playbook envoie désormais le lien SOAR comme `detail` du commentaire, et le connecteur v1.0.38 envoie toujours `detail`. Installez le connecteur v1.0.38 par-dessus l'application Proofpoint TRAP existante (mise à jour normale, sur place), réimportez `proofpoint_trap_detail` (il reste inactif — l'orchestrateur le lance) et refaites pointer ses noms d'actifs si vous les aviez modifiés. **La liste personnalisée `proofpoint_trap_excluded_senders` est remplacée par `proofpoint_trap_excluded_email`**, avec les colonnes `email`, `date`, `reason`, `enabled` (voir « Listes personnalisées à remplir ») : créez-la à partir de `custom_lists/proofpoint_trap_excluded_email.json`, recopiez chaque adresse de l'ancienne liste dans une ligne avec `enabled` = `yes`, puis supprimez `proofpoint_trap_excluded_senders` — le playbook ne la lit plus. Tant que la nouvelle liste ne contient pas vos adresses, ces expéditeurs sont traités comme les autres. La liste couvre désormais aussi les destinataires et les Cc. **Signalements via la boîte abuse :** TRAP liste deux fois un e-mail signalé, le signalement (`abuseCopy` true : l'analyseur qui le transfère à la boîte abuse) et l'e-mail signalé lui-même (`abuseCopy` false). Quand une alerte porte les deux, l'expéditeur, le destinataire et les Cc du signalement n'ont pas d'artefact : les artefacts montrent le vrai expéditeur et la vraie cible ; l'utilisateur qui l'a signalé (`X-PhishAlarm-Reporter`) apparaît comme `Recipient Email` avec le rôle `reporter`.

- **Un conteneur se ferme quand son incident est fermé dans TRAP (2026-10-02).** Jusqu'ici, seule une fermeture faite depuis SOAR (`proofpoint_trap_close`) fermait le conteneur ; une fermeture faite dans TRAP était vue par `proofpoint_trap_recheck` mais laissait le conteneur ouvert. `proofpoint_trap_detail` enregistre désormais l'état TRAP de l'incident sur `Enrichment Complete` (champ `incidentState`), et `proofpoint_trap_summary`, que l'orchestrateur lance en dernier, ferme le conteneur quand cet état vaut `closed` et ajoute une note **Closed in TRAP**. Il ne le fait qu'une fois : si un analyste rouvre le conteneur, celui-ci reste ouvert. Le tableau « Enrichment runs » du résumé affiche l'état TRAP. Seuls les incidents dans la fenêtre de `proofpoint_trap_recheck` sont vus. **`proofpoint_trap_recheck` ne regardait que les incidents à l'état `new` :** il devait lister tous les états, mais SOAR supprime un paramètre vide, si bien que le connecteur listait sa valeur par défaut `new` — un incident passé à `open` ou `closed` dans TRAP n'était jamais revérifié. Il liste désormais `new`, `open` et `closed`. Réimportez `proofpoint_trap_detail` et `proofpoint_trap_summary` (tous deux restent inactifs — l'orchestrateur les lance) ainsi que `proofpoint_trap_recheck` (gardez-le actif), et refaites pointer leurs noms d'actifs si vous les aviez modifiés. À sa première exécution après la mise à jour, la revérification voit chaque incident de sa fenêtre dont l'état a changé depuis qu'elle l'a vu à `new` : chacun reçoit une mise à jour, une ré-exécution de l'enrichissement et, s'il est fermé dans TRAP, un conteneur fermé — attendez-vous alors à un pic.

- **Les URL des notes ne sont plus cliquables (2026-10-05).** SOAR transforme une URL d'une note en lien sauf si elle est entre accents graves (backticks). `proofpoint_trap_summary` met désormais chaque URL de ses tableaux entre accents graves, et `proofpoint_trap_detail` fait de même pour la ligne de résumé de l'incident ; les notes d'e-mail de `proofpoint_trap_attachments` le faisaient déjà. Deux liens restent cliquables volontairement : **Open in TRAP** dans la note de détail et les liens du navigateur isolé de `proofpoint_trap_isolation_notify`. Réimportez `proofpoint_trap_detail` et `proofpoint_trap_summary` (tous deux restent inactifs — l'orchestrateur les lance) et refaites pointer leurs noms d'actifs si vous les aviez modifiés. Les notes écrites avant la mise à jour gardent leurs liens ; une note de résumé est réécrite à la prochaine exécution du conteneur.

- **Libellés et types de données des artefacts (2026-10-06).** Chaque artefact créé par les playbooks porte désormais le libellé `event`, `Enrichment Complete` et `Enrichment Failed` compris (ils avaient leurs propres libellés, que rien ne lisait ; les playbooks les retrouvent par leur nom). `proofpoint_trap_detail` ne laisse plus SOAR deviner un type de données pour les champs qu'il ne déclare pas (SOAR avait marqué le rôle de l'e-mail, l'objet, les dates et l'état de l'incident comme `domain` / `host name`), et déclare : le `messageId` de l'expéditeur comme `internet message id`, l'`url` d'un domaine menaçant comme `url`, `fileName` comme `file name` sur `MIME Body` et `Email Attachment`, et l'`incidentId` d'un `Event Info Update` comme `proofpoint trap incident id` (les actions TRAP y sont proposées). Avec les seules applications de messagerie IMAP et SMTP, `internet message id` ne propose encore aucune action ; `email` et `vault id` proposent `send email` de SMTP. Réimportez `proofpoint_trap_detail`, `proofpoint_trap_attachments` (tous deux restent inactifs) et `proofpoint_trap_recheck` (vérifiez qu'il est toujours actif après l'import), et refaites pointer leurs noms d'actifs si vous les aviez modifiés. Les artefacts créés avant la mise à jour gardent leurs libellés et types de données.

- **Préfixe du navigateur isolé (2026-10-07).** La valeur par défaut de `isolation_browser_url` dans `proofpoint_trap_isolation_notify` est désormais `https://www.domain.tld/browser?url=` (elle était `https://my_isolated_browser/browser?url=`). C'est toujours une valeur d'exemple : saisissez le vrai préfixe de votre navigateur isolé dans le champ `isolation_browser_url` au lancement du playbook, ou définissez-le une fois comme valeur par défaut — ouvrez le playbook dans l'éditeur, modifiez `DEFAULT_ISOLATION_BROWSER_URL` dans son Global Custom Code et enregistrez. L'URL cible reste encodée (URL encoding) après `?url=` (`:` et `/` deviennent `%3A` et `%2F`, les points restent), par exemple `https://www.domain.tld/browser?url=https%3A%2F%2Fwww.google.fr%2F`. Réimportez `proofpoint_trap_isolation_notify` (un playbook de données : rien à activer) et refaites pointer le nom de son actif `smtp` si vous l'aviez modifié. Si vous aviez déjà défini votre propre valeur par défaut dans ce playbook, l'import la remplace : redéfinissez-la.

- **Expéditeur, en-têtes, verdict CLEAR et pièces jointes (2026-10-07, vos retours).** (1) Quand TRAP ne donne que le signalement (pas de copie de l'e-mail signalé), comme pour un signalement envoyé depuis une boîte partagée, et que le signalement porte l'en-tête `X-PhishAlarm-Sender`, `proofpoint_trap_detail` prend l'expéditeur dans cet en-tête : il nomme le cas `TRAP-<id>: <adresse>` et ajoute un Sender Email pour cette adresse. L'expéditeur et le destinataire du signalement lui-même (l'outil de signalement ou la boîte partagée, et la boîte abuse) ne sont pas utilisés, et l'utilisateur ou la boîte qui a signalé devient un Recipient Email de rôle `reporter`. Rien à ajouter dans `proofpoint_trap_excluded_email` pour cela (le paquet r24 disait d'y inscrire la boîte partagée : inutile depuis r25). (2) Chaque Sender Email porte les champs `receivedSpf`, `dkimSignature`, `inReplyTo`, `received` et `phishAlarmSender` ; la note Email Content affiche In-Reply-To, X-PhishAlarm-Sender, Received-SPF et DKIM-Signature ; le TRAP Summary a les colonnes correspondantes. (3) Le TRAP Summary commence par le verdict CLEAR (Abuse Disposition / Sub Disposition) et les noms de menaces des alertes de l'incident. `proofpoint_trap_triage` fixe la sévérité à la plus haute entre TRAP Severity et le verdict (Malicious → high ; Suspicious, False Negative, Unknown / Needs Manual Review ou Unknown seul → medium ; le reste → low) et étiquette le cas avec le verdict, par exemple `trap-needs-manual-review` ou `trap-malicious` ; un nouveau verdict remplace cette étiquette et aucune autre n'est touchée. (4) Email Attachment reçoit le MD5 et la taille (`fileHashMd5`, `fileSize`) ; quand l'e-mail d'origine d'une alerte ne peut pas être téléchargé, les pièces jointes que TRAP liste pour elle sont ajoutées à partir des données de TRAP (aucun fichier dans le Vault). Réimportez `proofpoint_trap_detail`, `proofpoint_trap_attachments`, `proofpoint_trap_triage` et `proofpoint_trap_summary` (tous les quatre restent inactifs), et refaites pointer leurs noms d'actifs si vous les aviez modifiés. Les cas enrichis avant la mise à jour gardent leurs artefacts Sender Email sans les nouveaux champs.

- **X-PhishAlarm-Sender avec un guillemet non fermé (2026-10-08, votre exemple).** Sur votre appliance, l'en-tête a la forme `"Nom <adresse>` : le guillemet avant le nom n'est jamais fermé. Jusqu'au paquet r25, `proofpoint_trap_detail` prenait alors tout le texte comme adresse : le nom du cas et le Sender Email affichaient `Nom <adresse>`, et le Sender Domain se terminait par `>`. Il lit désormais l'adresse entre le dernier `<` et `>` (aussi pour `"Nom" <adresse>`, `Nom <adresse>` et une adresse seule) et ignore une valeur sans adresse valide. Réimportez `proofpoint_trap_detail` (reste inactif). Les cas créés avant gardent leur nom et leurs artefacts.

- **Connecteur 1.0.39 et textes plus courts (2026-10-08).** Installez le connecteur v1.0.39 par-dessus l'app Proofpoint TRAP existante : l'ID d'incident de l'artefact `Event Info` d'un nouveau cas a désormais le type `proofpoint trap incident id`, ce qui propose les actions TRAP sur cet artefact. Réimportez les neuf playbooks : leurs descriptions, notes de blocs et commentaires sont plus courts, ainsi que trois notes. `TRAP Triage - Severity` ne répète plus la table de correspondance (elle est dans la section PB2 du plan d'implémentation), `TRAP Detail` perd sa dernière phrase et une ligne Summary vide, et `Attachment Extraction` tient en une ligne quand aucun e-mail n'a de pièce jointe. Rien d'autre ne change : gardez `proofpoint_trap_orchestrator` et `proofpoint_trap_recheck` actifs et les quatre autres playbooks d'automatisation inactifs. Le plan d'implémentation dans `docs/` ne décrit plus que la conception actuelle.

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
   fichier contient le tableau `content` exact (les lignes définies par ce paquet, jamais les lignes de données de la source) à
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
5. **Activer les playbooks d'automatisation** (`proofpoint_trap_recheck`, `proofpoint_trap_orchestrator`) et définir leur utilisateur
   **Run As** selon le guide d'installation du document de plan d'implémentation
   (voir `docs/`).
   **Laissez-les inactifs :** `proofpoint_trap_detail`, `proofpoint_trap_triage`, `proofpoint_trap_attachments`, `proofpoint_trap_summary` — un playbook orchestrateur ci-dessus les appelle l'un
   après l'autre ; actifs, ils se lanceraient aussi d'eux-mêmes, en même temps que lui.
   Désactivez-les si un paquet précédent les avait activés.

## Listes personnalisées appartenant à ce cas d'usage

Ces listes constituent **l'état interne des playbooks** : créez-les vides (étape
ci-dessus), puis n'y touchez plus. Le playbook les remplit et les entretient lui-même ;
une ligne saisie à la main est relue comme un état réel et le fera réagir à des
événements qui n'ont jamais eu lieu.

- `proofpoint_trap_recheck_state` : `incident_id, signature` — écrite par le playbook, pas par vous.

Consultez le document de plan d'implémentation dans `docs/` pour savoir ce que le
playbook y stocke et à quel moment.

## Listes personnalisées à remplir

Réglages lus par les playbooks. Créez-les (étape ci-dessus), puis remplissez-les comme
l'indique la description de chaque liste ci-dessous, si besoin ; le cas d'usage fonctionne
avec les listes telles que livrées.

- `proofpoint_trap_excluded_email` : adresses e-mail que `proofpoint_trap_detail` et `proofpoint_trap_attachments` écartent, comme expéditeur, destinataire ou Cc — typiquement une adresse présente sur chaque incident. Colonnes : `email` (l'adresse, sans tenir compte de la casse), `date` (JJ/MM/AAAA) et `reason` (pour vous uniquement), `enabled` (`yes` pour appliquer la ligne, toute autre valeur pour la garder sans l'appliquer). Le fichier est livré avec deux lignes d'exemple, `sender1@example.com` et `sender2@example.com` : remplacez-les par vos vraies adresses (example.com n'envoie jamais de vrai courrier : laissées telles quelles, elles ne correspondent à rien). Une adresse écartée n'a pas d'artefact `Sender Email` ni `Recipient Email`, son domaine pas d'artefact `Sender Domain` (sauf si un autre expéditeur le partage), et elle ne nomme jamais un conteneur : quand TRAP ne donne pas de résumé à un incident, le conteneur est nommé `TRAP-<id>: <premier expéditeur non écarté>` au lieu de `TRAP-<id>: No summary`. Sans ligne activée, rien n'est écarté ; la ligne d'en-tête est ignorée.

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
