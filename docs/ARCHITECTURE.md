# Architecture cible SSR — Phase 0

**Statut :** proposition d’architecture et de séquencement ; aucune implémentation de payload effectuée.  
**Cible demandée :** Nintendo Switch 1, firmware de référence 23.0.1. La version réellement observée doit toujours provenir d’une lecture réussie et ne doit jamais être supposée égale à la cible.

## 1. Objectif, frontières et non-objectifs

SSR comprend deux collecteurs autonomes :

1. un homebrew `.nro` exécuté sous Horizon OS ;
2. un payload `.bin` exécuté dans un environnement pré-démarrage défini.

Chaque collecteur collecte uniquement ce que son contexte lui rend effectivement accessible, exécute des vérifications locales déterministes en lecture seule et émet son propre rapport JSON. Ils peuvent adopter un même **contrat de données** sans partager les mêmes API, privilèges, bibliothèques ou chaîne de compilation.

Hors périmètre de cette phase et de la prochaine implémentation tant qu’elle n’est pas validée :

- moteur d’analyse PC, analyseur firmware externe, interface web ou service en ligne ;
- exécution de contrôles non documentés, contournement de permissions ou collecte d’identifiants privés ;
- écriture firmware/NAND, programmation de fusibles, altération d’identifiants ou données système ;
- QR code comme format de sortie ou remplacement du JSON.

La création du dossier de rapports et l’écriture du rapport sur la carte SD sont les seules écritures de produit prévues. Elles doivent rester distinctes des données examinées.

## 2. Situation du dépôt

Le projet contient déjà un cœur C++17 et un NRO :

- [Makefile](../Makefile) : cibles `pc`, `test` et `switch`; la cible Switch utilise devkitA64/libnx ;
- [app/main.cpp](../app/main.cpp) : collecte, assemblage du rapport et écriture ;
- [src/platform_horizon.cpp](../src/platform_horizon.cpp) : requêtes `set:sys` de version et de modèle ;
- [src/inventory.cpp](../src/inventory.cpp) : inventaire borné, lecture de fichiers et SHA-256 ;
- [src/report.cpp](../src/report.cpp) : export JSON autonome et écriture protégée contre l’écrasement ;
- [src/scan_engine.cpp](../src/scan_engine.cpp) : orchestration des contrôles et garde sur les statuts `VULNERABLE`.

Le dépôt contient aussi [src/platform_pc.cpp](../src/platform_pc.cpp), une interface CLI PC, une cible `make pc` et des tests de cœur. Il s’agit de code déjà présent, pas d’un travail demandé ici ; aucun analyseur PC nouveau n’est proposé.

Écarts à traiter avant une livraison cible :

| Exigence cible | État observé |
|---|---|
| Sortie commune `sdmc:/rapports_SSR/` | Le NRO écrit désormais sous `sdmc:/rapports_SSR/`, séparément du répertoire d’entrée. |
| Deux collecteurs indépendants NRO et BIN | Seul l’adaptateur NRO est présent ; aucune cible BIN n’est établie. |
| Type de collecteur dans le rapport | Le JSON déclare `collector_type` (`NRO` dans la version Horizon, `PC_TEST` dans l’adaptateur de développement). |
| Liste de contrôles, preuves, erreurs et ressources non accessibles | Le rapport contient ces sections ; les contrôles ne déclarent pas de pourcentage de confiance non méthodologiquement défini. |
| NRO borné aux ressources autorisées | L’inventaire est restreint à `sdmc:/switch/SwitchSecurityResearch/input/` et possède des limites. |
| QR facultatif ultérieur | La génération automatique de QR a été retirée du chemin de rapport ; le JSON est le seul format généré. |
| Rapport autonome et identifiant unique | Le rapport a un schéma JSON versionné et un identifiant SHA-256 complet. Le NRO écrit/ferme un temporaire puis vérifie que la destination est absente avant le renommage ; le test PC réserve la destination avec `O_EXCL` avant de publier, car le renommage POSIX de l’hôte remplace une destination existante. Le refus d’un fichier déjà présent est testé sur PC ; la sémantique Horizon en cas de création concurrente entre le contrôle et le renommage reste à confirmer sur console ou par une garantie explicite de l’API cible. |

Le cœur actuel utilise plusieurs abstractions dépendantes de la bibliothèque standard/POSIX (`fstream`, `chrono`, répertoires et appels de fichiers). Il ne faut pas présumer qu’il est directement compilable en bare-metal avec BDK. Pour le BIN, ne réutiliser que des composants portables vérifiés ou conserver une implémentation indépendante conforme au même schéma JSON.

## 3. Frontières des environnements

### NRO — Horizon OS

Le homebrew s’exécute après le lancement d’Horizon et n’obtient pas une visibilité globale de la console. L’accès est limité aux services, FS et permissions accessibles à son contexte d’exécution.

- **Version firmware et modèle :** appeler explicitement les API `set:sys` libnx (`setsysGetFirmwareVersion`, `setsysGetProductModel`) et enregistrer le résultat, sa source et tout échec. La requête du service ne garantit pas sa disponibilité dans tous les modes de lancement.
- **Services :** aucune énumération générale n’est supposée. SSR doit déclarer une liste de services/API spécifiques à interroger, puis noter chaque succès ou refus/échec. Une absence de réponse ne signifie pas que le service n’existe pas.
- **Fichiers :** uniquement des chemins autorisés et explicitement configurés, sous un répertoire de carte SD défini. Pas de parcours implicite de NAND, partitions système, données d’autres titres, sauvegardes privées ou fichiers hors périmètre. La visibilité d’un fichier n’est pas garantie.
- **Intégrité :** SHA-256 peut établir le condensat des octets lus. Un résultat n’est comparé qu’à une référence versionnée et d’origine vérifiable. Un hash seul ne dit pas qu’un fichier est sain ; une différence mène au plus à `SUSPECT` tant que la référence n’est pas assez fiable pour conclure.
- **Anomalies :** uniquement des règles déterministes sur des éléments effectivement collectés (par exemple, écart à une référence approuvée ou fichier modifié pendant la lecture). Pas d’inférence de vulnérabilité à partir d’une absence d’accès ou d’une simple différence de hash.

### BIN — pré-démarrage

« Payload pré-démarrage » décrit un programme et un contexte précis ; ce n’est ni un mode universel de la console, ni une permission d’inspecter tous les composants. La version BIN devra choisir et figer un environnement d’exécution et un modèle SoC avant sa réalisation.

- **BootROM** : code de démarrage matériel distinct, exécuté en premier. Un payload ultérieur ne peut pas déduire ou exporter son contenu interne simplement parce qu’il s’exécute avant Horizon.
- **Bootloader** : Hekate ou un autre chargeur est un logiciel de démarrage distinct. Son état/configuration peut être rapporté uniquement si le collecteur sait l’observer et l’identifier.
- **Secure Monitor** : composant distinct du bootloader et d’Horizon ; le collecteur ne doit pas prétendre connaître son état interne sans interface de lecture explicitement documentée.
- **Horizon OS** : démarre plus tard. Il n’existe pas encore au moment de la collecte BIN. Une version lue dans un NCA/partition système est une version de l’image installée observée, et non automatiquement la version de l’OS en cours d’exécution.
- **Matériel/chaîne de démarrage :** BDK fournit des méthodes bas niveau spécifiques au matériel, par exemple pour lire des registres fuse/SoC. Cela ne vaut pas pour tous les modèles, toutes les versions, ni toutes les chaînes de démarrage. L’observation d’un payload et d’un bootloader n’est pas une attestation cryptographique de toute la chaîne.
- **Stockage :** n’accéder qu’aux périphériques/partitions approuvés et en lecture seule. La détection d’une image système peut dépendre de données chiffrées, clés, bases à jour et formats reconnus. En cas d’incertitude, rapporter `INCONCLUSIVE` ou `NOT_ACCESSIBLE`, jamais une version inventée.
- **Fusibles :** si la lecture du nombre de fusibles est retenue, limiter la sortie à la valeur agrégée utile ; exclure toute clé, valeur brute de fuse sans justification, ID matériel ou données d’identité. Les appels d’écriture ou de programmation ne sont pas dans la liste blanche.

BDK/FuseCheck sont des références, pas une dépendance décidée. Avant de choisir BDK, vérifier la compatibilité du SoC, les routines réellement appelées et les licences GPL-2.0 et composants inclus. Ne pas porter les fonctions de gestion de clés ou d’écriture de FuseCheck.

## 4. Capacités comparées

| Capacité | NRO / Horizon OS | BIN / pré-démarrage | Règle de restitution |
|---|---|---|---|
| Version firmware | Possible via `set:sys` si service accessible | Conditionnelle à la lecture/analyse fiable d’une image système ; ne prouve pas la version OS en exécution | Valeur, source, type d’observation et statut explicites |
| Informations système | Modèle et champs que les API accessibles retournent | Champs SoC/board lisibles via l’environnement choisi, au cas par cas | Liste blanche ; exclure numéros de série, comptes, certificats, MAC et clés |
| Services | Appels ciblés, un par un ; pas d’énumération globale présumée | Pas de services Horizon disponibles par défaut ; éventuellement état du bootloader courant | Service non ouvert = `NOT_ACCESSIBLE`, pas « absent » ni « OK » |
| Inventaire de fichiers | Répertoire et fichiers explicitement autorisés sur SD | Au minimum les fichiers SD explicitement autorisés ; autres partitions seulement après validation | Ne pas parcourir la NAND entière ; chemins non accessibles conservés comme tels |
| SHA-256 | Faisable pour les octets lus | Faisable si un moteur SHA-256 est disponible et testé dans l’environnement BIN | Un hash est une mesure, pas un verdict de sécurité |
| Vérifications d’anomalies | Références de fichiers vérifiées, format/attribut attendu, erreurs de stabilité | Comparaisons matériels/firmware documentées si données fiables | `VULNERABLE` uniquement avec preuve spécifique et suffisante |
| UTC | Horloge Horizon, à qualifier | RTC peut être absent, non initialisé ou incorrect | Ne pas inventer l’heure ; date absente explicitement signalée |
| Rapport JSON | Écriture via `sdmc:` après montage réussi | Écriture via le pilote SD du bootloader, si carte et FS utilisables | Même répertoire physique sur SD ; échec d’écriture visible |
| USB | Non garanti par libnx ou le lancement courant | Dépend du chargeur et de sa configuration | Récupération primaire par carte SD/lecteur de carte ; ne pas promettre USB non implémenté |

## 5. Contrat de rapport proposé

Les collecteurs écrivent séparément leurs rapports mais respectent un schéma versionné commun. Le contrat de données ne doit pas imposer un runtime ou des API communes.

```json
{
  "schema_version": 1,
  "report_id": "identifiant opaque",
  "collected_at_utc": "2026-11-08T12:34:56Z",
  "collector_type": "NRO",
  "collector_version": "development ou version de build",
  "firmware": {
    "value": null,
    "status": "NOT_ACCESSIBLE",
    "source": "set:sys"
  },
  "system": {},
  "checks": [
    {
      "id": "check-id",
      "status": "INCONCLUSIVE",
      "evidence": [],
      "error": null
    }
  ],
  "inaccessible_resources": [],
  "errors": []
}
```

Le JSON est UTF-8 autonome, lisible, sans référence externe nécessaire pour comprendre le résultat. Chaque valeur observée porte sa provenance et son état. `collected_at_utc` doit être `null` si une heure UTC fiable est indisponible, accompagné d’une erreur ou d’un état explicite ; ne pas fabriquer une date. L’identifiant ne contient aucune donnée console. Sa stratégie doit fonctionner sans garantie d’horloge pré-démarrage et prévenir l’écrasement de rapports existants (nom unique, création exclusive ou renommage vérifié).

Valeurs de statut autorisées :

- `OK` : le contrôle prévu a effectivement été exécuté et son critère documenté est satisfait ;
- `SUSPECT` : observation anormale ou divergence qui justifie une revue, sans preuve suffisante de vulnérabilité ;
- `VULNERABLE` : uniquement si le contrôle confirme une condition vulnérable précise avec une preuve directe et suffisante. Aucun pourcentage de confiance non défini n’est utilisé ; un hash différent ne suffit pas à lui seul ;
- `INCONCLUSIVE` : données partielles, source ou référence non vérifiable, ambiguïté ou contrôle non concluant ;
- `NOT_ACCESSIBLE` : ressource/API explicitement refusée, indisponible ou hors portée.

Un refus d’accès, une erreur de montage, un timeout, une ressource absente d’un inventaire partiel ou une horloge invalide ne doit jamais être converti en `OK`, `SUSPECT` ou `VULNERABLE` sans preuve distincte. Les erreurs décrivent l’opération et le code d’erreur, sans divulguer secrets ou données personnelles.

### Écriture et confidentialité

- Dossier : `sdmc:/rapports_SSR/`, créé si absent. Sur le BIN, le chemin API pourra être `sd:/rapports_SSR/` ou équivalent BDK, mais il doit correspondre au même dossier sur la carte.
- Nom recommandé : identifiant du rapport dans le nom de fichier, sans nom de console ni ID privé.
- Écrire d’abord un fichier temporaire, vérifier la fermeture/flush, puis renommer sans écraser un rapport existant. Toute panne de création, espace insuffisant ou écriture partielle doit être signalée ; ne pas afficher « rapport enregistré » si ce n’est pas vrai.
- N’inclure que des champs nécessaires. Exclure clés, secrets, numéros de série, identifiants de compte, certificats, adresses MAC et données privées.
- La carte SD et le JSON sont la voie de récupération garantie par conception ; un transfert USB est une fonction distincte à développer et tester. Aucun QR n’est requis avant validation du schéma et des règles de confidentialité.

## 6. Découpage logiciel cible

### NRO

1. **Démarrage et capacités :** initialiser libnx ; tenter le montage SD et les services autorisés ; journaliser les retours libnx et conserver `NOT_ACCESSIBLE` si nécessaire.
2. **Collecte déclarative :** demander firmware/modèle via `set:sys`; interroger uniquement une liste de services approuvée ; inventorier uniquement la liste de chemins autorisée.
3. **Vérifications locales :** SHA-256 en lecture seule, comparaisons à une référence dont l’origine/version est identifiée, contrôles déterministes à preuve traçable.
4. **Rapport :** remplir le schéma commun, créer `sdmc:/rapports_SSR/`, vérifier l’écriture JSON. Les erreurs de collecte n’effacent pas les observations valides.

### BIN

1. **Choix préalable de l’environnement :** SoC/modèles, chargeur/version, toolchain, format de lancement, API BDK minimales et compatibilité de licence.
2. **Initialisation minimale :** accès écran/entrée seulement si requis ; initialiser la SD et l’horloge sans modifier l’état système.
3. **Collecte bornée :** lire uniquement les registres et fichiers approuvés ; ne pas déchiffrer/extraire de clés ou appeler une routine de programmation.
4. **Vérifications :** appliquer la même sémantique de statut et de preuve que le NRO. Distinguer une version lue dans la partition d’une version réellement exécutée.
5. **Rapport :** produire le JSON avec la même version de schéma et le déposer dans le répertoire commun de la carte.

Un adaptateur BIN séparé est nécessaire : le code actuel s’appuie sur des fonctionnalités C++/POSIX qui ne sont pas garanties dans l’environnement BDK bare-metal. Une éventuelle extraction de composants partagés (SHA-256, sérialisation JSON, types de statut) doit être précédée d’un test de compilation freestanding et ne doit pas créer un couplage aux services Horizon.

## 7. Ordre de développement réaliste après validation

1. **Valider le périmètre et les licences BIN** : choisir source BDK ou réécriture minimale, modèles/SoC pris en charge, données matérielles autorisées.
2. **Valider sur Switch le collecteur NRO** : comportement `set:sys`, permission/montage SD, dossier de sortie, fermeture/renommage et récupération des rapports.
3. **Compléter les contrôles NRO seulement si autorisés** : réviser les chemins d’inventaire et les références SHA-256 ; tester sur matériel accès refusé, fichiers absents/modifiés et SD pleine.
4. **Étude de faisabilité BIN** (hors implémentation de cette phase) : vérifier le démarrage cible, l’accès SD/RTC, les API BDK nécessaires, les lectures matérielles retenues et les exigences GPL ; faire approuver avant tout prototype séparé.
5. **Implémenter ultérieurement le BIN minimal** : système/SoC non privé, capacités effectivement accessibles, rapport JSON seulement, aucune routine d’écriture/clé.
6. **Valider les deux outils sur matériel autorisé** : versions et modèles déclarés, horloges invalides, SD retirée/pleine, service refusé, données firmware inconnues, JSON récupérable via lecteur de carte ; documenter ce qui n’a pas pu être testé.

Les tests du cœur portable sur PC sont permis comme tests unitaires locaux, mais ne constituent pas un analyseur PC et ne justifient pas de développer un tel produit. Toute valeur de `VULNERABLE` doit avoir un test de preuve et un cas négatif correspondant ; en l’absence de preuve, le statut reste `SUSPECT`, `INCONCLUSIVE` ou `NOT_ACCESSIBLE`.

## 8. Décisions à valider avant implémentation

1. **Licence BIN :** accepter l’intégration de code BDK soumis à GPL-2.0 (et l’examen des composants embarqués), ou imposer une implémentation indépendante limitée à des interfaces documentées.
2. **Cible matérielle de phase 1 :** quels modèles/révisions Switch 1, quelle chaîne pré-démarrage et quel chargeur/version sont disponibles pour des tests reproductibles ?
3. **Périmètre fichiers NRO :** confirmer le répertoire SD d’entrée autorisé et si les références SHA-256 sont fournies par SSR, par l’utilisateur ou par une source signée.
4. **Données BIN :** confirmer si le rapport peut inclure le nombre agrégé de fusibles et les versions lues dans SYSTEM ; dans tous les cas, exclure les valeurs brutes de fusibles, les clés et les identifiants.
5. **Temps et identifiant :** décider du comportement acceptable si RTC ou source d’entropie ne sont pas fiables ; le collecteur ne doit ni prétendre une UTC exacte ni écraser un rapport existant.
6. **Licence SSR :** choisir une licence du dépôt avant toute redistribution de code ou dépendances.
7. **Récupération :** confirmer que la carte SD/lecteur de carte est le mécanisme de base et que USB reste optionnel, sans promesse de support jusqu’à implémentation.
