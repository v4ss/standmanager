# Changelog

Toutes les modifications notables apportées à **StandManager** sont consignées
dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et
les versions respectent [Semantic Versioning](https://semver.org/lang/fr/).

---

## [2.2.0] - 2026-06-01

Release majeure : ajout du **Dashboard météo SSI**, refonte de l'analyse
différentielle (fix de faux positifs), durcissement de la collecte EVTX.

### Ajouté

- **Dashboard météo SSI** (`-Action Dashboard` ou option 5 du menu) :
  - Génère un fichier HTML auto-contenu (aucune dépendance, aucun CDN,
    aucun serveur) dans `<SaveDestination>\_Dashboard\`.
  - Code couleur sobre blanc/gris/bleu avec touches de criticité.
  - 7 états météo : ☀️ Clair / 🌤️ Éclaircies / ⛅ Nuageux / 🌧️ Pluie /
    ⛈️ Orage / ❓ Obsolète / ❌ Sans données.
  - Bandeau KPI (SI, postes, couverture < 7 j, alertes crit/élevées,
    postes oubliés > 30 j).
  - Panel météo par SI (cards cliquables).
  - Graphique SVG de distribution par criticité (généré côté PowerShell).
  - Heatmap SI × criticité.
  - Tableau des postes triable + filtrable (recherche libre, filtre météo,
    filtre SI), score de priorisation décroissant par défaut.
  - Top 20 règles Hayabusa déclenchées (priorité criticité puis volume).
  - Liste des postes oubliés (> 30 jours sans collecte).
  - Lien direct vers chaque CSV Hayabusa depuis le tableau.
  - Génère `Dashboard_SSI_YYYYMMDD-HHMMSS.html` + raccourci stable
    `latest.html`.

- **Helper `Copy-LatestArtifacts`** intégré à `Invoke-NetworkBackup` :
  copie automatiquement vers `<SaveDestination>\<SI>\<Poste>\latest\`
  les artefacts récents (hayabusa.csv, system_audit.json, last_export.txt,
  rapport_export.txt, export_manifest.csv, meta.json) pour alimenter le
  dashboard sans dézippage.

- **Configuration enrichie** (`standmanager.config.json`) :
  - `CompressionLevel` : `Optimal` / `Fastest` / `NoCompression`.
  - `HayabusaProfile` : profil passé à `csv-timeline` (ex. `standard`,
    `verbose`).
  - `EventLogs` : liste configurable des journaux à exporter.

- **Audit système enrichi** :
  - Détection d'un redémarrage Windows en attente (`PendingReboot`).
  - Date d'installation de l'OS (`InstallDate`).
  - Statut de protection BitLocker (`ProtectionStatus`).
  - 50 derniers correctifs Windows seulement (limite la taille du JSON).

- **Manifests d'intégrité** :
  - `export_manifest.csv` : SHA-256 + taille de chaque EVTX exporté.
  - `<archive>.sha256.txt` : empreinte au format `sha256  filename`
    déposée à côté de chaque ZIP réseau.
  - `<archive>.manifest.json` : opérateur, taille, source, horodatage.

- **Liste de services critiques protégés** : Defender, MpsSvc, EventLog,
  RpcSs, RpcEptMapper, DcomLaunch, LSM, PlugPlay, Schedule, BFE, CryptSvc,
  Dnscache, LanmanWorkstation, Netman, NlaSvc, nsi, Power, ProfSvc. Ne
  seront **jamais** désactivés par le module de triage, même si la
  réponse au questionnaire les inclut.

- **CLI étendue** :
  - `-Action Dashboard` ajouté au `ValidateSet`.
  - `-CreateBaseline` pour créer toutes les baselines sans interroger.

### Modifié

- **Renommage Verb-Noun** des fonctions selon les conventions PowerShell :
  - `Load-Config` → `Import-StandManagerConfig`
  - `Ensure-Path` → `Confirm-Directory`
  - `Prompt-YesNo` → `Read-YesNoChoice`
  - `Get-UserInputMenu` → `Show-MainMenu`
  - `Get-UsbDrive` → `Get-DriveRoot` (le script peut tourner hors USB)
  - `Export-Trellix-Logs` → `Export-TrellixLogs`
  - `Collect-SystemAudit` → `Invoke-SystemAudit`
  - `Differential-Analysis` → `Invoke-DifferentialAnalysis`
  - `SaveLog` → `Invoke-NetworkBackup`
  - `Service-Triage` → `Invoke-ServiceTriage`
  - `Restore-Services` → `Restore-ServiceStartup`

- **`Invoke-DifferentialAnalysis` : refonte complète** (voir aussi
  *Corrigé* et *Cassant* ci-dessous).
  - Comparaison par **clés uniques** (chaînes dédoublonnées) au lieu de
    collections d'objets multi-colonnes.
  - Lookup `HashSet<string>` insensible à la casse, O(n) au lieu de O(n×m).
  - Réseau : suivi des **ports en écoute uniquement** (`Get-NetTCPConnection
    -State Listen`) au lieu de toutes les connexions TCP (qui changent en
    permanence).
  - Stockage en **texte plat** (1 entrée par ligne) au lieu de CSV
    multi-colonnes, pour éliminer le piège `"" vs $null` après ré-import.
  - **Affichage des ajouts uniquement** (clés présentes dans le snapshot
    courant et absentes de la baseline). Les disparitions ne sont plus
    affichées (réduction du bruit pour le RSSI).

- **Sauvegarde réseau** : test de l'accessibilité du `SaveDestination`
  avant écriture, abandon propre si inaccessible.

- **Niveau de compression** ZIP configurable via
  `CompressionLevel` (par défaut `Optimal`).

- **Compatibilité ascendante** : si une config contient `RnsdaDestination`
  (ancien nom), il est automatiquement promu en `SaveDestination`.

- **Menu principal** : nouvelle entrée *5. Dashboard météo SSI*, *Quitter*
  passe en *6*.

### Corrigé

- **`Invoke-WevtutilExport` rejetait le premier export d'un poste** :
  `[DateTime]$Since` refuse `$null`, donc lorsque `last_export.txt`
  n'existait pas (premier passage), les 4 journaux échouaient avec
  *"Impossible de convertir la valeur Null en type System.DateTime"*.
  Type devenu `[Nullable[DateTime]]`.

- **`Invoke-DifferentialAnalysis` affichait des diffs fantômes** :
  - `Get-Process` retourne `Path = $null` pour les processus protégés
    (csrss, smss, wininit, Idle, services système). Après `Import-Csv`,
    ce `$null` devenait `""`. `Compare-Object` considérait ces valeurs
    comme différentes → chaque processus protégé apparaissait à la fois
    en `=>` et en `<=`.
  - Les multi-instances (svchost, csrss, conhost) créaient du bruit en
    continu car non dédoublonnées.
  - `Get-NetTCPConnection` toutes connexions remontait des sessions
    client volatiles → 100 % de faux positifs entre deux runs.

- **Sortie du menu principal cassée** : le `break` dans `switch` à
  l'intérieur d'un `while` ne sortait que du `switch`. Remplacé par un
  drapeau `$running`.

- **`Load-Config` (ex-)** : `-not $json.PSObject.Properties.Name -contains
  $key` était mal parenthésé, ce qui empêchait la fusion correcte des
  clés manquantes lors du rechargement.

- **Backtick-n dans des chaînes single-quoted** : `'`n...'` n'insérait
  pas de saut de ligne, le `` ` `` étant interprété littéralement.
  Reformaté en double-quotes ou en `Write-Host ''`.

- **Variable `$input`** (automatique en pipeline) renommée `$ctx` pour
  éviter les conflits silencieux.

- **`Get-PosteWeather`** : utilisation de `[char]::ConvertFromUtf32()`
  pour les emojis hors BMP (🌧️, 🌤️ — codepoints > 0xFFFF) qui
  faisaient planter `[char]`.

### Cassant

- **Schéma des baselines de l'analyse différentielle**. Les fichiers
  `services-baseline.csv`, `process-baseline.csv`, `network-baseline.csv`,
  `scheduled-baseline.csv` sont remplacés par :
  - `services.baseline`
  - `processes.baseline`
  - `listening-ports.baseline`
  - `scheduled-tasks.baseline`

  Les anciens fichiers ne sont **pas migrés automatiquement**. Au prochain
  passage, le script propose de créer les nouvelles baselines (ou en
  silence avec `-CreateBaseline`).

- **Comparaison réseau** : passe de *« toutes les connexions TCP »* à
  *« ports en écoute uniquement »*. Le contenu de la baseline réseau
  change radicalement.

### Migration depuis 2.1.x

Au prochain passage sur chaque poste isolé :

```powershell
.\standmanager.ps1 -Action Export -SIName SIxx -ComputerName XXX -CreateBaseline -NoAnalyze
```

Cela recrée silencieusement les 4 nouvelles baselines. Les anciens fichiers
`*-baseline.csv` sous `<poste>\baseline\` peuvent être supprimés à la main
(ils ne gênent pas s'ils restent).

---

## [2.1.0] - antérieur

Version intermédiaire (non publiée) :
- Ajout préliminaire du dashboard météo SSI.
- Refonte des manifests de sauvegarde réseau.

## [2.0.0] - antérieur

Refonte majeure depuis la version originale :
- Convention Verb-Noun pour toutes les fonctions.
- Mode interactif robuste + dispatch CLI complet.
- Liste de services critiques protégés du triage.
- Manifest d'intégrité (SHA-256) sur EVTX et archives.

## [1.0.0] - origine

Première version : collecte EVTX + Trellix, audit système basique,
analyse différentielle, sauvegarde réseau.
