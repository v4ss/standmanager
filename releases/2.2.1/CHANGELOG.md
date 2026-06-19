# Changelog

Toutes les modifications notables de **StandManager** sont consignées ici.

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
versions selon [Semantic Versioning](https://semver.org/lang/fr/).

---

## [2.2.1] - 2026-06-02

Fiabilisation du dashboard météo face aux gros parcs et aux postes sans
analyse, plus une suite de tests interne pour prévenir les régressions.

### Corrigé

- **Dashboard — `PercentComplete` supérieur à 100.** Sur un SI comportant
  plus de 10 postes, la barre de progression dépassait 100 % et
  `Write-Progress` levait une erreur bloquante. La progression est désormais
  calculée sur le nombre réel de postes puis bornée à 100.
- **Dashboard — erreur « propriété Count introuvable ».** Lorsqu'aucun poste
  n'avait de règle Hayabusa déclenchée, la liste des règles valait `$null` et
  son `.Count` plantait sous `Set-StrictMode`. Les collections concernées
  (`$topRules`, `$siGroups`) sont maintenant toujours encapsulées en tableau.
- **`Get-HayabusaSummary` — plantage sur un CSV à une seule ligne.**
  `Import-Csv` renvoie un objet unique (et non un tableau) pour une seule
  détection ; `$rows.Count` échouait alors sous StrictMode. Un poste isolé
  avec une unique alerte aurait fait échouer toute la génération du dashboard.
  *(Bug mis en évidence par la nouvelle suite de tests.)*
- **Nettoyage cosmétique** : `Invoke-HayabusaAnalysis` n'écrase plus la
  variable automatique `$profile` (renommée `$hayProfile`).

### Ajouté

- **Suite de tests Pester interne** (`tests/`, non livrée au client) :
  63 tests couvrant les fonctions pures (météo SSI, parsing Hayabusa,
  dispatch CLI, nettoyage de noms, encodage HTML, chargement de config,
  horodatage d'export) et les régressions connues (faux positifs de
  l'analyse différentielle, `.Count`, `PercentComplete`, binding `wevtutil`).
  Les fonctions sont chargées par analyse AST sans exécuter le menu : le
  script livré reste inchangé. Compatible Pester 3.4 (fourni avec Windows)
  et 5.x. Lancement : `.\tests\Invoke-Tests.ps1`.

---

## [2.2.0] - 2026-06-01

Ajout du **Dashboard météo SSI**, refonte de l'analyse différentielle,
durcissement de la collecte EVTX.

### Ajouté

- **Dashboard météo SSI** (`-Action Dashboard` ou option 5 du menu) :
  - Fichier HTML auto-contenu (aucune dépendance, aucun CDN, aucun serveur),
    déposé dans `<SaveDestination>\_Dashboard\`.
  - Charte sobre blanc / gris / bleu.
  - 7 états météo : Clair, Éclaircies, Nuageux, Pluie, Orage, Obsolète,
    Sans données.
  - Bandeau KPI (SI, postes, couverture, alertes critiques / élevées,
    postes oubliés).
  - Panel météo par SI, graphique SVG par criticité, heatmap SI × criticité.
  - Tableau des postes triable et filtrable (recherche, météo, SI), trié par
    score de priorisation décroissant.
  - Top 20 des règles Hayabusa déclenchées, liste des postes oubliés,
    lien direct vers chaque CSV d'analyse.
  - Sortie horodatée + raccourci stable `latest.html`.
- **Extraction des artefacts récents** vers
  `<SaveDestination>\<SI>\<Poste>\latest\` à chaque sauvegarde réseau, pour
  alimenter le dashboard sans avoir à décompresser les archives.
- **Configuration enrichie** : `CompressionLevel`, `HayabusaProfile`,
  `EventLogs`.
- **Audit système étendu** : redémarrage en attente, date d'installation OS,
  statut de protection BitLocker, 50 derniers correctifs.
- **Manifests d'intégrité** : `export_manifest.csv` (SHA-256 des EVTX),
  `.sha256.txt` et `.manifest.json` à côté de chaque archive réseau.
- **Services critiques protégés** : Defender, MpsSvc, EventLog, RpcSs, BFE,
  etc. ne sont jamais désactivés par le triage, quelles que soient les
  réponses au questionnaire.

### Modifié

- Renommage Verb-Noun de toutes les fonctions selon les conventions
  PowerShell.
- **Analyse différentielle** entièrement revue (voir *Corrigé*).
- Vérification de l'accessibilité du partage réseau avant écriture.
- Compatibilité ascendante de l'ancien nom de configuration
  `RnsdaDestination` vers `SaveDestination`.

### Corrigé

- **Premier export EVTX d'un poste** : `wevtutil` échouait sur les 4 journaux
  car `$Since` n'acceptait pas `$null` (type passé en `[Nullable[DateTime]]`).
- **Analyse différentielle — faux positifs** : chaque processus protégé
  apparaissait en double (`=>` et `<=`) à cause de la différence `"" vs $null`
  après ré-import CSV, des instances multiples non dédupliquées et des
  connexions TCP volatiles. La comparaison se fait désormais sur des clés
  uniques, n'affiche que les ajouts, et le réseau se limite aux ports en
  écoute.
- Sortie du menu principal (`break` qui ne quittait pas la boucle).
- Fusion des clés de configuration manquantes.
- Sauts de ligne `` `n `` mal interprétés dans des chaînes à apostrophes.
- Emojis météo hors plan de base (`[char]::ConvertFromUtf32`).

### Cassant

- **Schéma des baselines de l'analyse différentielle** : les anciens
  `*-baseline.csv` sont remplacés par `services.baseline`,
  `processes.baseline`, `listening-ports.baseline`,
  `scheduled-tasks.baseline`. Non migrés automatiquement : recréer au
  prochain passage (`-CreateBaseline`).
- La comparaison réseau passe de « toutes les connexions TCP » à
  « ports en écoute uniquement ».

### Migration depuis 2.0.x / 2.1.x

```powershell
.\standmanager.ps1 -Action Export -SIName SIxx -ComputerName XXX -CreateBaseline -NoAnalyze
```

Recrée silencieusement les nouvelles baselines. Les anciens `*-baseline.csv`
peuvent être supprimés.

---

## [2.0.0]

Refonte majeure depuis la version d'origine :

- Convention Verb-Noun pour toutes les fonctions.
- Mode interactif robuste et dispatch CLI complet
  (`Triage`, `Restore`, `Export`, `Save`, `Quit`).
- Liste de services critiques protégés du triage.
- Empreintes SHA-256 sur les EVTX et les archives.

---

## [1.0.0]

Première version : collecte EVTX + logs antivirus, audit système, analyse
différentielle, sauvegarde réseau.
