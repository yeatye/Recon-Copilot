# recon-copilot

Copilote de reconnaissance assiste par IA pour pentest manuel a faible
agressivite (PFA). Pipeline complet, 7 modules, chacun teste
unitairement ET valide au moins une fois avec de vrais outils externes
(pas seulement des mocks) pendant le developpement.

```
scan (Nmap+Nuclei) -> parsing -> correlation LLM -> scoring -> [fuzzing]
                                                                    |
                                                                    v
                                            revue humaine <- (jamais saute)
                                                    |
                                                    v
                                    rapport FR/EN (MD/DOCX/PDF)
```

Diagramme complet avec flux de donnees : `docs/pipeline.mmd` (Mermaid).

## Modules

| Module | Role |
|---|---|
| `scanner` | Nmap + Nuclei, scope non-negociable, profils d'agressivite, throttling, audit |
| `parser` | Normalise XML Nmap / JSONL Nuclei en schema commun, garde une preuve source exacte |
| `correlation` | 1 appel LLM par cible (OpenAI ou Ollama), table CVE/CWE/MITRE statique **+ RAG optionnel**, **verifie chaque citation contre les donnees reelles** |
| `rag` | Enrichissement optionnel de la correlation : base vectorielle locale (ChromaDB), ingestion CISA KEV + templates Nuclei, recherche semantique |
| `scoring` | Score de risque composite (severite + exposition + criticite actif) |
| `fuzzing` | Genere des payloads (1 appel LLM) -> ffuf -> diff baseline -> triage des anomalies (1 appel LLM groupe, 0 si rien d'anormal) |
| `review` | CLI texte **ou TUI Textual** (`--tui`) pour accepter/editer/rejeter — rien ne passe au rapport sans ca |
| `report` | Rapport FR/EN en Markdown/DOCX/PDF **+ export SARIF et CycloneDX VEX**, uniquement les findings accepted/edited |

## RAG (optionnel, additif)

`correlation/` accepte un `rag_index: RagIndex | None = None`. A `None`
(defaut), le comportement est identique a avant l'existence du module RAG
-- aucune regression, memes tests. Fourni, une recherche semantique
(embeddings) enrichit le prompt
avec les entrees CISA KEV et templates Nuclei les plus proches
semantiquement de la detection en cours. La table statique
(`knowledge_base.py`) reste le socle deterministe et n'est jamais
remplacee -- c'est une contrainte du cahier des charges original ("sans
RAG"), toujours respectee en tant que base ; le RAG n'est qu'une couche
d'enrichissement par-dessus.

### Activation via la configuration (recommande)

Ajoute une section `rag:` dans `config/engagement.yaml` ; le pipeline
construit (ou reutilise, l'index est persistant) automatiquement l'index
au premier scan :

```yaml
rag:
  enabled: true
  persist_directory: "./data/rag_index"
  cisa_kev_path: "./data/known_exploited_vulnerabilities.json"
  nuclei_templates_dir: "~/.local/nuclei-templates"
```

Les embeddings sont calcules **100% localement** (`LocalEmbeddingClient`,
modele ONNX `all-MiniLM-L6-v2` embarque par ChromaDB, ~80 Mo telecharges une
fois, puis hors-ligne) -- aucune cle API supplementaire. C'est l'option a
choisir quand la cle LLM n'expose pas de endpoint `/embeddings` (ex: cle
OpenCode) ; les implementations `OpenAIEmbeddingClient` et
`OllamaEmbeddingClient` restent disponibles sinon.

Le catalogue CISA KEV se telecharge une fois ici :

```bash
curl -o data/known_exploited_vulnerabilities.json \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

### Usage programmatique

```python
from recon_copilot.rag import RagIndex, LocalEmbeddingClient, parse_cisa_kev_json, ingest_nuclei_templates_dir

rag_index = RagIndex(LocalEmbeddingClient(), persist_directory="./data/rag_index")

kev_docs, _ = parse_cisa_kev_json(open("known_exploited_vulnerabilities.json").read())
nuclei_docs, _ = ingest_nuclei_templates_dir("~/.local/nuclei-templates")
await rag_index.index_documents(kev_docs + nuclei_docs)

# puis dans le pipeline :
await correlate_and_store(conn, engagement, target, llm_client, host, detections, rag_index=rag_index)
```

## Export SARIF et CycloneDX VEX

```bash
recon-copilot --config config/engagement.yaml report \
    --output ./rapport --formats sarif,vex --langs fr
```

- **SARIF 2.1.0** (`<engagement>.sarif`) — injection dans GitHub Security,
  VS Code, DefectDojo. Structure validee contre le schema officiel OASIS.
  La cible (IP/URL) est utilisee comme `artifactLocation.uri` (SARIF est
  concu pour du code source, convention standard des outils DAST/pentest).
- **CycloneDX VEX 1.5** (`<engagement>.cyclonedx-vex.json`) — chaque cible
  scannee devient un composant synthetique ; chaque finding devient une
  entree `vulnerabilities[]` avec `analysis.state = "exploitable"` (les
  findings du rapport ont deja ete valides par revue humaine). Structure
  validee contre le schema officiel CycloneDX.

Contrairement a md/docx/pdf, SARIF et VEX sont generes **une seule fois**
par run (pas une fois par langue) — ce sont des formats de donnees pour
outillage, pas des documents de lecture bilingues.

## Revue moderne (TUI)

```bash
recon-copilot --config config/engagement.yaml review --analyst houda --tui
```

Interface Textual : tableau des findings en attente (triés par risque),
statut `citation_verified` visible directement (✓ vert / ✗ rouge),
panneau de detail au survol, actions en 1-2 touches (`a` accepter, `e`
editer, `r` rejeter, `q` quitter). Reutilise exactement la meme couche de
donnees que la CLI texte (`review/__init__.py`) — les deux interfaces
produisent des resultats identiques en base. La CLI texte classique reste
le comportement par defaut (`recon-copilot review` sans `--tui`).

## Arborescence et justification

```
recon-copilot/
├── config/engagement.example.yaml   # a copier -> engagement.yaml, jamais commiter avec de vraies cibles
├── docs/pipeline.mmd                # diagramme Mermaid du pipeline complet
├── src/recon_copilot/
│   ├── scope.py                     # SEUL endroit qui decide si une cible est autorisee
│   ├── profiles.py                  # SEUL endroit qui definit furtif/standard/agressif
│   ├── audit.py                     # SEUL endroit qui ecrit dans la piste d'audit
│   ├── db.py                        # schema SQLite complet, partage par tous les modules
│   ├── external_tool.py             # base commune Nmap/Nuclei/ffuf : scope, throttle, timeout, fallback
│   ├── llm_client.py                # interface LlmClient + OpenAIClient (OpenCode/OpenAI) + OllamaClient
│   ├── json_utils.py                # nettoyage des reponses LLM entourees de ```json
│   ├── pipeline.py                  # orchestrateur : scan -> parse -> correlate -> score -> [fuzz]
│   ├── cli.py                       # `recon-copilot scan|review|report`
│   ├── scanner/                     # etape 1
│   ├── parser/                      # etape 2
│   ├── correlation/                 # etape 3
│   ├── scoring/                     # etape 4 (dans le schema) -- composite risk score
│   ├── fuzzing/                     # etape 5
│   ├── review/                      # etape 6 -- data layer + cli.py interactive
│   └── report/                      # etape 7 -- i18n.py, markdown/docx/pdf_report.py
└── tests/                           # miroir de src/, un dossier par module
```

**Pourquoi ce decoupage :**

- **`scope.py`, `audit.py`, `profiles.py`, `external_tool.py`, `llm_client.py`
  sont hors de tout module.** Ce sont des contraintes ou des ressources
  transversales : le scanner ET le fuzzer verifient le meme scope de la
  meme facon (`ExternalToolWrapper`), correlation ET fuzzing appellent le
  meme service LLM (`LlmClient`). Les mettre dans un module aurait force les
  autres a en dependre pour de mauvaises raisons.
- **`db.py` centralise tout le schema SQLite.** Chaque module y ajoute ses
  tables (voir le fichier, commente section par section) plutot que
  d'avoir des migrations eparpillees. Une seule connexion partagee
  traverse tout un run du pipeline.
- **Chaque objet parse garde une preuve source exacte** (`source_fragment`
  pour Nmap, `raw_line` pour Nuclei). Le module `correlation` s'appuie
  dessus pour **verifier programmatiquement** que chaque citation du LLM
  existe reellement dans les donnees fournies (`citation_verified` en
  base) — voir la section "Anti-hallucination" plus bas.
- **`review/` est une couche de donnees testable + une CLI mince**, pas un
  framework web. Le cahier des charges ne precise pas de stack web ; en
  construire une aurait ete hors perimetre technique (Python +
  asyncio/subprocess + SQLite). Toute la logique (`accept_finding`,
  `edit_finding`, `reject_finding`) est independante de la CLI et
  reutilisable par une future interface web sans rien changer.
- **`report/data.py` ne lit QUE les findings `accepted`/`edited`.** Un
  finding `pending` ou `rejected` ne peut jamais atterrir dans un rapport
  — c'est impose au niveau de la requete SQL, pas juste par convention.

## Anti-hallucination : comment la citation est verifiee

Le cahier des charges impose que chaque finding cite la ligne exacte de
l'output brut qui le justifie. Ce n'est pas juste une instruction dans le
prompt (les LLM n'obeissent pas toujours) : `correlation/response_parser.py`
verifie programmatiquement que `source_citation` est une sous-chaine d'au
moins un `source_fragment`/`raw_line` reellement fourni en entree. Si ce
n'est pas le cas, le finding est **conserve** (l'analyste peut vouloir le
voir quand meme) mais marque `citation_verified=False`, et ca remonte
visiblement dans la CLI de revue et dans le rapport final (bandeau
d'avertissement rouge). Rien n'est filtre en silence.

## Installation

```bash
cd recon-copilot
pip install -e ".[dev]"
```

**A installer toi-meme** (non embarque) :

- **Nmap** : `sudo apt install nmap`
- **Nuclei** : `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates`
- **ffuf** : `sudo apt install ffuf` (ou `go install github.com/ffuf/ffuf/v2@latest`)
- **Ollama** (optionnel si `llm.provider: "ollama"`) : installation depuis
  [ollama.com](https://ollama.com), puis `ollama pull llama3` (ou le modele
  de ton choix — adapte `llm.model` dans la config). Doit tourner en local
  (`ollama serve`).

Par defaut (`llm.provider: "opencode"`), le pipeline appelle l'API OpenCode
Zen (`https://opencode.ai/zen/v1`, compatible OpenAI) : renseigne ta cle
API dans `config/engagement.yaml` (`llm.api_key`) — **ne commite jamais ce
fichier avec une vraie cle**. La cle peut aussi etre fournie par la
variable d'environnement `OPENCODE_API_KEY` (ou `OPENAI_API_KEY` pour
`provider: "openai"`). Choisis un modele qui utilise l'endpoint
`/chat/completions` (ex: `deepseek-v4-flash`) — les modeles GPT-5.x
d'OpenCode passent par `/responses` et ne sont pas supportes par ce client.

Si un de ces binaires est absent au moment de l'execution, le wrapper
correspondant leve une erreur explicite (`ToolExecutionError` /
`LlmError`) plutot qu'une trace Python brute — c'est le fallback prevu.

## Configuration d'un engagement

```bash
cp config/engagement.example.yaml config/engagement.yaml
```

Puis edite `scope.allowed_targets` avec les cibles reellement autorisees
par l'ordre de mission — **ne commite jamais ce fichier avec de vraies
cibles client**. Le scope y reste non-negociable quel que soit le profil
d'agressivite choisi au moment du scan.

## Utilisation

```bash
# 1. Scan + parsing + correlation + scoring (+ fuzzing si le profil l'autorise)
recon-copilot --config config/engagement.yaml scan \
    --target 10.0.0.5 --analyst "ton-nom" --profile standard \
    --comment "raison du choix de profil" --criticality high --fuzz

# 2. Revue interactive -- OBLIGATOIRE avant tout rapport
recon-copilot --config config/engagement.yaml review --analyst "ton-nom"

# 3. Rapport (uniquement les findings accepted/edited)
recon-copilot --config config/engagement.yaml report \
    --output ./rapport --formats md,docx,pdf --langs fr,en
```

Chaque etape peut etre relancee independamment (ex: rescanner une
nouvelle cible avant de tout revoir d'un coup).

## Tests

```bash
python -m pytest -v
```

Tu dois voir `270 passed`. Aucun test ne requiert Nmap/Nuclei/ffuf/Ollama
reels — tout est mocke au niveau `asyncio.create_subprocess_exec` ou via
un `LlmClient` de test (`FakeLlmClient`).

### ⚠️ Ce qui a ete valide avec de vrais outils, et ce qui ne l'a pas ete

Pendant le developpement, chaque module a ete verifie au moins une fois
avec de vrais outils externes en plus des tests unitaires mockes,
**sauf Nuclei et Ollama, absents du bac a sable de developpement** :

| Composant | Valide avec le vrai outil ? |
|---|---|
| `scanner` (Nmap) | ✅ vrai scan sur `127.0.0.1`, XML reel parse |
| `scanner` (Nuclei) | ❌ binaire indisponible en dev — valide uniquement par les tests mockes + fixture JSONL realiste |
| `parser` | ✅ vrai XML Nmap (bug `<extraports>` trouve et corrige, voir plus bas) |
| `fuzzing` (ffuf) | ✅ vrai `ffuf` contre un serveur HTTP local avec une anomalie deliberee — correctement detectee et triee |
| `correlation` / `fuzzing` (Ollama) | ❌ Ollama indisponible en dev — un serveur HTTP local imitant l'API reelle d'Ollama (`/api/generate`) a ete utilise pour exercer le vrai `OllamaClient` (httpx), avec des reponses scriptees |
| `review` CLI | ✅ session interactive reelle (entrees pipees), verifie en base |
| `report` (DOCX/PDF) | ✅ genere puis converti/rendu en images (LibreOffice + pdftoppm) pour verification visuelle |
| Pipeline complet via `recon-copilot scan/review/report` | ✅ execute de bout en bout avec les stands-in ci-dessus |

**Avant ta premiere vraie utilisation** : installe Nuclei et Ollama, puis
relance au moins un `recon-copilot scan --fuzz` complet sur une cible de
test pour confirmer que tout fonctionne avec les vrais services — les
stands-in utilises ici imitent le format des reponses mais ne remplacent
pas un vrai test avec Nuclei/Ollama installes.

### Bugs reels trouves pendant les tests manuels (tous corriges)

1. **Parser Nmap — ports groupes ignores.** Un scan reel sur `127.0.0.1`
   remontait 0 port alors que 100 avaient ete scannes. Nmap groupe les
   ports partageant le meme etat dans `<extraports state="closed"
   count="100"/>` plutot que de lister chaque `<port>` individuellement
   — c'est le cas le PLUS frequent en engagement reel (hote filtre).
   Corrige : `ParsedHost.extraports` (table `parsed_extraports`).
2. **Fuzzing — faux positifs sur baseline quasi instantanee.** La
   detection d'anomalie par temps de reponse explosait le ratio
   (division par un temps proche de zero) des qu'une baseline repondait
   tres vite, generant des anomalies sur des reponses parfaitement
   normales. Corrige avec un plancher (`min_baseline_time_ms`) sous
   lequel le critere temporel est ignore.
3. **Rapport PDF — curseur fpdf2 non reinitialise.** `multi_cell()` dans
   la version de fpdf2 utilisee laisse le curseur pres du bord droit
   plutot que de revenir a la marge gauche, faisant planter l'appel
   suivant sur les lignes longues. Corrige avec `new_x="LMARGIN",
   new_y="NEXT"` explicite sur chaque appel.
4. **Fuzzing — requete baseline envoyee avant verification du scope.**
   Dans une premiere version, `run_fuzz()` recuperait la baseline HTTP
   AVANT le controle de scope (qui n'intervenait qu'au moment de lancer
   ffuf) — une vraie requete reseau aurait donc pu partir vers une cible
   hors scope. Corrige : `scope_guard.enforce()` est maintenant le tout
   premier appel de `run_fuzz()`, avant toute activite reseau ou appel LLM.

## Limites connues et perimetre volontairement laisse de cote

- **Table CVE/CWE/MITRE statique tres reduite** (`correlation/knowledge_base.py`)
  — quelques entrees representatives, pas une base exhaustive. A enrichir
  avec les templates Nuclei et services reellement rencontres en
  engagement. C'est deliberement un point de depart, pas un produit fini
  (le cahier des charges demande explicitement une table statique
  embarquee dans le prompt, pas un flux CVE en direct ni du RAG).
- **Pas de traduction automatique du contenu dynamique.** Le rapport
  bilingue traduit les libelles structurels (titres de section, en-tetes)
  mais pas le texte genere par le LLM (titres/descriptions de findings) —
  qui reste dans la langue ou il a ete produit. Une vraie traduction
  demanderait soit un appel LLM supplementaire par langue (cout, risque
  de derive), soit une bibliotheque de traduction externe ; aucun des
  deux n'a ete ajoute sans que tu valides le compromis.
- **`review/` est une CLI, pas une interface web.** Voir plus haut —
  toute la logique est reutilisable telle quelle par une future interface
  web si besoin.
- **Le pipeline traite une cible a la fois** (`run_pipeline()` prend un
  seul `target`). Scanner plusieurs cibles = plusieurs appels, ce qui
  reste coherent avec l'approche manuelle a faible agressivite plutot
  qu'un balayage automatique de plage large.

## Prochaines etapes possibles

- Enrichir `knowledge_base.py` avec les templates Nuclei reellement
  utilises dans tes engagements.
- Ajouter une commande CLI `recon-copilot scan-range` si le besoin de
  traiter plusieurs cibles d'un coup se confirme.
- Explorer une interface web legere pour `review/` si la CLI devient
  limitante en usage reel.
