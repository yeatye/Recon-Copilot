# Rapport de test d'intrusion -- Juice_Shop

**Engagement** : Juice_Shop  
**Genere le** : 2026-09-11T15:17:30.455484+00:00

## Resume executif

Cet engagement a permis d'identifier 8 constatation(s) validee(s) par l'analyste : 2 moyenne, 4 faible, 2 information. Les constatations de severite critique et elevee doivent faire l'objet d'une remediation prioritaire (voir section dediee).

## Perimetre de l'engagement

**Cibles autorisees** : 127.0.0.1

## Methodologie

Ce test d'intrusion a ete conduit selon une methodologie manuelle a faible agressivite, assistee par des outils automatises (Nmap, Nuclei, ffuf) dont les resultats ont ete correles, notes et revus individuellement par un analyste humain avant integration a ce rapport. Aucune constatation n'est incluse sans validation explicite de l'analyste.

## Constatations techniques

### [Moyenne] Endpoint Prometheus /metrics accessible sans authentification

- **Cible** : 127.0.0.1
- **Severite** : Moyenne
- **Score de risque** : 5.48/10 (medium)
- **CWE** : CWE-200
- **MITRE ATT&CK** : T1592

Une page de metriques Prometheus est accessible publiquement sur http://127.0.0.1:3000/metrics. L'exposition de metriques d'observabilite revele des informations internes (versions, chemins, compteurs d'erreurs, parfois noms d'hotes et variables d'environnement) utiles pour cartographier l'application avant exploitation.

**Remediation** : Restreindre /metrics aux reseaux d'administration (filtrage IP, mTLS ou reverse-proxy avec authentification) et supprimer cet endpoint du meme port que l'application utilisateur.

**Commande utilisee** : `nuclei -target 127.0.0.1:3000 -severity info,low,medium,high,critical -jsonl -silent -etags dos,intrusive`

> **Preuve (extrait source)** : `"template-id":"prometheus-metrics"`

### [Moyenne] Politique CORS permissive (origine generique autorisee)

- **Cible** : 127.0.0.1
- **Severite** : Moyenne
- **Score de risque** : 5.48/10 (medium)
- **CWE** : CWE-942

La reponse HTTP du service sur le port 3000 renvoie un en-tete Access-Control-Allow-Origin avec la valeur joker, y compris sur les reponses OPTIONS listant les methodes autorisees. Une politique CORS ouverte permet a n'importe quel site de lire les reponses de l'application au nom d'un utilisateur authentifie si des cookies ou identifiants sont envoyes.

**Remediation** : Remplacer la valeur joker par une liste blanche d'origines de confiance, valider l'en-tete Origin cote serveur et n'autoriser les identifiants (Access-Control-Allow-Credentials) qu'avec des origines explicitement approuvees.

**Commande utilisee** : `nmap -T3 -Pn -sV -p 3000 -oX - 127.0.0.1`

> **Preuve (extrait source)** : `Access-Control-Allow-Origin`

### [Faible] Documentation Swagger / OpenAPI publique

- **Cible** : 127.0.0.1
- **Severite** : Faible
- **Score de risque** : 4.52/10 (medium)
- **CWE** : CWE-200
- **MITRE ATT&CK** : T1592

Un fichier de specification Swagger est accessible publiquement (http://127.0.0.1:3000/api-docs/swagger.yaml). Il expose l'inventaire complet des routes, parametres et schemas de l'API, ce qui facilite la decouverte d'endpoints non documentes ou mal proteges et la construction de requetes ciblees.

**Remediation** : Desactiver l'exposition publique de la specification OpenAPI en production, ou la proteger par authentification et la limiter aux environnements de developpement.

**Commande utilisee** : `nuclei -target 127.0.0.1:3000 -severity info,low,medium,high,critical -jsonl -silent -etags dos,intrusive`

> **Preuve (extrait source)** : `"matched-at":"http://127.0.0.1:3000/api-docs/swagger.yaml"`

### [Faible] robots.txt revelant le repertoire /ftp

- **Cible** : 127.0.0.1
- **Severite** : Faible
- **Score de risque** : 4.16/10 (medium)
- **CWE** : CWE-200
- **MITRE ATT&CK** : T1083

Le fichier robots.txt est present et son contenu extrait par Nuclei expose une entree disallow pointant vers /ftp. Ce type de directive indique aux robots d'indexation un chemin que le proprietaire souhaite masquer, mais ne protege en rien l'acces direct : cela guide un attaquant vers un repertoire potentiellement sensible.

**Remediation** : Ne pas utiliser robots.txt comme mecanisme de dissimulation. Supprimer le contenu du repertoire /ftp s'il ne doit pas etre servi, ou le proteger par authentification et controle d'acces cote serveur.

**Commande utilisee** : `nuclei -target 127.0.0.1:3000 -severity info,low,medium,high,critical -jsonl -silent -etags dos,intrusive`

> **Preuve (extrait source)** : `"extracted-results":["/ftp"]`

### [Faible] HSTS non active sur le service web

- **Cible** : 127.0.0.1
- **Severite** : Faible
- **Score de risque** : 4.52/10 (medium)
- **CWE** : CWE-319

L'analyse Nuclei indique l'absence de l'en-tete Strict-Transport-Security sur http://127.0.0.1:3000. Sans HSTS, un utilisateur peut etre redirige vers une connexion non chiffree lors d'une attaque de type downgrade ou interception, ce qui expose les cookies de session.

**Remediation** : Activer HTTPS avec un certificat valide et renvoyer l'en-tete Strict-Transport-Security avec un max-age suffisant (ex. 31536000) et includeSubDomains.

**Commande utilisee** : `nuclei -target 127.0.0.1:3000 -severity info,low,medium,high,critical -jsonl -silent -etags dos,intrusive`

> **Preuve (extrait source)** : `"matcher-name":"strict-transport-security"`

### [Faible] En-tete HTTP obsolete Feature-Policy encore utilise

- **Cible** : 127.0.0.1
- **Severite** : Faible
- **Score de risque** : 3.86/10 (medium)
- **CWE** : CWE-477

L'en-tete de reponse Feature-Policy est encore emis (valeur 'payment self'). Cet en-tete est deprecie et remplace par Permissions-Policy : selon les navigateurs, la restriction de fonctionnalites peut devenir inoperante, reduisant la defense en profondeur contre l'abus de fonctionnalites navigateur.

**Remediation** : Migrer vers Permissions-Policy (ex. permissions-policy: payment=(self)) et supprimer l'en-tete Feature-Policy devenu obsolete.

**Commande utilisee** : `nuclei -target 127.0.0.1:3000 -severity info,low,medium,high,critical -jsonl -silent -etags dos,intrusive`

> **Preuve (extrait source)** : `"extracted-results":["payment 'self'"]`

### [Information] En-tetes de securite HTTP absents

- **Cible** : 127.0.0.1
- **Severite** : Information
- **Score de risque** : 2.3/10 (low)
- **CWE** : CWE-693

Nuclei signale l'absence de plusieurs en-tetes de securite sur http://127.0.0.1:3000, notamment la Content-Security-Policy. L'absence de CSP augmente l'impact d'une eventuelle injection de contenu (XSS) puisqu'aucune restriction de sources de scripts n'est imposee par le navigateur.

**Remediation** : Ajouter une Content-Security-Policy restrictive (pas de 'unsafe-inline', sources de scripts limitees), ainsi que les autres en-tetes manquants : Referrer-Policy, Permissions-Policy, X-Permitted-Cross-Domain-Policies et COOP/COEP/CORP.

**Commande utilisee** : `nuclei -target 127.0.0.1:3000 -severity info,low,medium,high,critical -jsonl -silent -etags dos,intrusive`

> **Preuve (extrait source)** : `"matcher-name":"content-security-policy"`

### [Information] Fichier security.txt exposant un contact interne

- **Cible** : 127.0.0.1
- **Severite** : Information
- **Score de risque** : 2.3/10 (low)
- **CWE** : CWE-200
- **MITRE ATT&CK** : T1598

Un fichier .well-known/security.txt est publiquement accessible et contient une adresse de contact (mailto:donotreply@owasp-juice.shop). Cette information, bien que faiblement sensible, confirme l'organisation proprietaire de la cible et peut alimenter des campagnes de phishing ou d'ingenierie sociale.

**Remediation** : Verifier que l'adresse de contact publiee est une boite de service dediee et non une adresse exploitable, et limiter l'exposition de ce fichier aux environnements de production uniquement.

**Commande utilisee** : `nuclei -target 127.0.0.1:3000 -severity info,low,medium,high,critical -jsonl -silent -etags dos,intrusive`

> **Preuve (extrait source)** : `"extracted-results":[" mailto:donotreply@owasp-juice.shop"]`

## Remediation prioritaire

Aucune constatation retenue pour ce rapport.