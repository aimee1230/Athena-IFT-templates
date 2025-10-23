## Athena-templates
Filling different IFT templates using athena-database

### Setup
```bash
pip install -r requirements.txt
```

### Usage 
```bash
python3 cve.py --limit 10
python3 mitre.py
```
The --limit option controls how many records (e.g., CVEs) are fetched from the database.
Example: --limit 10 processes only 10 CVEs for faster testing.


### Project Structure
```bash
├── cve.py                       # Fills CVE templates from PostgreSQL
├── mitre.py                     # Fills ATT&CK templates from athena-database
├── cwe.py                       # Fills CWE templates using athena-database
├── capec.py                     # Fills CAPEC templates using athena-database
├── query_postgre.py             # PostgreSQL helper
├── query_neo4j.py               # Neo4j helper
├── templates/                   # JSONL template files
├── filled_templates/            # Output files (auto-created)
└── requirements.txt
```

#### Notes
PostgreSQL helper (query_postgre.py): runs SQL queries to fetch structured data (e.g., CVE details).
Neo4j helper (query_neo4j.py): runs Cypher queries to extract relationships (e.g., subtechniques, related tactics).
Outputs are saved automatically in the filled_templates/ folder.

