#!/usr/bin/env python3
"""
Neo4j helper module to run Cypher queries and return results.
"""

import os
import requests
import base64

# Neo4j configuration from environment variables (can be overridden)
NEO4J_URL = os.getenv('NEO4J_URL', 'http://127.0.0.1')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD', 'yx1c')

NEO4J_ENDPOINT = f"{NEO4J_URL}/db/neo4j/tx/commit"

# Create base64 encoded auth header
auth_string = f"{NEO4J_USER}:{NEO4J_PASSWORD}"
auth_b64 = base64.b64encode(auth_string.encode('ascii')).decode('ascii')

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Authorization": f"Basic {auth_b64}"
}


def run_query(query):
    """
    Run a Cypher query and return results as a list of rows.
    Each row is a list of values corresponding to the RETURN clause.
    """
    try:
        payload = {'statements': [{'statement': query}]}
        response = requests.post(NEO4J_ENDPOINT, headers=HEADERS, json=payload, timeout=60)
        response.raise_for_status()
        result = response.json()

        if 'errors' in result and result['errors']:
            raise Exception(f"Neo4j returned errors: {result['errors']}")

        output = []
        for res in result.get('results', []):
            for row in res.get('data', []):
                if 'row' in row:
                    output.append(row['row'])
        return output

    except Exception as e:
        print(f"Error running query: {e}")
        return []


def run_query_dict(query, keys=None):
    """
    Run a Cypher query and return results as a list of dictionaries.
    Optional `keys` argument defines dictionary keys corresponding to RETURN columns.
    """
    rows = run_query(query)
    if not rows:
        return []

    if keys is None:
        keys = [f"col{i+1}" for i in range(len(rows[0]))]

    return [dict(zip(keys, row)) for row in rows]
