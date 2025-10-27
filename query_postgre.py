#!/usr/bin/env python3
"""
PostgreSQL helper module to run SQL queries and return results.
"""

import os
import psycopg2
import psycopg2.extras

# Database configuration from environment variables
DB_CONFIG = {
    'host': os.getenv('POSTGRES_HOST', '127.0.0,0'),
    'database': os.getenv('POSTGRES_DB', 'threats'),
    'user': os.getenv('POSTGRES_USER', 'postgres'),
    'password': os.getenv('POSTGRES_PASSWORD', 'gSC7LO'),
    'port': int(os.getenv('POSTGRES_PORT', 5432))
}


def run_query(query, return_dict=False):
    """
    Run a SQL query and return results.
    
    Args:
        query (str): The SQL query to execute.
        return_dict (bool): If True, return rows as list of dictionaries (column_name: value).
                            If False, return rows as list of tuples.
                            
    Returns:
        list: Query results.
    """
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        # Use DictCursor if return_dict=True
        cursor_factory = psycopg2.extras.DictCursor if return_dict else None
        with conn.cursor(cursor_factory=cursor_factory) as cursor:
            cursor.execute(query)
            
            if query.strip().upper().startswith('SELECT'):
                results = cursor.fetchall()
                if return_dict:
                    # Convert DictRows to normal dicts
                    results = [dict(row) for row in results]
                return results
            else:
                conn.commit()
                return {'rows_affected': cursor.rowcount}
    except Exception as e:
        print(f"Error executing query: {e}")
        return []  # Return empty list on error
    finally:
        if conn:
            conn.close()
