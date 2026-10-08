import sqlite3

def add_columns():
    db_path = "./aegis_node.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    columns_to_add = [
        ("llm_mode", "VARCHAR(32) NOT NULL DEFAULT 'auto'"),
        ("requested_provider", "VARCHAR(64) NOT NULL DEFAULT ''"),
        ("requested_model", "VARCHAR(128)"),
        ("initial_provider", "VARCHAR(64) NOT NULL DEFAULT ''"),
        ("final_provider", "VARCHAR(64) NOT NULL DEFAULT ''"),
        ("fallback_used", "BOOLEAN NOT NULL DEFAULT 0"),
        ("fallback_reason", "TEXT"),
        ("provider_attempts_json", "TEXT NOT NULL DEFAULT '[]'")
    ]

    for col_name, col_type in columns_to_add:
        try:
            cursor.execute(f"ALTER TABLE llm_analyses ADD COLUMN {col_name} {col_type}")
            print(f"Added column {col_name}")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print(f"Column {col_name} already exists. Skipping.")
            else:
                print(f"Error adding column {col_name}: {e}")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    add_columns()
