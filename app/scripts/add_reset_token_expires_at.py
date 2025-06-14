import sqlite3
import os

# Caminho absoluto para o banco de dados
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'db.sqlite3')

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE users ADD COLUMN reset_token_expires_at DATETIME;")
    print("Coluna 'reset_token_expires_at' adicionada com sucesso.")
except sqlite3.OperationalError as e:
    if 'duplicate column name' in str(e) or 'already exists' in str(e):
        print("Coluna 'reset_token_expires_at' já existe.")
    else:
        print(f"Erro ao adicionar coluna: {e}")

conn.commit()
conn.close()
