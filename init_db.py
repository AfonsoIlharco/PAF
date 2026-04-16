
from app import app
from db import db

# Executar: python init_db.py
with app.app_context():
    # opcional: apagar todas as tabelas antes de criar
    db.drop_all()
    db.create_all()
    print("Base de dados recriada (drop_all + create_all).")