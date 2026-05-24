import json
from datetime import datetime

import pyotp
from werkzeug.security import generate_password_hash, check_password_hash

from db import db


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nome = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # 'user' or 'empresa'
    foto_perfil = db.Column(db.String, nullable=True)
    cv_path = db.Column(db.String, nullable=True)
    # Campos de autenticação de dois fatores (TOTP)
    two_factor_enabled = db.Column(db.Boolean, default=False, nullable=False)
    two_factor_secret = db.Column(db.String(64), nullable=True)
    # Cópia de segurança de códigos de uso único armazenados como uma matriz JSON de códigos com hash
    backup_codes = db.Column(db.Text, nullable=True)

    empresa = db.relationship('Empresa', back_populates='user', uselist=False)
    # Relationship: candidaturas feitas por este user
    candidaturas = db.relationship('Candidatura', back_populates='user', cascade='all, delete-orphan')

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def generate_2fa_secret(self):
        """
        Gerar e armazenar um novo segredo em base32 para o TOTP e devolvê-lo.
        """
        # Utilizar o pyotp para criar um segredo aleatório em base32
        secret = pyotp.random_base32()
        self.two_factor_secret = secret
        return secret

    def verify_2fa_token(self, token):
        """
        Verifica um token TOTP em relação ao segredo armazenado.

        Retorna True se for válido, False caso contrário.
        """
        if not self.two_factor_secret:
            return False
        totp = pyotp.TOTP(self.two_factor_secret)
        # Prever uma pequena margem para o desfasamento do relógio
        return bool(totp.verify(token, valid_window=1))

    def generate_backup_codes(self, n=8):
        """
        Gerar n códigos de backup de uso único, armazenar as suas versões com hash na base de dados e
        devolver a lista em texto simples para que possa ser apresentada uma vez ao utilizador.
        """
        codes = []
        hashed = []
        for _ in range(n):
            # Criar um código curto e de fácil compreensão
            c = pyotp.random_base32()[:10]
            codes.append(c)
            hashed.append(generate_password_hash(c))
        self.backup_codes = json.dumps(hashed)
        return codes

    def verify_and_consume_backup_code(self, code):
        """
        Verifica um código de reserva; se for válido, remove-o da lista de hash armazenada e devolve True.
        Caso contrário, devolve False.
        """
        if not self.backup_codes:
            return False
        try:
            hashed_list = json.loads(self.backup_codes)
        except Exception:
            return False
        for i, h in enumerate(hashed_list):
            if check_password_hash(h, code):
                # Execute este código
                hashed_list.pop(i)
                self.backup_codes = json.dumps(hashed_list) if hashed_list else None
                return True
        return False

    def __repr__(self):
        return f"User(id={self.id}, nome='{self.nome}', email='{self.email}')"

class Empresa(db.Model):
    __tablename__ = 'empresa'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    nome = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    website = db.Column(db.String, nullable=True)
    morada = db.Column(db.String, nullable=False)
    telefone = db.Column(db.String, nullable=False)
    descricao = db.Column(db.String, nullable=False)
    nif = db.Column(db.String(32), nullable=True)
    logo = db.Column(db.String, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "nome": self.nome,
            "email": self.email,
            "morada": self.morada,
            "telefone": self.telefone
        }

    user = db.relationship('User', back_populates='empresa')
    anuncios = db.relationship('Anuncio', back_populates='empresa', cascade='all, delete-orphan')

class Anuncio(db.Model):
    __tablename__ = 'anuncio'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    empresa_id = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)

    # New fields
    tipo = db.Column(db.String(32), nullable=False)        # 'Curricular', 'Extracurricular', 'Profissional'
    categoria = db.Column(db.String(128), nullable=False)  # e.g. 'Informática: Sistemas'
    local_trabalho = db.Column(db.String(255), nullable=True)

    descricao = db.Column(db.String)
    hora_entrada = db.Column(db.Time, nullable=True)
    hora_saida = db.Column(db.Time, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "empresa_id": self.empresa_id,
            "tipo": self.tipo,
            "categoria": self.categoria,
            "local_trabalho": self.local_trabalho,
            "descricao": self.descricao,
            "hora_entrada": self.hora_entrada.strftime('%H:%M') if self.hora_entrada else None,
            "hora_saida": self.hora_saida.strftime('%H:%M') if self.hora_saida else None,
        }

    def __repr__(self):
        return f"Anuncio(id={self.id}, categoria='{self.categoria}', tipo='{self.tipo}', empresa_id={self.empresa_id})"

class Candidatura(db.Model):
    """
    Representa a candidatura de um User a um Anuncio.
    Garante unicidade (user_id, anuncio_id) para impedir candidaturas duplicadas.
    """
    __tablename__ = 'candidatura'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    anuncio_id = db.Column(db.Integer, db.ForeignKey('anuncio.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    mensagem = db.Column(db.String, nullable=True)

    # Restrição de exclusividade
    __table_args__ = (db.UniqueConstraint('user_id', 'anuncio_id', name='uq_user_ad'),)

    user = db.relationship('User', back_populates='candidaturas')
    anuncio = db.relationship('Anuncio', back_populates='candidaturas')

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'anuncio_id': self.anuncio_id,
            'created_at': self.created_at.isoformat(),
            'mensagem': self.mensagem
        }
