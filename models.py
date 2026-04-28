from db import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import Boolean
import pyotp
import json

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nome = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # 'user' or 'empresa'
    foto_perfil = db.Column(db.String, nullable=True)
    cv_path = db.Column(db.String, nullable=True)
    # Two-factor auth (TOTP) fields
    two_factor_enabled = db.Column(db.Boolean, default=False, nullable=False)
    two_factor_secret = db.Column(db.String(64), nullable=True)
    # Backup single-use codes stored as JSON array of hashed codes
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
        Generate and store a new base32 secret for TOTP and return it.
        """
        # use pyotp to create a random base32 secret
        secret = pyotp.random_base32()
        self.two_factor_secret = secret
        return secret

    def verify_2fa_token(self, token):
        """
        Verify a TOTP token against the stored secret.

        Returns True if valid, False otherwise.
        """
        if not self.two_factor_secret:
            return False
        totp = pyotp.TOTP(self.two_factor_secret)
        # allow small window for clock skew
        return bool(totp.verify(token, valid_window=1))

    def generate_backup_codes(self, n=8):
        """
        Generate n one-time backup codes, store their hashed versions in the DB and
        return the plaintext list so it can be shown once to the user.
        """
        codes = []
        hashed = []
        for _ in range(n):
            # create a short human-friendly code
            c = pyotp.random_base32()[:10]
            codes.append(c)
            hashed.append(generate_password_hash(c))
        self.backup_codes = json.dumps(hashed)
        return codes

    def verify_and_consume_backup_code(self, code):
        """
        Verify a backup code; if valid, remove it from stored hashed list and return True.
        Otherwise return False.
        """
        if not self.backup_codes:
            return False
        try:
            hashed_list = json.loads(self.backup_codes)
        except Exception:
            return False
        for i, h in enumerate(hashed_list):
            if check_password_hash(h, code):
                # consume this code
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
    titulo = db.Column(db.String, nullable=False)
    descricao = db.Column(db.String)
    hora_entrada = db.Column(db.Time, nullable=True)
    hora_saida = db.Column(db.Time, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "empresa_id": self.empresa_id,
            "titulo": self.titulo,
            "descricao": self.descricao,
            # convert times to string if needed:
            "hora_entrada": self.hora_entrada.strftime('%H:%M') if self.hora_entrada else None,
            "hora_saida": self.hora_saida.strftime('%H:%M') if self.hora_saida else None,
        }

    empresa = db.relationship('Empresa', back_populates='anuncios')
    # Relationship: candidaturas recebidas por este anuncio
    candidaturas = db.relationship('Candidatura', back_populates='anuncio', cascade='all, delete-orphan')

    def __repr__(self):
        return f"Anuncio(id={self.id}, titulo='{self.titulo}', empresa_id={self.empresa_id})"

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

    # Uniqueness constraint
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
