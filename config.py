import os

class Config:
    SECRET_KEY = 'd855496646e88b7c12e0a80135bef652'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    BASE_UPLOAD_FOLDER = os.path.join('static', 'uploads')
    EMPRESA_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, 'empresas')
    USER_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, 'users')
    CV_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, 'cv')

    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB limite upload
    # Configurações SMTP opcionais para o envio de e-mails de redefinição de palavra-passe. Se não forem definidas,
    # A aplicação irá apresentar mensagens de e-mail na consola (em ambiente de desenvolvimento).
    SMTP_HOST = None
    SMTP_PORT = 587
    SMTP_USER = None
    SMTP_PASS = None
    SMTP_FROM = None
