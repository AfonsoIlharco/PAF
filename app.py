"""
app.py

Aplicação web em Flask para uma pequena plataforma de anúncios para estágios.

Este modulo define a aplicação Flask, helper utilities (verificações de upload de ficheiro, decorators de autenticação),
e handlers de rota para registro de users, empresas, login/logout, edição de
perfil, criar/apagar anúncios, e ver informação relacionada á empresa

A configuração é importada do ficheiro config, através do objeto Config. Modelos da BD são importados de 'models.py'
e a instance de SQLAlchemy através do ficheiro `db.py`. Os diretórios de upload são garantidos na inicialização.

Notas:
- Funções de rota dependem da `session` no Flask para gerir utilizadores com sessão iniciada.
- As páginas devem estar localizados no diretório `templates/` (por exemplo, 'templates/registar.html').
"""

import os
from functools import wraps
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.utils import secure_filename

from db import db
from config import Config
from sqlalchemy.exc import IntegrityError

from uuid import uuid4
import pathlib
import pyotp
import qrcode
import io
import base64
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from uuid import uuid4 as _uuid4

app = Flask(__name__)
app.config.from_object(Config)

# Registo básico para auditoria de eventos de recuperação
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Limitador de taxa (armazenamento em memória para desenvolvimento). Ajustar os limites para produção.
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
limiter.init_app(app)

# Serializador para o cookie “remember-device”
_serializer = URLSafeTimedSerializer(app.secret_key)

# Inicializar SQLAlchemy com a aplicação Flask
db.init_app(app)

# Importar modelos após a app e db serem inicializadas para evitar
# o erro SQLAlchemy "not registered with this 'SQLAlchemy' instance"
from models import User, Empresa, Anuncio, Candidatura


# Um auxiliar simples para o envio de e-mails. Utiliza as definições SMTP do ficheiro Config, quando estas forem fornecidas,
# caso contrário, recorre à exibição da mensagem na consola (em ambiente de desenvolvimento).
def send_email(to_address: str, subject: str, body: str) -> bool:
    host = app.config.get('SMTP_HOST')
    from_addr = app.config.get('SMTP_FROM') or app.config.get('SMTP_USER') or 'noreply@example.com'
    # Se for fornecido conteúdo HTML, este é passado como uma tupla (texto, html) em `body`.
    text_body = None
    html_body = None
    if isinstance(body, tuple) and len(body) == 2:
        text_body, html_body = body
    else:
        text_body = str(body)

    if host:
        try:
            port = app.config.get('SMTP_PORT', 587)
            user = app.config.get('SMTP_USER')
            password = app.config.get('SMTP_PASS')

            # Criar uma mensagem multiparte com texto e uma parte HTML opcional
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = from_addr
            msg['To'] = to_address

            part1 = MIMEText(text_body or '', 'plain', 'utf-8')
            msg.attach(part1)
            if html_body:
                part2 = MIMEText(html_body, 'html', 'utf-8')
                msg.attach(part2)

            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls()
            if user and password:
                server.login(user, password)
            server.sendmail(from_addr, [to_address], msg.as_string())
            server.quit()
            return True
        except Exception as e:
            # Falha no registo
            logger.exception('send_email error')
            return False

    # Solução alternativa de desenvolvimento: enviar o e-mail para a saída padrão do processo em execução
    print('----- EMAIL (dev) -----')
    print('To:', to_address)
    print('Subject:', subject)
    if html_body:
        print('(text)')
        print(text_body)
        print('(html)')
        print(html_body)
    else:
        print(text_body)
    print('----- END EMAIL -----')
    return True

# Extensões de ficheiro permitidas para upload (logo, CVs, fotos de perfil, etc.)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

# Assegurar que as diretorias de upload configuradas no Config existem. Nós usamos get(..., default)
# para que a app funcione na mesma se uma definição de um arquivo estiver em falta.
os.makedirs(app.config.get('EMPRESA_FOLDER', os.path.join('static', 'uploads', 'empresas')), exist_ok=True)
os.makedirs(app.config.get('USER_FOLDER', os.path.join('static', 'uploads', 'users')), exist_ok=True)
os.makedirs(app.config.get('CV_FOLDER', os.path.join('static', 'uploads', 'cv')), exist_ok=True)


def allowed_file(filename):
    """
    Verificar se o filename dado tem uma extensão permitida.

    Args:
        filename (str): O filename a verificar.
    Devolve:
        bool: True se o filename conter uma extensão e estiver nas ALLOWED_EXTENSIONS.
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _remove_file_if_exists(rel_path):
    """
    Remover um ficheiro referenciado por um caminho relativo armazenado na base de dados (por exemplo, «uploads/empresas/x.png»).
    Esta função resolve o caminho de forma segura dentro do diretório «static» e remove o ficheiro
    se este existir. Ignora os erros e devolve True se o ficheiro tiver sido removido; caso contrário, devolve False.
    """
    if not rel_path:
        return False
    # normalizar e prevenir path traversal
    # assumir caminhos guardados são relativos ao arquivo 'static'
    try:
        base = pathlib.Path(app.static_folder).resolve()
        target = (base / rel_path).resolve()
        if base in target.parents or target == base:
            if target.exists() and target.is_file():
                target.unlink()
                return True
    except Exception:
        pass
    return False


def login_required(f):
    """
    Decorator para proteger rotas que requerem um utilizador com sessão iniciada.

    Se não existir um `user_id` na sessão Flask, redireciona á rota 'login'.
    Caso contrário, chama a função wrapped.

    Uso:
        @app.route('/protected')
        @login_required
        def protected(): ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    """
    Fábrica de Decorators para proteger rotas baseadas no role de um utilizador.

    Args:
        roles (str): Roles permitidos (e.g. 'empresa', 'user').

    Comportamento:
        - Se não estiver com sessão iniciada, redireciona para o 'login'.
        - Se o role do utilizador com sessão iniciada não estiver em 'roles', Devolve HTTP 403 (Forbidden).

    Usage:
        @app.route('/empresa-only')
        @role_required('empresa')
        def only_for_empresa(): ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get('user_id'):
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                return "Forbidden", 403
            return f(*args, **kwargs)
        return decorated
    return decorator


@app.route('/', methods=['GET', 'POST'])
def registar():
    """
    Rota de registo de utilizador.

    GET:
        - Renderizar o template de registo.

    POST:
        - Cria um 'User' com os campos 'form':
            - nomeForm: nome do utilizador (obrigatório)
            - emailForm: email (obrigatório, tem de ser único)
            - passwordForm: password (obrigatório)
            - roleForm: role (O valor padrão é 'user'; se for 'empresa' vai redirecionar para o registo de empresa)

        - Se bem-sucedido:
            - Se role == 'empresa' redirecionar para '/registar_empresa/<user_id>'
            - Caso contrário, redirecionar para '/home'

    Template:
        - 'registar.html' utilizado para ambos GET e renderização de erros.
    """
    db.session.query(User).all()
    user_id = session.get('user_id')
    # Load current_user from DB if logged in (used to customize templates)
    db.session.get(User, user_id) if user_id else None

    # Allow registration POST even if someone is logged in (useful for admin or multi-account flows).
    # Previously this checked `and not user_id` which blocked account creation when a session existed.
    if request.method == 'POST':
        nome = (request.form.get('nomeForm') or '').strip()
        email = request.form.get('emailForm')
        password = request.form.get('passwordForm')
        role = request.form.get('roleForm') or 'user'
        # Basic validation: all fields required
        if not nome or not email or not password or not role:
            return render_template('registar.html', error="Preencha todos os campos!")
        # Prevent duplicate emails
        if db.session.query(User).filter_by(email=email).first():
            return render_template('registar.html', error="Email já registado!")
        novo_user = User(nome=nome, email=email, role=role)
        novo_user.set_password(password)
        db.session.add(novo_user)
        db.session.commit()
        # If the user chooses the 'empresa' role, redirect to company registration bound to this user
        if role == 'empresa':
            return redirect(url_for('registar_empresa', user_id=novo_user.id))
        # For non-company users, redirect to the home dashboard
        return redirect(url_for('home'))
    # Render registration form for GET or when user_id exists
    return render_template('registar.html')


@app.route('/registar_empresa/<int:user_id>', methods=['GET', 'POST'])
def registar_empresa(user_id):
    """
    Página de registo de empresa associada com um utilizador existente.

    Parâmetros de caminho:
        - user_id (int): O ID do user já-criado que se torna num dono de empresa.

    GET:
        - Renderizar o formulário 'registar_empresa.html' para recolher dados da empresa (nome, email, morada, telefone, descricao).

    POST:
        - Validar que o nome da empresa está presente.
        - Opcionalmente aceitar um upload de ficheiro 'logo' (verificado com allowed_file).
        - Guardar o logo carregado para a pasta configurada EMPRESA_FOLDER e gravar caminho relativo em `empresa.logo`.
        - Criar registo Empresa e dar commit, depois, redirecionar para '/dashboard'.

    Template:
        - 'registar_empresa.html'
    """
    user = db.session.get(User, user_id)
    if not user:
        return "User not found", 404

    if request.method == 'POST':
        nome_empresa = request.form.get('nome')
        email_empresa = request.form.get('email')
        morada = request.form.get('morada')
        telefone = request.form.get('telefone')
        descricao = request.form.get('descricao')
        nif = (request.form.get('nif') or '').strip()

        # Basic NIF validation: digits only, length 9
        nif_digits = ''.join(ch for ch in nif if ch.isdigit())
        if not nif_digits or len(nif_digits) != 9:
            return render_template('registar_empresa.html', user=user, error='NIF inválido. Deve conter 9 dígitos.')

        empresa = Empresa(
            user_id=user.id,
            nome=nome_empresa,
            email=email_empresa,
            morada=morada,
            telefone=telefone,
            descricao=descricao,
            nif=nif_digits
        )

        # Lidar com o carregamento opcional de logótipos (utilizar UUID para evitar conflitos)
        file = request.files.get('logo')
        if file and file.filename != '':
            # Verifique as extensões de ficheiro permitidas por motivos de segurança
            if allowed_file(file.filename):
                original = secure_filename(file.filename)
                name, ext = os.path.splitext(original)
                unique_name = f"{name}_{uuid4().hex}{ext}"
                # Utilizar a pasta configurada; caso contrário, utilizar a pasta padrão static/uploads/empresas
                upload_folder = app.config.get('EMPRESA_FOLDER', os.path.join('static', 'uploads', 'empresas'))
                filepath = os.path.join(upload_folder, unique_name)
                # Guarde o ficheiro no disco (diretório criado no arranque da aplicação)
                file.save(filepath)
                # Armazenar o caminho relativo (em relação à pasta estática), por exemplo, «uploads/empresas/xxxxx.png»
                rel = os.path.relpath(filepath, start=app.static_folder).replace('\\', '/')
                empresa.logo = rel
            else:
                # Recusar tipos de ficheiros inválidos e apresentar uma mensagem de erro no próprio formulário
                return render_template('registar_empresa.html', user=user, error='Tipo de ficheiro não permitido')

        db.session.add(empresa)
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('registar_empresa.html', user=user)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("6 per minute")
def login():
    """
    Rota Login.

    POST:
        Campos de formulário:
            - emailForm
            - passwordForm
        - Se credenciais condizerem, definir chaves de sessão:
            - 'user_id', 'nome', 'role'
          Se o utilizador for uma 'empresa', tenta anexar 'empresa_id' á sessão.
        - Redirecionar para '/home' se o login for bem-sucçedido.

    GET:
        - Renderiza 'login.html'
    """
    if request.method == 'POST':
        email = request.form.get('emailForm')
        password = request.form.get('passwordForm')

        # Pesquisar utilizador e verificar a palavra-passe
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            # Se o utilizador tiver a autenticação de dois fatores ativada, solicitar o TOTP antes de estabelecer a sessão completa
            # Verificar se existe um cookie de memorização do dispositivo: se estiver presente e for válido, ignorar a autenticação de dois fatores
            remember_cookie = request.cookies.get('remember_device')
            if getattr(user, 'two_factor_enabled', False):
                if remember_cookie:
                    try:
                        data = _serializer.loads(remember_cookie, max_age=60 * 60 * 24 * 30)
                        if isinstance(data, dict) and data.get('uid') == user.id:
                            # trusted device, complete login
                            session['user_id'] = user.id
                            session['nome'] = user.nome
                            session['role'] = user.role
                            if user.role == 'empresa':
                                empresa = db.session.query(Empresa).filter_by(user_id=user.id).first()
                                if empresa:
                                    session['empresa_id'] = empresa.id
                            return redirect(url_for('home'))
                    except (BadSignature, SignatureExpired):
                        # Cookie inválido ou expirado — ignorar e avançar para a autenticação de dois fatores
                        pass

                # Store pre-auth id and redirect to 2FA verification page
                session['pre_2fa_user_id'] = user.id
                return redirect(url_for('two_factor_verify'))

            # Caso contrário, conclua o início de sessão como anteriormente
            session['user_id'] = user.id
            session['nome'] = user.nome
            session['role'] = user.role
            # Se o utilizador for proprietário de uma empresa, inclua o ID da empresa na sessão por uma questão de comodidade
            if user.role == 'empresa':
                empresa = db.session.query(Empresa).filter_by(user_id=user.id).first()
                if empresa:
                    session['empresa_id'] = empresa.id
            return redirect(url_for('home'))
        # Em caso de falha na autenticação, atualizar a página de login com uma mensagem de erro
        return render_template('login.html', error="Email ou password incorretos!")
    return render_template('login.html')


@app.route('/2fa-verify', methods=['GET', 'POST'])
@limiter.limit("6 per minute")
def two_factor_verify():
    """
    Verify a TOTP code after password verification for users with 2FA enabled.
    The login handler sets `session['pre_2fa_user_id']` and this route finalizes the login.
    """
    pre_id = session.get('pre_2fa_user_id')
    if not pre_id:
        return redirect(url_for('login'))

    user = db.session.get(User, pre_id)
    if not user:
        session.pop('pre_2fa_user_id', None)
        return redirect(url_for('login'))

    error = None
    if request.method == 'POST':
        token = (request.form.get('token') or '').strip()
        if user.verify_2fa_token(token) or user.verify_and_consume_backup_code(token):
            # Token válido — concluir o início de sessão
            session.pop('pre_2fa_user_id', None)
            session['user_id'] = user.id
            session['nome'] = user.nome
            session['role'] = user.role
            if user.role == 'empresa':
                empresa = db.session.query(Empresa).filter_by(user_id=user.id).first()
                if empresa:
                    session['empresa_id'] = empresa.id
            # Opcionalmente, definir o cookie de memorização do dispositivo, se solicitado
            resp = redirect(url_for('home'))
            if request.form.get('remember'):
                payload = {'uid': user.id, 'dev': _uuid4().hex}
                token_signed = _serializer.dumps(payload)
                # Definir um cookie com validade de 30 dias
                resp.set_cookie('remember_device', token_signed, max_age=60 * 60 * 24 * 30, httponly=True, samesite='Lax')
            return resp
        else:
            error = 'Código inválido. Tente novamente.'

    return render_template('2fa_verify.html', error=error)


@app.route('/settings/2fa', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def settings_2fa():
    """
    Page to enable/confirm 2FA for the logged-in user.
    GET: generate secret (if missing) and show QR code.
    POST: verify token and enable 2FA on success.
    """
    user = db.session.get(User, session.get('user_id'))
    if not user:
        return redirect(url_for('login'))

    # Garantir que o utilizador tenha um segredo guardado (mas que ainda não esteja necessariamente ativado)
    if not user.two_factor_secret:
        user.generate_2fa_secret()
        db.session.commit()

    issuer = app.config.get('TWO_FA_ISSUER', 'Internia')
    provisioning_uri = pyotp.TOTP(user.two_factor_secret).provisioning_uri(name=user.email, issuer_name=issuer)

    # Criar imagem QR como URI de dados
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('ascii')
    qr_data_uri = f"data:image/png;base64,{qr_b64}"

    error = None
    success = None
    if request.method == 'POST':
        token = (request.form.get('token') or '').strip()
        if user.verify_2fa_token(token):
            user.two_factor_enabled = True
            db.session.commit()
            success = '2FA ativado com sucesso.'
        else:
            error = 'Código inválido. Tente novamente.'

    return render_template('settings_2fa.html', qr_data_uri=qr_data_uri, secret=user.two_factor_secret, error=error, success=success, two_factor_enabled=user.two_factor_enabled)


@app.route('/settings/2fa/backup', methods=['POST'])
@login_required
@limiter.limit("6 per minute")
def settings_2fa_backup():
    """Generate new backup codes after verifying current TOTP or a backup code.
    Returns a page showing the plaintext codes once.
    """
    user = db.session.get(User, session.get('user_id'))
    if not user or not user.two_factor_enabled:
        return redirect(url_for('settings_2fa'))

    token = (request.form.get('token') or '').strip()
    valid = False
    # Aceitar o TOTP ou um código de reserva já existente
    if user.verify_2fa_token(token):
        valid = True
    elif user.verify_and_consume_backup_code(token):
        # O token era um código de segurança válido e foi utilizado
        db.session.commit()
        valid = True

    if not valid:
        return render_template('settings_2fa.html', qr_data_uri='', secret=user.two_factor_secret, error='Código inválido para gerar backup codes.', success=None, two_factor_enabled=user.two_factor_enabled)

    # Gerar novos códigos de segurança e guardar versões com hash
    codes = user.generate_backup_codes()
    db.session.commit()
    # Armazenar os códigos em texto simples na sessão por um curto período de tempo, para que o utilizador os possa descarregar
    session['last_backup_codes'] = codes
    return render_template('settings_2fa_backup.html', codes=codes)


@app.route('/settings/2fa/backup/download', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def settings_2fa_backup_download():
    """Return the last generated backup codes as a downloadable text file (one-time).
    Codes are stored temporarily in session by settings_2fa_backup and will be cleared after download.
    """
    codes = session.pop('last_backup_codes', None)
    if not codes:
        return redirect(url_for('settings_2fa'))
    text = "\n".join(codes)
    from flask import make_response
    resp = make_response(text)
    resp.headers.set('Content-Type', 'text/plain')
    resp.headers.set('Content-Disposition', 'attachment', filename='backup_codes.txt')
    return resp


@app.route('/settings/2fa/disable', methods=['POST'])
@login_required
@limiter.limit("6 per minute")
def settings_2fa_disable():
    """Disable 2FA for the logged-in user after verifying a TOTP or backup code."""
    user = db.session.get(User, session.get('user_id'))
    if not user or not user.two_factor_enabled:
        return redirect(url_for('settings_2fa'))

    token = (request.form.get('token') or '').strip()
    valid = False
    if user.verify_2fa_token(token):
        valid = True
    elif user.verify_and_consume_backup_code(token):
        db.session.commit()
        valid = True

    if not valid:
        return render_template('settings_2fa.html', qr_data_uri='', secret=user.two_factor_secret, error='Código inválido para desativar 2FA.', success=None, two_factor_enabled=user.two_factor_enabled)

    # Desativar a autenticação de dois fatores e apagar os códigos secretos/de reserva
    user.two_factor_enabled = False
    user.two_factor_secret = None
    user.backup_codes = None
    db.session.commit()
    return redirect(url_for('settings_2fa'))


@app.route('/recover-with-code', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def recover_with_code():
    """Recuperar a conta utilizando um código de segurança.

    O utilizador introduz o seu endereço de e-mail e um código de segurança. Se o código corresponder
    (e for utilizado), permitimos que avance para atualizar tanto o endereço de e-mail como
    a palavra-passe numa página específica.
    """
    error = None
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip()
        code = (request.form.get('code') or '').strip()
        if not email or not code:
            error = 'Preencha email e código de backup.'
        else:
            user = db.session.query(User).filter_by(email=email).first()
            if not user:
                error = 'Email ou código inválido.'
            else:
                ok = False
                try:
                    if user.verify_and_consume_backup_code(code):
                        db.session.commit()
                        ok = True
                except Exception:
                    # Manter erro genérico
                    ok = False

                if ok:
                    session['recovery_user_id'] = user.id
                    logger.info('Backup code recovery success for user_id=%s', user.id)
                    return redirect(url_for('recover_update'))
                else:
                    logger.warning('Backup code recovery failed for email=%s', email)
                    error = 'Email ou código inválido.'

    return render_template('recover_with_code.html', error=error)


@app.route('/recover-update', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def recover_update():
    """Após a verificação bem-sucedida do código de recuperação, permita a alteração do e-mail/palavra-passe.

    Esta rota espera que `session[‘recovery_user_id’]` seja definido pela função
    `recover_with_code`. Após a atualização bem-sucedida, limpamos a chave de sessão e
    iniciamos sessão para o utilizador.
    """
    uid = session.get('recovery_user_id')
    if not uid:
        return redirect(url_for('login'))

    user = db.session.get(User, uid)
    if not user:
        session.pop('recovery_user_id', None)
        return redirect(url_for('login'))

    error = None
    if request.method == 'POST':
        new_email = (request.form.get('email') or '').strip()
        new_pw = (request.form.get('password') or '').strip()
        if not new_email or not new_pw:
            error = 'Preencha email e password.'
        else:
            # Verificar se o endereço de e-mail é único caso tenha sido alterado
            if new_email != user.email and db.session.query(User).filter_by(email=new_email).first():
                error = 'Email já registado por outro utilizador.'
            else:
                user.email = new_email
                user.set_password(new_pw)
                db.session.commit()
                # Limpar o estado de recuperação e iniciar sessão
                session.pop('recovery_user_id', None)
                session['user_id'] = user.id
                session['nome'] = user.nome
                session['role'] = user.role
                if user.role == 'empresa':
                    empresa = db.session.query(Empresa).filter_by(user_id=user.id).first()
                    if empresa:
                        session['empresa_id'] = empresa.id
                return redirect(url_for('home'))

    return render_template('recover_update.html', user=user, error=error)


@app.route('/forgot', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def forgot():
    """Solicite a redefinição da palavra-passe. Se o endereço de e-mail existir, enviamos por e-mail um
    link de redefinição de palavra-passe com validade limitada. Por uma questão de conveniência (recuperação da conta), também geramos um
    novo conjunto de códigos de segurança de 2FA e incluímo-los no corpo do e-mail. Em
    fase de desenvolvimento, o e-mail é enviado para a saída padrão (stdout) se o SMTP não estiver configurado.
    """
    info = None
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip()
        if email:
            user = db.session.query(User).filter_by(email=email).first()
            # Responda sempre da mesma forma para evitar revelar quais são os e-mails existentes
            info = 'Se esse email existe, enviámos instruções para o mesmo.'
            if user:
                token = _serializer.dumps({'uid': user.id}, salt='password-reset')
                reset_url = url_for('reset_password', token=token, _external=True)
                # Gerar versões simples e em HTML do e-mail de redefinição a partir dos modelos
                text_body = render_template('email/reset_email.txt', reset_url=reset_url)
                html_body = render_template('email/reset_email.html', reset_url=reset_url)
                send_email(user.email, 'Redefinir password - Internia', (text_body, html_body))
                logger.info('Password reset requested for user_id=%s email=%s', user.id, user.email)
        else:
            info = 'Preencha um email válido.'
    return render_template('forgot.html', info=info)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reinicie a palavra-passe utilizando um token enviado por e-mail."""
    try:
        data = _serializer.loads(token, salt='password-reset', max_age=3600)
        uid = data.get('uid')
    except (BadSignature, SignatureExpired):
        return "Link inválido ou expirado", 400

    user = db.session.get(User, uid)
    if not user:
        return "User not found", 404

    error = None
    if request.method == 'POST':
        new_pw = (request.form.get('password') or '').strip()
        if not new_pw:
            error = 'Password obrigatória.'
        else:
            user.set_password(new_pw)
            db.session.commit()
            return redirect(url_for('login', _external=False))

    return render_template('reset_password.html', error=error)


@app.route('/logout')
def logout():
    """
    Rota Logout: Apaga sessão e redireciona para a página de registo.
    """
    # Limpe também qualquer estado anterior à autenticação de dois fatores
    session.pop('pre_2fa_user_id', None)
    session.clear()
    return redirect(url_for('registar'))


@app.route("/apagar/<int:user_id>", methods=['POST'])
@login_required
def apagar(user_id):
    """
    Apagar a conta do utilizador.

    Params de caminho POST:
        - user_id: id do utilizador que quer apagar a conta.

    Segurança/validação:
        - Converte id para int e compara-o ao id do user em sessão.
        - Apenas permite apagar quando o user_id da sessão é igual ao id requesitado para apagar.
        - Devolve 400 para input de id invalido, 403 para tentativas não autorizadas,
          ou 404 se o user não for encontrado.

    Em caso de sucesso: apaga o utilizador e redireciona para '/'.
    """
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return "Invalid user id", 400

    session_uid = session.get('user_id')
    try:
        session_uid_int = int(session_uid) if session_uid is not None else None
    except (TypeError, ValueError):
        session_uid_int = None

    if uid == session_uid_int:
        user_to_delete = db.session.get(User, uid)
        if user_to_delete:
            # Remover os ficheiros carregados pelo utilizador (foto de perfil, CV), caso existam
            try:
                _remove_file_if_exists(user_to_delete.foto_perfil)
                _remove_file_if_exists(user_to_delete.cv_path)
            except Exception:
                pass

            # Se o utilizador for proprietário de uma empresa, remova o logótipo da empresa e elimine o registo da empresa
            empresa_obj = db.session.query(Empresa).filter_by(user_id=uid).first()
            if empresa_obj:
                try:
                    _remove_file_if_exists(empresa_obj.logo)
                except Exception:
                    pass
                db.session.delete(empresa_obj)

            db.session.delete(user_to_delete)
            db.session.commit()
            return redirect(url_for('home'))
        return "User not found", 404
    return "Unauthorized", 403


@app.route("/editar/<int:user_id>", methods=['GET', 'POST'])
@login_required
def editar(user_id):
    """
    Editar o perfil do utilizador da sessão.

    GET:
        - Renderiza 'editar.html' com o objeto User do user_id dado, ou 404 se não encontrado.

    POST:
        - Aceita 'nomeForm' e 'emailForm' para atualizar o email e nome do utilizador.
        - Apenas permite editar se o 'user_id' da sessão seja igual ao do objeto User.
        - Redireciona para '/home' após atualização bem-sucedida.
    """
    user_to_edit = db.session.get(User, user_id)
    if not user_to_edit:
        return "User not found", 404
    if session.get('user_id') != user_to_edit.id:
        return "Unauthorized", 403

    if request.method == 'GET':
        return render_template('editar.html', user=user_to_edit)
    elif request.method == 'POST':
        nome = request.form.get('nomeForm')
        email = request.form.get('emailForm')

        user_to_edit.nome = nome
        user_to_edit.email = email
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('editar.html', user=user_to_edit)


@app.route('/anuncios')
@login_required
def dashboard():
    """
    Dashboard que demonstra todos os anuncios.

    Devolve:
        - Renderiza 'anuncios.html' e passa uma lista de todos os Anuncio em BD.
    """
    anuncios = db.session.query(Anuncio).all()
    user_id = session.get('user_id')
    current_user = db.session.get(User, user_id) if user_id else None
    # Compute a set of ad ids the current user already applied to (only relevant for normal users)
    applied_ad_ids = set()
    if current_user and current_user.role == 'user':
        # Access candidaturas relationship to build set
        applied_ad_ids = {c.anuncio_id for c in current_user.candidaturas}

    return render_template('anuncios.html', anuncios=anuncios, current_user=current_user, applied_ad_ids=applied_ad_ids)


@app.route('/dashboard/<int:ad_id>/apply', methods=['POST'])
@login_required
@role_required('user')
def apply_to_ad(ad_id):
    """
    Permite que um utilizador normal se candidate a um Anúncio.

    POST form fields:
        - mensagem (opcional): mensagem de candidatura

    Regras:
        - Apenas utilizadores com role 'user' podem candidatar-se.
        - O mesmo utilizador não pode candidatar-se duas vezes ao mesmo anúncio.
    """
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)
    if not user:
        return redirect(url_for('login'))

    anuncio = db.session.get(Anuncio, ad_id)
    if not anuncio:
        return "Anúncio não encontrado", 404

    mensagem = request.form.get('mensagem') or None

    # Prevent duplicate candidatures
    existing = db.session.query(Candidatura).filter_by(user_id=user.id, anuncio_id=ad_id).first()
    if existing:
        # already applied, redirect back to dashboard
        return redirect(url_for('dashboard'))

    candidatura = Candidatura(user_id=user.id, anuncio_id=ad_id, mensagem=mensagem)
    db.session.add(candidatura)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return "Erro ao submeter candidatura", 500

    return redirect(url_for('dashboard'))


@app.route('/dashboard/<int:ad_id>/applicants', methods=['GET'])
@login_required
@role_required('empresa')
def view_applicants(ad_id):
    """
    Permite que a empresa proprietária do Anúncio veja a lista de candidaturas recebidas.

    Segurança:
        - Apenas o owner (empresa cujo user_id está na sessão) pode ver os candidatos para esse anúncio.
    """
    anuncio = db.session.get(Anuncio, ad_id)
    if not anuncio:
        return "Anúncio não encontrado", 404

    # Verify the logged-in company owns this ad
    empresa = db.session.query(Empresa).filter_by(user_id=session.get('user_id')).first()
    if not empresa or anuncio.empresa_id != empresa.id:
        return "Unauthorized", 403

    # Load candidaturas and related users
    candidaturas = db.session.query(Candidatura).filter_by(anuncio_id=ad_id).all()

    return render_template('applicants.html', candidaturas=candidaturas, anuncio=anuncio)


@app.route('/dashboard/<int:ad_id>/info_empresa', methods=['GET'])
def info_empresa(ad_id):
    """
    Mostrar informação da empresa associada a um anúncio (acessível a qualquer utilizador).
    """
    anuncio = db.session.get(Anuncio, ad_id)
    if not anuncio:
        return "Anúncio não encontrado", 404

    empresa = db.session.get(Empresa, anuncio.empresa_id)
    if not empresa:
        return "Empresa não encontrada", 404

    return render_template('info_empresa.html', empresa=empresa, ad_id=ad_id)


@app.route('/novo_anuncio', methods=['GET', 'POST'])
@login_required
def novo_anuncio():
    """Criar um novo Anúncio (apenas empresas).

    GET: renderiza 'novo_anuncio.html'
    POST: cria o Anuncio a partir de fields do form e redireciona para o dashboard
    """
    # Se o utilizador que iniciou sessão não for uma empresa, redirecione de volta para «anúncios» com
    # uma mensagem de aviso amigável, em vez de apresentar uma página de erro 403. Isto faz com que
    # a experiência do utilizador fique mais clara quando alguém tenta, por engano, criar um anúncio.
    if session.get('role') != 'empresa':
        # Utilizar o Flash em vez de parâmetros de consulta para uma melhor experiência do utilizador
        from flask import flash
        flash('Apenas empresas podem criar anúncios. Crie um perfil de empresa primeiro.', 'error')
        return redirect(url_for('dashboard'))

    # Encontrar a empresa do utilizador atual
    empresa = db.session.query(Empresa).filter_by(user_id=session.get('user_id')).first()
    if not empresa:
        return "Empresa não encontrada", 404

    if request.method == 'POST':
        tipo = (request.form.get('tipo') or '').strip()
        categoria = (request.form.get('categoria') or '').strip()
        local_trabalho = (request.form.get('local_trabalho') or '').strip()
        descricao = request.form.get('descricao')
        hora_entrada_str = request.form.get('hora_entrada')
        hora_saida_str = request.form.get('hora_saida')

        # Validate required new fields
        if not tipo or not categoria:
            return render_template('novo_anuncio.html', error='Tipo e Categoria obrigatórios')

        # parse horas (same as before)
        hora_entrada = None
        hora_saida = None
        try:
            if hora_entrada_str:
                hora_entrada = datetime.strptime(hora_entrada_str, '%H:%M').time()
            if hora_saida_str:
                hora_saida = datetime.strptime(hora_saida_str, '%H:%M').time()
        except ValueError:
            return render_template('novo_anuncio.html', error='Formato de hora inválido')

        novo = Anuncio(
            empresa_id=empresa.id,
            tipo=tipo,
            categoria=categoria,
            local_trabalho=local_trabalho if local_trabalho else None,
            descricao=descricao,
            hora_entrada=hora_entrada,
            hora_saida=hora_saida
        )
        db.session.add(novo)
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('novo_anuncio.html')


@app.route('/dashboard/<int:ad_id>/apagar', methods=['POST'])
@login_required
@role_required('empresa')
def apagar_anuncio(ad_id):
    """Apagar um anúncio — apenas a empresa que o criou pode apagar."""
    anuncio = db.session.get(Anuncio, ad_id)
    if not anuncio:
        return "Anúncio não encontrado", 404

    empresa = db.session.query(Empresa).filter_by(user_id=session.get('user_id')).first()
    if not empresa or anuncio.empresa_id != empresa.id:
        return "Unauthorized", 403

    db.session.delete(anuncio)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/home')
def home():
    """
    Rota home que demonstra a página principal.

    Variáveis de template:
        - users: Lista de todos os utilizadores em BD.
        - current_user: Objeto User para o utilizador da sessão (ou None)
        - user_id: id do user da sessão (or None)
    """
    user_id = session.get('user_id')
    current_user = db.session.get(User, user_id) if user_id else None
    return render_template('home.html', current_user=current_user, user_id=user_id)


if __name__ == '__main__':
    """
    Quando for corrido como um script, garante que as tabelas da BD existem e começa o 
        Flask em modo debug.
    Nota: Na produção, preferir um servidor WSGI real e desativar modo debug.
    """
    with app.app_context():
        db.create_all()
    app.run(debug=True)
