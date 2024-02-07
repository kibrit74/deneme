from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_security import Security, SQLAlchemyUserDatastore
from forms.your_forms import LoginForm

# Flask uygulamasını oluşturun
app = Flask(__name__)

# Flask-SQLAlchemy ile veritabanı bağlantısını yapın
db = SQLAlchemy()

# Flask-Migrate ile veritabanı migrasyonlarını yönetin
migrate = Migrate(app, db)

# Flask-Security ile ilgili yapılandırmalar
from models import User, Role  # models modülünden User ve Role sınıflarını import edin

# Flask-Security'nin kullanıcı verilerini ve rollerini saklamak için SQLAlchemyUserDatastore'ı tanımlayın
user_datastore = SQLAlchemyUserDatastore(db, User, Role)

# Flask-Security'nin özelliklerini uygulamaya ekleyin
security = Security()

# User rol tablosunu kullanıcı veri deposuna ekleyin
user_datastore.user_model.roles = db.relationship(
    'Role', secondary='user_roles',
    backref=db.backref('users', lazy='dynamic')
)

# Flask-Security yapılandırmasını uygula
security.init_app(app, user_datastore)

# (Diğer importlar ve yapılandırmalar buraya gelebilir)
