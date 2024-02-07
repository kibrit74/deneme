from datetime import datetime
from flask import Flask, render_template
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
import google.generativeai as genai
from forms.your_forms import YourForm
from flask_login import UserMixin, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from flask_login import UserMixin, current_user
from flask_login import login_user, logout_user, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'gizli_ananiz'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

login_manager.login_message_category = 'info'

admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')


genai.configure(api_key="AIzaSyBWC2gp-UjhlnGQgM0S77lftXnSl0uhqQ0")

generation_config = {
    "temperature": 0.1,
    "top_p": 1,
    "top_k": 32,
    "max_output_tokens": 5000,
}

safety_settings = [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
]

model = genai.GenerativeModel(
    model_name="gemini-pro-vision", generation_config=generation_config, safety_settings=safety_settings
)

class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    search_query = db.Column(db.String(255), nullable=False)
    response = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @classmethod
    def get_response_for_query(cls, user_id, search_query):
        result = cls.query.filter_by(user_id=user_id, search_query=search_query).first()
        return result.response if result else None

    def __repr__(self):
        return f"<SearchHistory(user_id={self.user_id}, search_query='{self.search_query}', created_at={self.created_at})>"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

def toplam_soru_sayisi(self):
        return Soru.query.filter_by(soru_sahibi_id=self.id).count()
   

class Soru(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    soru_icerik = db.Column(db.String(255), nullable=False)
    soru_sahibi_adi = db.Column(db.String(255), default="Misafir")
    soru_sahibi_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    cevaplar = db.relationship('Cevap', back_populates='soru', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    

    def __init__(self, soru_icerik, soru_sahibi_adi):
        self.soru_icerik = soru_icerik
        self.soru_sahibi_adi = soru_sahibi_adi

@staticmethod
def toplam_soru_sayisi():
    return Soru.query.count()


# Cevap Modeli (Örnek)
class Cevap(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cevap_icerik = db.Column(db.Text, nullable=False)
    cevap_sahibi_adi = db.Column(db.String(255))
    soru_id = db.Column(db.Integer, db.ForeignKey('soru.id'), nullable=False)
    soru = db.relationship('Soru', back_populates='cevaplar', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, cevap_icerik, cevap_sahibi_adi, soru_id):
        self.cevap_icerik = cevap_icerik
        self.cevap_sahibi_adi = cevap_sahibi_adi
        self.soru_id = soru_id


class TextContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)

class UserView(ModelView):
    can_delete = False
    can_create = False
    can_edit = False
    column_exclude_list = ["password"]
    form_columns = ["username", "email", "is_admin"]

# Admin panosuna modelleri ekledik
admin.add_view(UserView(User, db.session))
admin.add_view(ModelView(Soru, db.session))
admin.add_view(ModelView(Cevap, db.session))

# Veritabanını oluşturduk
with app.app_context():
    db.create_all()
    

@app.route('/user_login')
def user_login():
    # Giriş işlemleri
    return render_template('login.html')
@login_manager.user_loader
def load_user(user_id):
    try:
        user_id = int(user_id)
        user = db.session.query(User).get(user_id)

        if user:
            return user
        else:
            print(f"Kullanıcı bulunamadı: {user_id}")
            return None
    except Exception as e:
        print(f"Hata: {e}")
        return None


@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # E-posta adresinin boş olup olmadığını kontrol et
        if not email:
            flash('Geçerli bir e-posta adresi giriniz.', 'danger')
            return redirect(url_for('admin_register'))

        # E-posta adresinin veritabanında zaten var olup olmadığını kontrol et
        if User.query.filter_by(email=email).first():
            flash('Bu e-posta adresi zaten kullanımda.', 'danger')
            return redirect(url_for('admin_register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, email=email, password=hashed_password, is_admin=True)
        db.session.add(new_user)
        db.session.commit()

        flash('Başarıyla kayıt oldunuz! Şimdi giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))

    return render_template('admin_register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        flash('Bu sayfaya erişim izniniz yok.', 'danger')
        return redirect(url_for('profil'))

    # Giriş yapan kullanıcının arama geçmişi
    user_search_history = SearchHistory.query.filter_by(user_id=current_user.id).all()

    # Giriş yapan kullanıcının toplam arama sayısı
    user_total_searches = len(user_search_history)

    # Tüm kullanıcılar
    users = User.query.all()
    
    # Toplam üye sayısı
    total_users = len(users)
    
    # Toplam arama geçmişi sayısı
    total_search_history = len(SearchHistory.query.all())

    # Kullanıcı bazında arama sayıları
    user_search_counts = {}
    for user in users:
        user_search_counts[user.id] = len(SearchHistory.query.filter_by(user_id=user.id).all())

    # Son 1 Haftadaki Üye Sayısı
    one_week_ago = datetime.now() - timedelta(days=7)
    new_users_last_week = User.query.filter(User.created_at >= one_week_ago).count()
    # Toplam soru soran kullanıcı sayısı
    total_soru_users = len(Soru.query.filter(Soru.soru_sahibi_adi.isnot(None)).distinct(Soru.soru_sahibi_adi).all())

    # Toplam misafir kullanıcı sayısı ("Misafir" adıyla gösterilen kullanıcılar)
    total_misafir_users = len(Soru.query.filter_by(soru_sahibi_adi="Misafir").all())
    kullanici_sorulari = Soru.query.filter_by(soru_sahibi_id=current_user.id).count()
    toplam_soru_sayisi_last_week = toplam_soru_sayisi_son_hafta()

    return render_template(
        'dashboard.html',
        users=users,
        user_search_history=user_search_history,
        total_users=total_users,
        total_search_history=total_search_history,
        user_total_searches=user_total_searches,
        user_search_counts=user_search_counts,
        new_users_last_week=new_users_last_week,
        toplam_soru_sayisi=total_soru_users,
        soru_adisahibi_adi=total_misafir_users,
        kullanici_sorulari=kullanici_sorulari,toplam_soru_sayisi_last_week=toplam_soru_sayisi_last_week
    )
    

@app.route('/your_route')
def your_route():
    # Son bir hafta içinde üye olanları bul
    current_date = datetime.now()
    last_week = current_date - timedelta(days=7)
    new_users_last_week_count = User.query.filter(User.created_at >= last_week).count()

    # Diğer bilgileri al (örneğin toplam kullanıcı sayısı)
    total_users = User.query.count()
    user_total_searches = 42  # Bu değeri kendi veritabanınıza göre ayarlayın

    # Tüm kullanıcıları alabilirsiniz, veya başka bir kritere göre sorgu yapabilirsiniz
    all_users = User.query.all()
    toplam_soru_sayisi = Soru.toplam_soru_sayisi()
    soru_sahibi_adi=soru_sahibi_adi()
    # Diğer bilgileri render_template'e geçirerek HTML sayfanıza gönderin
    return render_template('your_template.html', total_users=total_users, user_total_searches=user_total_searches, new_users_last_week_count=new_users_last_week_count, all_users=all_users,toplam_soru_sayisi=toplam_soru_sayisi, soru_sahibi_adi=soru_sahibi_adi)


@app.route('/editor', methods=['GET', 'POST'])
def editor():
    # TinyMCE'den gelen metni işleyin
    if request.method == 'POST':
        new_text = request.form.get('content', '')
        # Veritabanına kaydedin veya güncelleyin
        text_content = TextContent.query.first()
        if text_content:
            text_content.content = new_text
        else:
            new_content = TextContent(content=new_text)
            db.session.add(new_content)
            db.session.commit()
        return redirect(url_for('editor'))

    # Metin editörü sayfasını görüntüleyin
    text_content = TextContent.query.first()
    current_text = text_content.content if text_content else ''
    
    return render_template('editor.html', current_text=current_text)

@app.route('/user_details/<int:user_id>')
@login_required
def user_details(user_id):
    selected_user = User.query.get(user_id)
    if selected_user:
        user_search_history = SearchHistory.query.filter_by(user_id=user_id).all()
        
        # Kullanıcı bazında arama sayıları
        users = User.query.all()
        user_search_counts = {}
        for user in users:
            user_search_counts[user.id] = len(SearchHistory.query.filter_by(user_id=user.id).all())

        return render_template('detail.html', user=selected_user, search_history=user_search_history, user_search_counts=user_search_counts)
    else:
        flash('Invalid user ID.')
        return redirect(url_for('dashboard'))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        
        if user and bcrypt.check_password_hash(user.password, password):

            login_user(user)
            flash('Başarıyla giriş yaptınız!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))

        else:
            flash('Kullanıcı adı veya şifre hatalı. Lütfen tekrar deneyin.', 'danger')

    return render_template('login.html')

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    # Sileceğimiz kullanıcıyı çek
    user_to_delete = User.query.get(user_id)

    # Kullanıcıyı veritabanından sil
    db.session.delete(user_to_delete)
    db.session.commit()

    return redirect(url_for('dashboard'))

# Arama geçmişi kaydetme fonksiyonu
def save_search_history(username, search_query, response):
    user = User.query.filter_by(username=username).first()
    new_search_history = SearchHistory(
        user_id=user.id,
        search_query=search_query,
        response=response,
    )
    db.session.add(new_search_history)
    db.session.commit()

@app.route('/admin')
@login_required
def admin():
    # Sadece giriş yapmış kullanıcılar admin sayfasına erişebilir
    if current_user.is_authenticated:
        return render_template('admin.html')
    else:
        # Kullanıcı giriş yapmamışsa, 'login' sayfasına yönlendir
        return redirect(url_for('dashboard'))

# Ana sayfa
@app.route('/')
def index():
    # Burada mevcut metni veritabanından çekin
    text_content = TextContent.query.first()
    current_text = text_content.content if text_content else ''
    return render_template('index.html', current_text=current_text)

# Kullanıcı adını getirme endpoint'i
@app.route('/get-username')
def get_username():
    user = session.get('user')
    if user:
        return jsonify({"username": user})
    else:
        return jsonify({"error": "Kullanıcı adı bulunamadı."})

@app.route('/process_users', methods=['POST'])
def process_users():
    action = request.form.get('action')

    if action == 'delete':
        selected_users = request.form.getlist('selected_users')

        # Silme işlemini gerçekleştiren bir delete_user fonksiyonunuz olduğunu varsayalım
        for user_id in selected_users:
            delete_user(user_id)

        flash('Seçilen kullanıcılar başarıyla silindi.', 'success')
    elif action == 'details':
        # Detayları görüntüleme işlemini gerçekleştirin
        pass
    else:
        flash('Geçersiz işlem.', 'error')

    return redirect(url_for('dashboard'))

# Profil sayfası
@app.route('/profil')
def profil():
    user = session.get('user')
    user_info = User.query.filter_by(username=user).first()
    return render_template('profil.html', user=user)

@app.route('/kayit', methods=['GET', 'POST'])
def kayit():
    user = session.get('user')
    user_info = User.query.filter_by(username=user).first()

    if user:
        return redirect('/index')

    error_message = None

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_repeat = request.form.get('password_repeat')

        # Mevcut kullanıcıları kontrol et
        existing_user = User.query.filter(db.or_(User.username == username, User.email == email)).first()

        if existing_user:
            # Kullanıcı zaten varsa hata mesajını ayarla
            error_message = "Bu kullanıcı adı veya email adresi zaten mevcut."
        elif password != password_repeat:
            error_message = "Şifreler uyuşmuyor."
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect('/giris')

    return render_template('kayit.html', user=user, error_message=error_message)


# Giriş sayfası
@app.route('/giris', methods=['GET', 'POST'])
def giris():
    user = session.get('user')
    user_info = User.query.filter_by(username=user).first()
    error_message = None

    if user:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user'] = username
            return redirect(url_for('profildata'))
        else:
            error_message = "Kullanıcı adı veya şifre hatalı."

    return render_template('giris.html', error_message=error_message, user=user)

# Kayıt sayfasına yönlendirme
@app.route('/register')
def register():
    return render_template('admin_register.html')

@app.route('/soru', methods=['GET', 'POST'])
def soru():
    user = session.get('user')
    user_info = User.query.filter_by(username=user).first()

    if request.method == 'POST':
        # Ürün arama formundan gelen veriyi al
        search_query = request.form.get('search_query')

        # Eğer arama sorgusu varsa, ürün aramasını yap
        if search_query:
            

            # Ardından ürün listesini ve arama sorgusunu kaydedebilirsiniz
            save_search_history(user, search_query, "Ürün arama sonuçları")

            # Ürün listesini ve arama sorgusunu şablonla paylaş
            return render_template('arama_sonuclari.html', search_query=search_query)

    return render_template('soru.html', user=user)
# Karşılaştırma sayfası
@app.route('/karsi')
def karsi():
    return render_template('karsi.html')

# İçerik üretme endpoint'i
@app.route("/generate-content", methods=["POST"])
def generate_content():
    try:
        data = request.form

        if 'image' in request.files:
            image = request.files['image']
            product_name = data.get('product_name', '')

            if not image:
                raise ValueError("No image provided.")

            image_parts = [{"mime_type": image.mimetype, "data": image.read()}]

            prompt_parts = [
                f"[Kullanıcının gönderdiği fotoğraftaki ürünü tanımlıyorum]. Ürün adını ve varsa teknik özelliklerini getireceğim. **Ürün yorumlarını analiz et:** Amazon.com.tr, Trendyol.com ve Hepsiburada.com sitelerindeki yorumları inceleyerek, olumlu ve olumsuz görüşleri analiz edip paylaşacağım. Ayrıca, sitelerdeki değerlendirme puanlarını da sunacağım ve kullanıcı yorumlarından çıkan genel eğilimi özetleyeceğim. **Olumlu ve olumsuz yorumları seçerken, Her siteninin değerlendirme puanını getireceğim, Örnek olarak her siteden olumlu ve olumsuz yorumlar getireceğim. yorumların kalitesini ve kullanıcının ürüne verdiği puanı dikkate alacağım. Örnek olsun diye birkaç tane olumlu ve olumsuz yorum getireceğim.** Yorumları her siteden getirip, sonuç kısmında ürünün genel değerlendirmesini yapacağım.Sonuç kısımında daha detaylı değerlendiröe yapacaksın.'",
                f"Ürün Adı: {product_name}",
                " ",
                image_parts[0],
            ]

            response = model.generate_content(prompt_parts)
            username = session.get('user')
            save_search_history(username, "", response.text)
            return jsonify({"content": response.text})

        elif 'image1' in request.files and 'image2' in request.files:
            image1 = request.files['image1']
            image2 = request.files['image2']
            product_name_1 = data.get('product_name_1', '')
            product_name_2 = data.get('product_name_2', '')

            if not image1 or not image2:
                raise ValueError("No image provided.")

            image_parts1 = [{"mime_type": image1.mimetype, "data": image1.read()}]
            image_parts2 = [{"mime_type": image2.mimetype, "data": image2.read()}]

            prompt_parts = [
                f"Gönderilen resimlerdeki ürünleri detaylı bir şekilde inceleyip, teknik özellikleri ve kullanıcı deneyimlerine göre analiz ederek karşılaştırma yapacağım. Ürünlerin teknik özelliklerini ve gerçek kullanıcı yorumlarını {', '.join(['www.hepsiburada.com', 'www.trendyol.com', 'www.teknosa.com', 'https://www.mediamarkt.com.tr', 'www.epey.com'])} adreslerinden toplayarak bu bilgileri listeleyeceğim. Ayrıca, her bir ürüne değerlendirme puanları vererek, ürünleri birbirinden ayıran ve öne çıkaran özelliklere odaklanacağım.",
                f"Ürün Adı 1: {product_name_1}",
                f"Ürün Adı 2: {product_name_2}",
                " ",
                image_parts1[0],
                image_parts2[0],
            ]

            response = model.generate_content(prompt_parts)
            username = session.get('user')
            save_search_history(username, "", response.text)
            return jsonify({"content": response.text})

        else:
            raise ValueError("Invalid request. Please provide either 'image' or both 'image1' and 'image2'.")

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

# Profil ve arama geçmişi sayfası
@app.route('/profildata', methods=['GET', 'POST'])
def profildata():
    username = session.get('user')
    user_info = User.query.filter_by(username=username).first()

    user_search_history = SearchHistory.query.filter_by(user_id=user_info.id).order_by(SearchHistory.created_at.desc()).limit(5).all()
    last_search_response = user_search_history[-1].response if user_search_history else ''
    total_searches = len(user_search_history)
    recent_search_summaries = [{'query': history.search_query, 'response': history.response} for history in user_search_history]
    all_searches = SearchHistory.query.filter_by(user_id=user_info.id).order_by(SearchHistory.created_at.desc()).all()
    search_query = request.form.get('search_query')
    form = YourForm()

    if request.method == 'POST':
        search_query = request.form.get('search_query')

        if search_query:
            new_search_history = SearchHistory(
                user_id=user_info.id,
                search_query=search_query,
                response="Arama sonuçları burada...", 
            )
            db.session.add(new_search_history)
            db.session.commit()

            search_result = {'search_query': '', 'other_data': ''}
            return render_template('profildata.html', user_search_history=user_search_history,
                                   user=user_info, response=last_search_response,
                                   recent_search_summaries=recent_search_summaries,
                                   all_searches=all_searches, total_searches=total_searches, form=form,
                                   search_query=search_query if search_query else '',
                                   search_result=search_result)

    return render_template('profildata.html', user_search_history=user_search_history,
                           user=user_info, response=last_search_response,
                           recent_search_summaries=recent_search_summaries,
                           all_searches=all_searches, total_searches=total_searches, form=form,
                           search_query=search_query if search_query else '')

# Örnek: Veritabanından arama geçmişini kaldıran bir işlev
def delete_search_from_history(user_id, search_id):
    # user_id parametresi kullanıcının kimliğini belirtir
    # search_id parametresi silinecek aramanın kimliğini belirtir
    # Burada veritabanınıza veya depolama mekanizmanıza göre uygun silme işlemlerini gerçekleştirin
    # Örneğin SQLAlchemy kullanılıyorsa:
    search_to_delete = SearchHistory.query.filter_by(user_id=user_id, id=search_id).first()
    if search_to_delete:
        db.session.delete(search_to_delete)
        db.session.commit()
    
       
@app.route('/delete_search', methods=['POST'])
def delete_search():
    user_id = request.form.get('user_id')
    search_id = request.form.get('search_id')

    # Burada kullanıcı kimliği ve silinecek arama kimliği alınır ve delete_search_from_history
    # fonksiyonu çağrılarak arama geçmişi güncellenir
    delete_search_from_history(user_id, search_id)

    return jsonify({'success': True})

@app.route('/sss1')
def sss1():
    # Giriş işlemleri
    return render_template('sss1.html')


sayfa_boyutu = 20

@app.route('/sss', methods=['GET', 'POST'])
def sss():
    sorular = Soru.query.all()
    cevaplar = Cevap.query.all()

    # Görünen toplam soru ve cevap sayısını hesaplayın
    toplam_soru_ve_cevap = len(sorular) + len(cevaplar)

    # Daha fazla göster linki için bir bayrak
    daha_fazla_goster = False

    gosterilen_soru_sayisi = sayfa_boyutu  # sayfa_boyutu'nu gosterilen_soru_sayisi olarak başlatın

    if request.method == 'POST':
        soru_icerik = request.form.get('soru_icerik')
        soru_sahibi_adi = request.form.get('soru_sahibi_adi', default="Misafir")
        cevap_icerik = request.form.get('cevap_icerik')

        if not soru_icerik:
            flash('Soru içeriği boş olamaz.', 'error')
            return redirect(url_for('sss'))

        yeni_soru = Soru(soru_icerik=soru_icerik, soru_sahibi_adi=soru_sahibi_adi)
        db.session.add(yeni_soru)
        db.session.commit()

        # Eğer cevap içeriği girilmişse ve soru eklenmişse
        if cevap_icerik and yeni_soru:
            yeni_cevap = Cevap(cevap_icerik=cevap_icerik, soru_id=yeni_soru.id, cevap_sahibi_adi=soru_sahibi_adi)
            db.session.add(yeni_cevap)
            db.session.commit()
        elif cevap_icerik:
            flash('Cevap eklemek için önce bir soru sorun.', 'error')

        # Yeniden sorgu yaparak güncellenmiş soru listesini al
        sorular = Soru.query.all()

    # Sayfa boyutu tanımlanması

    # Toplam görünen soru ve cevap sayısı, şu ana kadar gösterilen sayfa sayısının
    # (sayfa_boyutu * sayfa_numarasi) kadar olmalıdır.
    if gosterilen_soru_sayisi < toplam_soru_ve_cevap:
        daha_fazla_goster = True

    return render_template('sss.html', sorular=sorular, cevaplar=cevaplar, current_user=current_user, daha_fazla_goster=daha_fazla_goster, gosterilen_soru_sayisi=gosterilen_soru_sayisi)

from flask import jsonify, redirect, url_for

@app.route('/cevap_ver/<int:soru_id>', methods=['POST'])
def cevap_ver(soru_id):
    selected_soru = Soru.query.get(soru_id)

    if request.method == 'POST':
        if 'user' in session:
            cevap_sahibi_adi = session['user']
        else:
            cevap_sahibi_adi = request.form.get('cevap_sahibi_adi')

        cevap_icerik = request.form.get('cevap_icerik')

        if not cevap_icerik:
            print('Hata: Cevap içeriği boş olamaz.')
            return jsonify({'success': False, 'message': 'Cevap içeriği boş olamaz.'})

        if len(cevap_icerik) > 1000:
            print('Hata: Cevap içeriği 1000 karakteri geçemez.')
            return jsonify({'success': False, 'message': 'Cevap içeriği 1000 karakteri geçemez.'})

        yeni_cevap = Cevap(cevap_icerik=cevap_icerik, soru_id=soru_id, cevap_sahibi_adi=cevap_sahibi_adi)

        db.session.add(yeni_cevap)
        db.session.commit()

    sorular = Soru.query.all()
    cevaplar = Cevap.query.all()
    return render_template('sss.html', sorular=sorular, cevaplar=cevaplar, current_user=current_user)


@app.route('/soru_sor', methods=['POST'])
def soru_sor():
    if request.method == 'POST':
        soru_icerik = request.form.get('soru_icerik')

        # Kullanıcı girişi yapılmış mı kontrol et
        if 'user' in session:
            soru_sahibi_adi = session['user']  # Eğer oturum varsa, kullanıcının adını al
        else:
            soru_sahibi_adi = request.form.get('soru_sahibi_adi')
            # Eğer oturum yoksa, formdan gelen soru_sahibi_adi'yi kullan

            # Kullanıcı adı girilmemişse hata mesajı ver ve işlemi durdur
            if not soru_sahibi_adi:
                flash('Kullanıcı adı boş olamaz.', 'danger')
                return redirect(url_for('sss'))

        if soru_icerik:
            yeni_soru = Soru(soru_icerik=soru_icerik, soru_sahibi_adi=soru_sahibi_adi)
            db.session.add(yeni_soru)
            db.session.commit()

            return redirect(url_for('sss'))

        flash('Soru içerik boş olamaz.', 'danger')

    # Soruları güncel al
    sorular = Soru.query.all()
    cevaplar = Cevap.query.all()

    return render_template('sss.html', sorular=sorular, cevaplar=cevaplar, current_user=current_user)

@app.route('/soru_sil/<int:soru_id>', methods=['GET'])
def soru_sil(soru_id):
    soru = Soru.query.get_or_404(soru_id)

    # Kullanıcı girişi yapılmış mı kontrol et
    if 'user' in session:
        soru_sahibi_adi = session['user']  # Eğer oturum varsa, kullanıcının adını al
        if soru.user.username == soru_sahibi_adi:
            db.session.delete(soru)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Soru silindi.'})
        else:
            return jsonify({'success': False, 'message': 'Bu işlemi gerçekleştirmek için yetkiniz yok.'})
    else:
        return jsonify({'success': False, 'message': 'Kullanıcı oturumu yok.'})
    
def toplam_soru_sayisi_son_hafta():
    one_week_ago = datetime.now() - timedelta(days=7)
    return Soru.query.filter(
        Soru.created_at >= one_week_ago
    ).count()


def get_user_question_counts(users):
    user_question_counts = {}
    for user in users:
        question_count = Soru.query.filter_by(soru_sahibi_id=user.id).count()
        user_question_counts[user.id] = question_count
    return user_question_counts


@app.route('/cikis')
def cikis():
    session.pop('user', None)
    return redirect('/')
@app.route('/logout')
@login_required
def logout():
    logout_user()  # Flask-Login ile kullanıcıyı çıkış yaptırın
    session.pop('user', None)
    session.pop('admin_username', None)
    return redirect(url_for('login'))


if __name__ == "__main__":


    app.run(debug=True)
    