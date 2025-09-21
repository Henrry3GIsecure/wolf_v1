import React, { useState, useEffect, createContext, useContext } from 'react';
import './App.css';
import axios from 'axios';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Context para autenticación
const AuthContext = createContext();

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth debe usarse dentro de AuthProvider');
  }
  return context;
};

// Componente de traducción
const translations = {
  es: {
    appName: 'WOLF',
    tagline: 'Inteligencia de Amenazas Cibernéticas',
    login: 'Iniciar Sesión',
    register: 'Registrarse',
    email: 'Correo Electrónico',
    password: 'Contraseña (24 caracteres)',
    pin: 'PIN de Recuperación (5 dígitos)',
    phone: 'Teléfono (Opcional)',
    loginBtn: 'Iniciar Sesión',
    registerBtn: 'Registrarse',
    logout: 'Cerrar Sesión',
    threats: 'Amenazas',
    admin: 'Administración',
    dashboard: 'Dashboard',
    addThreat: 'Agregar Amenaza',
    uploadJson: 'Subir JSON',
    qrCode: 'Código QR',
    statistics: 'Estadísticas',
    level: 'Nivel',
    type: 'Tipo',
    country: 'País',
    description: 'Descripción',
    actions: 'Acciones',
    edit: 'Editar',
    delete: 'Eliminar',
    save: 'Guardar',
    cancel: 'Cancelar',
    high: 'Alto',
    medium: 'Medio', 
    low: 'Bajo',
    leak: 'Filtración',
    malware: 'Malware',
    hack: 'Hackeo',
    vulnerability: 'Vulnerabilidad',
    title: 'Título',
    url: 'URL',
    socialReference: 'Referencia Social',
    forgotPassword: 'Olvidé mi contraseña',
    resetPassword: 'Restablecer Contraseña',
    newPassword: 'Nueva Contraseña',
    resetBtn: 'Restablecer',
    backToLogin: 'Volver al Login',
    loading: 'Cargando...',
    noThreats: 'No hay amenazas disponibles',
    error: 'Error',
    success: 'Éxito',
    socialMedia: 'Redes Sociales',
    donations: 'Donaciones BTC'
  },
  en: {
    appName: 'WOLF',
    tagline: 'Cybersecurity Threat Intelligence',
    login: 'Login',
    register: 'Register',
    email: 'Email',
    password: 'Password (24 characters)',
    pin: 'Recovery PIN (5 digits)',
    phone: 'Phone (Optional)',
    loginBtn: 'Login',
    registerBtn: 'Register',
    logout: 'Logout',
    threats: 'Threats',
    admin: 'Administration',
    dashboard: 'Dashboard',
    addThreat: 'Add Threat',
    uploadJson: 'Upload JSON',
    qrCode: 'QR Code',
    statistics: 'Statistics',
    level: 'Level',
    type: 'Type',
    country: 'Country',
    description: 'Description',
    actions: 'Actions',
    edit: 'Edit',
    delete: 'Delete',
    save: 'Save',
    cancel: 'Cancel',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    leak: 'Leak',
    malware: 'Malware',
    hack: 'Hack',
    vulnerability: 'Vulnerability',
    title: 'Title',
    url: 'URL',
    socialReference: 'Social Reference',
    forgotPassword: 'Forgot Password',
    resetPassword: 'Reset Password',
    newPassword: 'New Password',
    resetBtn: 'Reset',
    backToLogin: 'Back to Login',
    loading: 'Loading...',
    noThreats: 'No threats available',
    error: 'Error',
    success: 'Success',
    socialMedia: 'Social Media',
    donations: 'BTC Donations'
  },
  pt: {
    appName: 'WOLF',
    tagline: 'Inteligência de Ameaças Cibernéticas',
    login: 'Entrar',
    register: 'Registrar',
    email: 'Email',
    password: 'Senha (24 caracteres)',
    pin: 'PIN de Recuperação (5 dígitos)',
    phone: 'Telefone (Opcional)',
    loginBtn: 'Entrar',
    registerBtn: 'Registrar',
    logout: 'Sair',
    threats: 'Ameaças',
    admin: 'Administração',
    dashboard: 'Dashboard',
    addThreat: 'Adicionar Ameaça',
    uploadJson: 'Upload JSON',
    qrCode: 'Código QR',
    statistics: 'Estatísticas',
    level: 'Nível',
    type: 'Tipo',
    country: 'País',
    description: 'Descrição',
    actions: 'Ações',
    edit: 'Editar',
    delete: 'Excluir',
    save: 'Salvar',
    cancel: 'Cancelar',
    high: 'Alto',
    medium: 'Médio',
    low: 'Baixo',
    leak: 'Vazamento',
    malware: 'Malware',
    hack: 'Hack',
    vulnerability: 'Vulnerabilidade',
    title: 'Título',
    url: 'URL',
    socialReference: 'Referência Social',
    forgotPassword: 'Esqueci a senha',
    resetPassword: 'Redefinir Senha',
    newPassword: 'Nova Senha',
    resetBtn: 'Redefinir',
    backToLogin: 'Voltar ao Login',
    loading: 'Carregando...',
    noThreats: 'Nenhuma ameaça disponível',
    error: 'Erro',
    success: 'Sucesso',
    socialMedia: 'Redes Sociais',
    donations: 'Doações BTC'
  },
  fr: {
    appName: 'WOLF',
    tagline: 'Renseignement sur les Menaces Cybernétiques',
    login: 'Connexion',
    register: 'S\'inscrire',
    email: 'Email',
    password: 'Mot de passe (24 caractères)',
    pin: 'PIN de récupération (5 chiffres)',
    phone: 'Téléphone (Optionnel)',
    loginBtn: 'Se connecter',
    registerBtn: 'S\'inscrire',
    logout: 'Déconnexion',
    threats: 'Menaces',
    admin: 'Administration',
    dashboard: 'Tableau de bord',
    addThreat: 'Ajouter une menace',
    uploadJson: 'Télécharger JSON',
    qrCode: 'Code QR',
    statistics: 'Statistiques',
    level: 'Niveau',
    type: 'Type',
    country: 'Pays',
    description: 'Description',
    actions: 'Actions',
    edit: 'Modifier',
    delete: 'Supprimer',
    save: 'Sauvegarder',
    cancel: 'Annuler',
    high: 'Élevé',
    medium: 'Moyen',
    low: 'Faible',
    leak: 'Fuite',
    malware: 'Malware',
    hack: 'Piratage',
    vulnerability: 'Vulnérabilité',
    title: 'Titre',
    url: 'URL',
    socialReference: 'Référence Sociale',
    forgotPassword: 'Mot de passe oublié',
    resetPassword: 'Réinitialiser le mot de passe',
    newPassword: 'Nouveau mot de passe',
    resetBtn: 'Réinitialiser',
    backToLogin: 'Retour à la connexion',
    loading: 'Chargement...',
    noThreats: 'Aucune menace disponible',
    error: 'Erreur',
    success: 'Succès',
    socialMedia: 'Réseaux Sociaux',
    donations: 'Donations BTC'
  }
};

const useTranslation = (language) => {
  return translations[language] || translations.es;
};

// Proveedor de autenticación
const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      // Set axios default header
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      // Verify token and get user info
      verifyToken();
    } else {
      setLoading(false);
    }
  }, [token]);

  const verifyToken = async () => {
    try {
      // This would ideally be a separate endpoint to verify token
      setLoading(false);
    } catch (error) {
      logout();
    }
  };

  const login = async (email, password) => {
    try {
      const response = await axios.post(`${API}/auth/login`, { email, password });
      const { access_token, user_id, is_admin } = response.data;
      
      setToken(access_token);
      setUser({ email, user_id, is_admin });
      localStorage.setItem('token', access_token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      
      return { success: true };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Error de login' 
      };
    }
  };

  const register = async (userData) => {
    try {
      const response = await axios.post(`${API}/auth/register`, userData);
      const { access_token, user_id, is_admin } = response.data;
      
      setToken(access_token);
      setUser({ email: userData.email, user_id, is_admin });
      localStorage.setItem('token', access_token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      
      return { success: true };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Error de registro' 
      };
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
    delete axios.defaults.headers.common['Authorization'];
  };

  const resetPassword = async (email, pin, newPassword) => {
    try {
      await axios.post(`${API}/auth/reset-password`, {
        email,
        pin,
        new_password: newPassword
      });
      return { success: true };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Error al restablecer contraseña' 
      };
    }
  };

  return (
    <AuthContext.Provider value={{
      user,
      token,
      loading,
      login,
      register,
      logout,
      resetPassword
    }}>
      {children}
    </AuthContext.Provider>
  );
};

// Componente Header
const Header = ({ language, setLanguage, t }) => {
  const { user, logout } = useAuth();

  return (
    <header className="wolf-header">
      {/* Redes Sociales */}
      <div className="social-header">
        <div className="social-links">
          <span className="social-label">{t.socialMedia}:</span>
          <a href="#" className="social-link instagram">IG</a>
          <a href="#" className="social-link telegram">TELEGRAM</a>
          <span className="btc-label">{t.donations}:</span>
          <span className="btc-address">1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</span>
        </div>
        <div className="language-selector">
          <select 
            value={language} 
            onChange={(e) => setLanguage(e.target.value)}
            className="language-select"
          >
            <option value="es">🇪🇸 Español</option>
            <option value="en">🇺🇸 English</option>
            <option value="pt">🇧🇷 Português</option>
            <option value="fr">🇫🇷 Français</option>
          </select>
        </div>
      </div>

      {/* Logo y Navigation */}
      <div className="main-header">
        <div className="logo-section">
          <div className="wolf-logo">
            <h1 className="wolf-title">{t.appName}</h1>
            <p className="wolf-tagline">{t.tagline}</p>
          </div>
        </div>

        {user && (
          <nav className="main-nav">
            <button className="nav-btn">{t.dashboard}</button>
            <button className="nav-btn">{t.threats}</button>
            {user.is_admin && <button className="nav-btn">{t.admin}</button>}
            <button className="nav-btn logout-btn" onClick={logout}>
              {t.logout}
            </button>
          </nav>
        )}
      </div>
    </header>
  );
};

// Componente Login
const LoginForm = ({ t, onToggleForm, onForgotPassword }) => {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const result = await login(email, password);
    if (!result.success) {
      setError(result.error);
    }
    setLoading(false);
  };

  return (
    <div className="auth-container">
      <div className="auth-form">
        <h2 className="auth-title">{t.login}</h2>
        {error && <div className="error-message">{error}</div>}
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>{t.email}</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="form-input"
            />
          </div>
          
          <div className="form-group">
            <label>{t.password}</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="form-input"
              maxLength="24"
            />
          </div>
          
          <button 
            type="submit" 
            disabled={loading}
            className="auth-button primary"
          >
            {loading ? t.loading : t.loginBtn}
          </button>
        </form>
        
        <div className="auth-links">
          <button 
            onClick={onToggleForm}
            className="link-button"
          >
            {t.register}
          </button>
          <button 
            onClick={onForgotPassword}
            className="link-button"
          >
            {t.forgotPassword}
          </button>
        </div>
      </div>
    </div>
  );
};

// Componente Register
const RegisterForm = ({ t, onToggleForm }) => {
  const { register } = useAuth();
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    pin: '',
    phone: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (formData.password.length !== 24) {
      setError('La contraseña debe tener exactamente 24 caracteres');
      setLoading(false);
      return;
    }

    if (formData.pin.length !== 5 || !/^\d+$/.test(formData.pin)) {
      setError('El PIN debe tener exactamente 5 dígitos');
      setLoading(false);
      return;
    }

    const result = await register(formData);
    if (!result.success) {
      setError(result.error);
    }
    setLoading(false);
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  return (
    <div className="auth-container">
      <div className="auth-form">
        <h2 className="auth-title">{t.register}</h2>
        {error && <div className="error-message">{error}</div>}
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>{t.email}</label>
            <input
              type="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              required
              className="form-input"
            />
          </div>
          
          <div className="form-group">
            <label>{t.password}</label>
            <input
              type="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              required
              className="form-input"
              maxLength="24"
              placeholder="Debe tener exactamente 24 caracteres"
            />
          </div>
          
          <div className="form-group">
            <label>{t.pin}</label>
            <input
              type="text"
              name="pin"
              value={formData.pin}
              onChange={handleChange}
              required
              className="form-input"
              maxLength="5"
              pattern="\d{5}"
              placeholder="5 dígitos para recuperación"
            />
          </div>
          
          <div className="form-group">
            <label>{t.phone}</label>
            <input
              type="tel"
              name="phone"
              value={formData.phone}
              onChange={handleChange}
              className="form-input"
            />
          </div>
          
          <button 
            type="submit" 
            disabled={loading}
            className="auth-button primary"
          >
            {loading ? t.loading : t.registerBtn}
          </button>
        </form>
        
        <div className="auth-links">
          <button 
            onClick={onToggleForm}
            className="link-button"
          >
            {t.login}
          </button>
        </div>
      </div>
    </div>
  );
};

// Componente Reset Password
const ResetPasswordForm = ({ t, onBackToLogin }) => {
  const { resetPassword } = useAuth();
  const [formData, setFormData] = useState({
    email: '',
    pin: '',
    newPassword: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (formData.newPassword.length !== 24) {
      setError('La nueva contraseña debe tener exactamente 24 caracteres');
      setLoading(false);
      return;
    }

    const result = await resetPassword(formData.email, formData.pin, formData.newPassword);
    if (result.success) {
      setSuccess(true);
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  if (success) {
    return (
      <div className="auth-container">
        <div className="auth-form">
          <h2 className="auth-title">{t.success}</h2>
          <p>Contraseña restablecida exitosamente</p>
          <button onClick={onBackToLogin} className="auth-button primary">
            {t.backToLogin}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-container">
      <div className="auth-form">
        <h2 className="auth-title">{t.resetPassword}</h2>
        {error && <div className="error-message">{error}</div>}
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>{t.email}</label>
            <input
              type="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              required
              className="form-input"
            />
          </div>
          
          <div className="form-group">
            <label>{t.pin}</label>
            <input
              type="text"
              name="pin"
              value={formData.pin}
              onChange={handleChange}
              required
              className="form-input"
              maxLength="5"
              pattern="\d{5}"
            />
          </div>
          
          <div className="form-group">
            <label>{t.newPassword}</label>
            <input
              type="password"
              name="newPassword"
              value={formData.newPassword}
              onChange={handleChange}
              required
              className="form-input"
              maxLength="24"
            />
          </div>
          
          <button 
            type="submit" 
            disabled={loading}
            className="auth-button primary"
          >
            {loading ? t.loading : t.resetBtn}
          </button>
        </form>
        
        <div className="auth-links">
          <button 
            onClick={onBackToLogin}
            className="link-button"
          >
            {t.backToLogin}
          </button>
        </div>
      </div>
    </div>
  );
};

// Componente Dashboard
const Dashboard = ({ t }) => {
  const { user } = useAuth();
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState(null);
  const [qrCode, setQrCode] = useState('');
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('threats');
  const [filters, setFilters] = useState({
    country: '',
    level: '',
    type: ''
  });

  useEffect(() => {
    loadThreats();
    loadStats();
    loadQrCode();
  }, [filters]);

  const loadThreats = async () => {
    try {
      const params = new URLSearchParams();
      if (filters.country) params.append('country', filters.country);
      if (filters.level) params.append('level', filters.level);
      if (filters.type) params.append('threat_type', filters.type);

      const response = await axios.get(`${API}/threats?${params}`);
      setThreats(response.data);
    } catch (error) {
      console.error('Error loading threats:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const response = await axios.get(`${API}/stats`);
      setStats(response.data);
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  const loadQrCode = async () => {
    try {
      const response = await axios.get(`${API}/qr-code`);
      setQrCode(response.data.qr_code);
    } catch (error) {
      console.error('Error loading QR code:', error);
    }
  };

  const getLevelColor = (level) => {
    switch (level) {
      case 'alto': return '#ff0000';
      case 'medio': return '#ff8800';
      case 'bajo': return '#00ff00';
      default: return '#ffffff';
    }
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'leak': return '💧';
      case 'malware': return '🦠';
      case 'hack': return '⚡';
      case 'vulnerability': return '🔓';
      default: return '⚠️';
    }
  };

  if (loading) {
    return (
      <div className="dashboard-container">
        <div className="loading-spinner">{t.loading}</div>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <div className="dashboard-tabs">
        <button 
          className={`tab-btn ${activeTab === 'threats' ? 'active' : ''}`}
          onClick={() => setActiveTab('threats')}
        >
          {t.threats}
        </button>
        <button 
          className={`tab-btn ${activeTab === 'stats' ? 'active' : ''}`}
          onClick={() => setActiveTab('stats')}
        >
          {t.statistics}
        </button>
        <button 
          className={`tab-btn ${activeTab === 'qr' ? 'active' : ''}`}
          onClick={() => setActiveTab('qr')}
        >
          {t.qrCode}
        </button>
        {user?.is_admin && (
          <button 
            className={`tab-btn ${activeTab === 'admin' ? 'active' : ''}`}
            onClick={() => setActiveTab('admin')}
          >
            {t.admin}
          </button>
        )}
      </div>

      {/* Tab de Amenazas */}
      {activeTab === 'threats' && (
        <div className="threats-section">
          <div className="filters-bar">
            <select 
              value={filters.level} 
              onChange={(e) => setFilters({...filters, level: e.target.value})}
              className="filter-select"
            >
              <option value="">{t.level}</option>
              <option value="alto">{t.high}</option>
              <option value="medio">{t.medium}</option>
              <option value="bajo">{t.low}</option>
            </select>
            
            <select 
              value={filters.type} 
              onChange={(e) => setFilters({...filters, type: e.target.value})}
              className="filter-select"
            >
              <option value="">{t.type}</option>
              <option value="leak">{t.leak}</option>
              <option value="malware">{t.malware}</option>
              <option value="hack">{t.hack}</option>
              <option value="vulnerability">{t.vulnerability}</option>
            </select>
            
            <input
              type="text"
              placeholder={t.country}
              value={filters.country}
              onChange={(e) => setFilters({...filters, country: e.target.value})}
              className="filter-input"
            />
          </div>

          {/* Vista Mobile (tabla) */}
          <div className="mobile-view">
            {threats.length === 0 ? (
              <p className="no-threats">{t.noThreats}</p>
            ) : (
              threats.map((threat) => (
                <div key={threat.id} className="threat-card-mobile">
                  <div className="threat-header">
                    <div className="threat-icon">{getTypeIcon(threat.threat_type)}</div>
                    <div className="threat-level" style={{color: getLevelColor(threat.level)}}>
                      {threat.level.toUpperCase()}
                    </div>
                    <div className="threat-country">{threat.country_code}</div>
                  </div>
                  <h3 className="threat-title">{threat.title}</h3>
                  <p className="threat-description">{threat.description}</p>
                  <div className="threat-meta">
                    <span className="threat-type">{threat.threat_type}</span>
                    <span className="threat-date">
                      {new Date(threat.created_at).toLocaleDateString()}
                    </span>
                  </div>
                  {threat.url && (
                    <a href={threat.url} target="_blank" rel="noopener noreferrer" className="threat-link">
                      Ver más
                    </a>
                  )}
                </div>
              ))
            )}
          </div>

          {/* Vista Desktop (lista) */}
          <div className="desktop-view">
            {threats.length === 0 ? (
              <p className="no-threats">{t.noThreats}</p>
            ) : (
              <div className="threats-table">
                <div className="table-header">
                  <div className="col-icon"></div>
                  <div className="col-title">{t.title}</div>
                  <div className="col-type">{t.type}</div>
                  <div className="col-level">{t.level}</div>
                  <div className="col-country">{t.country}</div>
                  <div className="col-date">Fecha</div>
                </div>
                {threats.map((threat) => (
                  <div key={threat.id} className="table-row">
                    <div className="col-icon">{getTypeIcon(threat.threat_type)}</div>
                    <div className="col-title">
                      <div className="threat-title-desktop">{threat.title}</div>
                      <div className="threat-description-desktop">{threat.description}</div>
                    </div>
                    <div className="col-type">{threat.threat_type}</div>
                    <div className="col-level" style={{color: getLevelColor(threat.level)}}>
                      {threat.level.toUpperCase()}
                    </div>
                    <div className="col-country">{threat.country_code}</div>
                    <div className="col-date">
                      {new Date(threat.created_at).toLocaleDateString()}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab de Estadísticas */}
      {activeTab === 'stats' && stats && (
        <div className="stats-section">
          <div className="stats-grid">
            <div className="stat-card">
              <h3>Total de Amenazas</h3>
              <div className="stat-number">{stats.total_threats}</div>
            </div>
            
            <div className="stat-card">
              <h3>Por Nivel</h3>
              <div className="stat-breakdown">
                {Object.entries(stats.by_level).map(([level, count]) => (
                  <div key={level} className="stat-item">
                    <span style={{color: getLevelColor(level)}}>
                      {level.toUpperCase()}: {count}
                    </span>
                  </div>
                ))}
              </div>
            </div>
            
            <div className="stat-card">
              <h3>Por Tipo</h3>
              <div className="stat-breakdown">
                {Object.entries(stats.by_type).map(([type, count]) => (
                  <div key={type} className="stat-item">
                    {getTypeIcon(type)} {type}: {count}
                  </div>
                ))}
              </div>
            </div>
            
            <div className="stat-card">
              <h3>Top Países</h3>
              <div className="stat-breakdown">
                {Object.entries(stats.by_country).map(([country, count]) => (
                  <div key={country} className="stat-item">
                    {country}: {count}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab de QR Code */}
      {activeTab === 'qr' && (
        <div className="qr-section">
          <div className="qr-container">
            <h3>Código QR para Acceso Rápido</h3>
            <div className="qr-code">
              <img src={qrCode} alt="QR Code" />
            </div>
            <p>Escanea este código para acceder rápidamente a WOLF</p>
          </div>
        </div>
      )}

      {/* Tab de Admin */}
      {activeTab === 'admin' && user?.is_admin && (
        <div className="admin-section">
          <h3>Panel de Administración</h3>
          <div className="admin-actions">
            <button className="admin-btn">{t.addThreat}</button>
            <button className="admin-btn">{t.uploadJson}</button>
            <label className="file-upload-btn">
              Subir JSON
              <input 
                type="file" 
                accept=".json" 
                style={{display: 'none'}}
                onChange={async (e) => {
                  const file = e.target.files[0];
                  if (file) {
                    const formData = new FormData();
                    formData.append('file', file);
                    try {
                      await axios.post(`${API}/threats/upload-json`, formData, {
                        headers: { 'Content-Type': 'multipart/form-data' }
                      });
                      alert('JSON subido exitosamente');
                      loadThreats();
                    } catch (error) {
                      alert('Error al subir JSON');
                    }
                  }
                }}
              />
            </label>
          </div>
        </div>
      )}
    </div>
  );
};

// App principal
function App() {
  const [language, setLanguage] = useState('es');
  const [authMode, setAuthMode] = useState('login'); // 'login', 'register', 'reset'

  // Detectar idioma por IP al cargar
  useEffect(() => {
    detectLanguage();
  }, []);

  const detectLanguage = async () => {
    try {
      const response = await axios.get(`${API}/detect-language`);
      if (response.data.language) {
        setLanguage(response.data.language);
      }
    } catch (error) {
      console.log('Could not detect language, using default');
    }
  };

  const t = useTranslation(language);

  return (
    <AuthProvider>
      <div className="App">
        <Header language={language} setLanguage={setLanguage} t={t} />
        
        <main className="main-content">
          <AuthConsumer 
            authMode={authMode} 
            setAuthMode={setAuthMode} 
            t={t} 
          />
        </main>
      </div>
    </AuthProvider>
  );
}

// Componente para consumir autenticación
const AuthConsumer = ({ authMode, setAuthMode, t }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return <div className="loading-screen">{t.loading}</div>;
  }

  if (!user) {
    switch (authMode) {
      case 'register':
        return (
          <RegisterForm 
            t={t} 
            onToggleForm={() => setAuthMode('login')} 
          />
        );
      case 'reset':
        return (
          <ResetPasswordForm 
            t={t} 
            onBackToLogin={() => setAuthMode('login')} 
          />
        );
      default:
        return (
          <LoginForm 
            t={t} 
            onToggleForm={() => setAuthMode('register')}
            onForgotPassword={() => setAuthMode('reset')}
          />
        );
    }
  }

  return <Dashboard t={t} />;
};

export default App;