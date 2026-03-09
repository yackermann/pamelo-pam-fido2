package i18n

import (
	"fmt"
	"strings"
)

type MessageID string

const (
	MsgContactingServer            MessageID = "contacting_server"
	MsgPreparingAssertion          MessageID = "preparing_assertion"
	MsgAssertionFailed             MessageID = "assertion_failed"
	MsgVerifyingWithServer         MessageID = "verifying_with_server"
	MsgDeniedByServer              MessageID = "denied_by_server"
	MsgAuthenticationSucceeded     MessageID = "authentication_succeeded"
	MsgSkipContinuityMissingFields MessageID = "skip_continuity_missing_fields"
	MsgPersistContinuityFailed     MessageID = "persist_continuity_failed"
	MsgServerUnavailable           MessageID = "server_unavailable"
	MsgTryingOfflineContinuity     MessageID = "trying_offline_continuity"
	MsgOfflineContinuityFailed     MessageID = "offline_continuity_failed"
	MsgOfflineContinuitySucceeded  MessageID = "offline_continuity_succeeded"
	MsgTouchSecurityKey            MessageID = "touch_security_key"
	MsgUsingFIDO2Device            MessageID = "using_fido2_device"
	MsgConfigLoadFailed            MessageID = "config_load_failed"
	MsgUnableReadPAMUser           MessageID = "unable_read_pam_user"
	MsgUnableReadPAMService        MessageID = "unable_read_pam_service"
	MsgUnableInitServerClient      MessageID = "unable_init_server_client"
	MsgAuthenticationFailedDebug   MessageID = "authentication_failed_debug"
)

var catalogs = map[string]map[MessageID]string{
	"en": {
		MsgContactingServer:            "Contacting authentication server...",
		MsgPreparingAssertion:          "Preparing FIDO2 assertion...",
		MsgAssertionFailed:             "FIDO2 assertion failed",
		MsgVerifyingWithServer:         "Verifying assertion with authentication server...",
		MsgDeniedByServer:              "Authentication denied by server",
		MsgAuthenticationSucceeded:     "Authentication succeeded",
		MsgSkipContinuityMissingFields: "Skipping continuity state update: missing fields",
		MsgPersistContinuityFailed:     "Failed to persist continuity state: %v",
		MsgServerUnavailable:           "Authentication server unavailable",
		MsgTryingOfflineContinuity:     "Trying offline continuity verification...",
		MsgOfflineContinuityFailed:     "Offline continuity verification failed",
		MsgOfflineContinuitySucceeded:  "Offline continuity verification succeeded",
		MsgTouchSecurityKey:            "Touch your security key to continue [%s]",
		MsgUsingFIDO2Device:            "Using FIDO2 device: %s",
		MsgConfigLoadFailed:            "pamelo-pam-fido2: failed to load config %s: %v",
		MsgUnableReadPAMUser:           "Unable to read PAM username",
		MsgUnableReadPAMService:        "Unable to read PAM service name",
		MsgUnableInitServerClient:      "Unable to initialize authentication server client",
		MsgAuthenticationFailedDebug:   "authentication failed: %v",
	},
	"es": {
		MsgContactingServer:            "Contactando al servidor de autenticacion...",
		MsgPreparingAssertion:          "Preparando la verificacion FIDO2...",
		MsgAssertionFailed:             "La verificacion FIDO2 fallo",
		MsgVerifyingWithServer:         "Verificando la respuesta con el servidor de autenticacion...",
		MsgDeniedByServer:              "Autenticacion denegada por el servidor",
		MsgAuthenticationSucceeded:     "Autenticacion correcta",
		MsgSkipContinuityMissingFields: "Se omite la actualizacion del estado de continuidad: faltan campos",
		MsgPersistContinuityFailed:     "No se pudo guardar el estado de continuidad: %v",
		MsgServerUnavailable:           "Servidor de autenticacion no disponible",
		MsgTryingOfflineContinuity:     "Intentando verificacion de continuidad sin conexion...",
		MsgOfflineContinuityFailed:     "La verificacion de continuidad sin conexion fallo",
		MsgOfflineContinuitySucceeded:  "La verificacion de continuidad sin conexion fue correcta",
		MsgTouchSecurityKey:            "Toque su llave de seguridad para continuar [%s]",
		MsgUsingFIDO2Device:            "Usando dispositivo FIDO2: %s",
		MsgConfigLoadFailed:            "pamelo-pam-fido2: no se pudo cargar la configuracion %s: %v",
		MsgUnableReadPAMUser:           "No se pudo leer el usuario de PAM",
		MsgUnableReadPAMService:        "No se pudo leer el servicio PAM",
		MsgUnableInitServerClient:      "No se pudo inicializar el cliente del servidor de autenticacion",
		MsgAuthenticationFailedDebug:   "autenticacion fallida: %v",
	},
	"fr": {
		MsgContactingServer:            "Contact du serveur d'authentification...",
		MsgPreparingAssertion:          "Preparation de l'assertion FIDO2...",
		MsgAssertionFailed:             "Echec de l'assertion FIDO2",
		MsgVerifyingWithServer:         "Verification de l'assertion avec le serveur d'authentification...",
		MsgDeniedByServer:              "Authentification refusee par le serveur",
		MsgAuthenticationSucceeded:     "Authentification reussie",
		MsgSkipContinuityMissingFields: "Mise a jour de l'etat de continuite ignoree: champs manquants",
		MsgPersistContinuityFailed:     "Impossible d'enregistrer l'etat de continuite: %v",
		MsgServerUnavailable:           "Serveur d'authentification indisponible",
		MsgTryingOfflineContinuity:     "Tentative de verification de continuite hors ligne...",
		MsgOfflineContinuityFailed:     "Echec de la verification de continuite hors ligne",
		MsgOfflineContinuitySucceeded:  "Verification de continuite hors ligne reussie",
		MsgTouchSecurityKey:            "Touchez votre cle de securite pour continuer [%s]",
		MsgUsingFIDO2Device:            "Appareil FIDO2 utilise: %s",
		MsgConfigLoadFailed:            "pamelo-pam-fido2: echec du chargement de la configuration %s: %v",
		MsgUnableReadPAMUser:           "Impossible de lire l'utilisateur PAM",
		MsgUnableReadPAMService:        "Impossible de lire le service PAM",
		MsgUnableInitServerClient:      "Impossible d'initialiser le client du serveur d'authentification",
		MsgAuthenticationFailedDebug:   "authentification echouee: %v",
	},
	"de": {
		MsgContactingServer:            "Authentifizierungsserver wird kontaktiert...",
		MsgPreparingAssertion:          "FIDO2-Assertion wird vorbereitet...",
		MsgAssertionFailed:             "FIDO2-Assertion fehlgeschlagen",
		MsgVerifyingWithServer:         "Assertion wird mit dem Authentifizierungsserver verifiziert...",
		MsgDeniedByServer:              "Authentifizierung vom Server abgelehnt",
		MsgAuthenticationSucceeded:     "Authentifizierung erfolgreich",
		MsgSkipContinuityMissingFields: "Aktualisierung des Kontinuitaetsstatus uebersprungen: fehlende Felder",
		MsgPersistContinuityFailed:     "Kontinuitaetsstatus konnte nicht gespeichert werden: %v",
		MsgServerUnavailable:           "Authentifizierungsserver nicht verfuegbar",
		MsgTryingOfflineContinuity:     "Offline-Kontinuitaetspruefung wird versucht...",
		MsgOfflineContinuityFailed:     "Offline-Kontinuitaetspruefung fehlgeschlagen",
		MsgOfflineContinuitySucceeded:  "Offline-Kontinuitaetspruefung erfolgreich",
		MsgTouchSecurityKey:            "Beruehren Sie Ihren Sicherheitsschluessel, um fortzufahren [%s]",
		MsgUsingFIDO2Device:            "Verwendetes FIDO2-Geraet: %s",
		MsgConfigLoadFailed:            "pamelo-pam-fido2: Konfiguration %s konnte nicht geladen werden: %v",
		MsgUnableReadPAMUser:           "PAM-Benutzer konnte nicht gelesen werden",
		MsgUnableReadPAMService:        "PAM-Dienst konnte nicht gelesen werden",
		MsgUnableInitServerClient:      "Client fuer den Authentifizierungsserver konnte nicht initialisiert werden",
		MsgAuthenticationFailedDebug:   "authentifizierung fehlgeschlagen: %v",
	},
	"ja": {
		MsgContactingServer:            "認証サーバーに接続しています...",
		MsgPreparingAssertion:          "FIDO2アサーションを準備しています...",
		MsgAssertionFailed:             "FIDO2アサーションに失敗しました",
		MsgVerifyingWithServer:         "認証サーバーでアサーションを検証しています...",
		MsgDeniedByServer:              "サーバーによって認証が拒否されました",
		MsgAuthenticationSucceeded:     "認証に成功しました",
		MsgSkipContinuityMissingFields: "継続性状態の更新をスキップしました: 必須項目が不足しています",
		MsgPersistContinuityFailed:     "継続性状態を保存できませんでした: %v",
		MsgServerUnavailable:           "認証サーバーが利用できません",
		MsgTryingOfflineContinuity:     "オフライン継続性検証を試行しています...",
		MsgOfflineContinuityFailed:     "オフライン継続性検証に失敗しました",
		MsgOfflineContinuitySucceeded:  "オフライン継続性検証に成功しました",
		MsgTouchSecurityKey:            "続行するにはセキュリティキーにタッチしてください [%s]",
		MsgUsingFIDO2Device:            "使用中のFIDO2デバイス: %s",
		MsgConfigLoadFailed:            "pamelo-pam-fido2: 設定 %s の読み込みに失敗しました: %v",
		MsgUnableReadPAMUser:           "PAMユーザーを取得できません",
		MsgUnableReadPAMService:        "PAMサービス名を取得できません",
		MsgUnableInitServerClient:      "認証サーバークライアントを初期化できません",
		MsgAuthenticationFailedDebug:   "認証失敗: %v",
	},
	"zh": {
		MsgContactingServer:            "正在连接认证服务器...",
		MsgPreparingAssertion:          "正在准备 FIDO2 断言...",
		MsgAssertionFailed:             "FIDO2 断言失败",
		MsgVerifyingWithServer:         "正在向认证服务器验证断言...",
		MsgDeniedByServer:              "认证被服务器拒绝",
		MsgAuthenticationSucceeded:     "认证成功",
		MsgSkipContinuityMissingFields: "跳过连续性状态更新: 缺少字段",
		MsgPersistContinuityFailed:     "保存连续性状态失败: %v",
		MsgServerUnavailable:           "认证服务器不可用",
		MsgTryingOfflineContinuity:     "正在尝试离线连续性校验...",
		MsgOfflineContinuityFailed:     "离线连续性校验失败",
		MsgOfflineContinuitySucceeded:  "离线连续性校验成功",
		MsgTouchSecurityKey:            "请触碰安全密钥继续 [%s]",
		MsgUsingFIDO2Device:            "正在使用 FIDO2 设备: %s",
		MsgConfigLoadFailed:            "pamelo-pam-fido2: 加载配置 %s 失败: %v",
		MsgUnableReadPAMUser:           "无法读取 PAM 用户名",
		MsgUnableReadPAMService:        "无法读取 PAM 服务名",
		MsgUnableInitServerClient:      "无法初始化认证服务器客户端",
		MsgAuthenticationFailedDebug:   "认证失败: %v",
	},
}

type Localizer struct {
	lang string
}

func New(language string) *Localizer {
	resolved := NormalizeLanguage(language)
	if resolved == "" {
		resolved = "en"
	}
	return &Localizer{lang: resolved}
}

func (l *Localizer) Language() string {
	if l == nil || l.lang == "" {
		return "en"
	}
	return l.lang
}

func (l *Localizer) S(id MessageID, args ...any) string {
	lang := "en"
	if l != nil && l.lang != "" {
		lang = l.lang
	}
	template, ok := catalogs[lang][id]
	if !ok {
		template = catalogs["en"][id]
	}
	if len(args) == 0 {
		return template
	}
	return fmt.Sprintf(template, args...)
}

func SupportedLanguages() []string {
	return []string{"en", "es", "fr", "de", "ja", "zh"}
}

func IsSupportedLanguage(language string) bool {
	if strings.EqualFold(strings.TrimSpace(language), "auto") {
		return true
	}
	normalized := NormalizeLanguage(language)
	if normalized == "" {
		return false
	}
	_, ok := catalogs[normalized]
	return ok
}

func ResolveLanguage(configLanguage, envLanguage string) string {
	configLanguage = strings.TrimSpace(configLanguage)
	if configLanguage == "" || strings.EqualFold(configLanguage, "auto") {
		if normalized := NormalizeLanguage(envLanguage); normalized != "" {
			return normalized
		}
		return "en"
	}
	if normalized := NormalizeLanguage(configLanguage); normalized != "" {
		return normalized
	}
	return "en"
}

func NormalizeLanguage(language string) string {
	normalized := strings.ToLower(strings.TrimSpace(language))
	if normalized == "" {
		return ""
	}
	if idx := strings.IndexAny(normalized, ".@"); idx > 0 {
		normalized = normalized[:idx]
	}
	normalized = strings.ReplaceAll(normalized, "_", "-")

	switch {
	case normalized == "en" || strings.HasPrefix(normalized, "en-"):
		return "en"
	case normalized == "es" || strings.HasPrefix(normalized, "es-"):
		return "es"
	case normalized == "fr" || strings.HasPrefix(normalized, "fr-"):
		return "fr"
	case normalized == "de" || strings.HasPrefix(normalized, "de-"):
		return "de"
	case normalized == "ja" || strings.HasPrefix(normalized, "ja-"):
		return "ja"
	case normalized == "zh" || strings.HasPrefix(normalized, "zh-"):
		return "zh"
	default:
		return ""
	}
}
