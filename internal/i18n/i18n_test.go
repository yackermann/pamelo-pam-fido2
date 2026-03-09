package i18n

import "testing"

func TestResolveLanguageFromConfig(t *testing.T) {
	if got := ResolveLanguage("fr", "en_US.UTF-8"); got != "fr" {
		t.Fatalf("expected fr, got %s", got)
	}
}

func TestResolveLanguageAutoFromEnv(t *testing.T) {
	if got := ResolveLanguage("auto", "es_NZ.UTF-8"); got != "es" {
		t.Fatalf("expected es, got %s", got)
	}
}

func TestResolveLanguageFallbackToEnglish(t *testing.T) {
	if got := ResolveLanguage("auto", "pt_BR.UTF-8"); got != "en" {
		t.Fatalf("expected en fallback, got %s", got)
	}
}

func TestNormalizeLanguage(t *testing.T) {
	tests := map[string]string{
		"EN_us.UTF-8": "en",
		"es-MX":       "es",
		"fr_FR":       "fr",
		"de":          "de",
		"ja_JP":       "ja",
		"zh-Hans-CN":  "zh",
		"unknown":     "",
	}
	for in, expected := range tests {
		if got := NormalizeLanguage(in); got != expected {
			t.Fatalf("NormalizeLanguage(%q) expected %q, got %q", in, expected, got)
		}
	}
}

func TestIsSupportedLanguage(t *testing.T) {
	if !IsSupportedLanguage("auto") {
		t.Fatalf("auto should be supported")
	}
	if !IsSupportedLanguage("zh_CN") {
		t.Fatalf("zh_CN should be supported")
	}
	if IsSupportedLanguage("pt") {
		t.Fatalf("pt should not be supported")
	}
}

func TestLocalizerFallback(t *testing.T) {
	l := New("pt")
	if got := l.S(MsgAuthenticationSucceeded); got != "Authentication succeeded" {
		t.Fatalf("expected english fallback, got %q", got)
	}
}

func TestLocalizedMessageFormat(t *testing.T) {
	l := New("de")
	got := l.S(MsgTouchSecurityKey, "|")
	expected := "Beruehren Sie Ihren Sicherheitsschluessel, um fortzufahren [|]"
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}
