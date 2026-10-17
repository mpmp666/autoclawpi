// Package sign menandatangani request userapi AutoClaw.
//
// Dari recon app AutoClaw 1.17.8: header X-Auth-Sign adalah
// md5(APP_ID & timestamp & APP_KEY), dengan APP_ID 100003.
package sign

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	appID  = "100003"
	appKey = "38d2391985e2369a5fb8227d8e6cd5e5"
)

// Sign menghitung X-Auth-Sign untuk timestamp tertentu (detik unix).
func Sign(ts int64) string {
	sum := md5.Sum([]byte(appID + "&" + strconv.FormatInt(ts, 10) + "&" + appKey))
	return hex.EncodeToString(sum[:])
}

// HeadersAt membangun header aplikasi standar userapi dengan timestamp tertentu.
// Gunakan ini bila timestamp body harus sama dengan header.
//
// X-Tm / X-Version bisa di-override lewat env (AUTOCLAW_X_TM / AUTOCLAW_X_VERSION):
// upstream bisa saja mengikat kode OAuth ke fingerprint platform/versi saat
// otorisasi diminta, jadi saat debug kita perlu bisa ganti tanpa build ulang.
func HeadersAt(ts int64) map[string]string {
	return map[string]string{
		"Content-Type":     "application/json",
		"Accept":           "*/*",
		"X-Product":        "autoclaw",
		"X-Version":        envOr("AUTOCLAW_X_VERSION", "1.17.9"),
		"X-Tm":             envOr("AUTOCLAW_X_TM", "linux"),
		"X-Auth-Appid":     appID,
		"X-Auth-TimeStamp": strconv.FormatInt(ts, 10),
		"X-Auth-Sign":      Sign(ts),
		"X-Trace-Id":       newUUID(),
	}
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// Headers membangun set header aplikasi standar userapi dengan timestamp sekarang.
func Headers() map[string]string {
	ts := time.Now().Unix()
	return map[string]string{
		"Content-Type":     "application/json",
		"Accept":           "*/*",
		"X-Product":        "autoclaw",
		"X-Version":        "1.17.9",
		"X-Tm":             "linux",
		"X-Auth-Appid":     appID,
		"X-Auth-TimeStamp": strconv.FormatInt(ts, 10),
		"X-Auth-Sign":      Sign(ts),
		"X-Trace-Id":       newUUID(),
	}
}

// UUID mengembalikan UUID v4 acak (stdlib only).
func UUID() string { return newUUID() }

// newUUID membuat UUID v4 acak (stdlib only).
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand tidak pernah gagal di Linux
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
