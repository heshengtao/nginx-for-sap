package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mojocn/base64Captcha" // 引入验证码库
)

// --- 配置与状态 ---
var (
	dataDir    = "/data"
	authFile   = dataDir + "/auth.json"
	jwtSecret  = []byte(os.Getenv("JWT_SECRET"))
	initUser   = os.Getenv("INIT_USER")
	initPass   = os.Getenv("INIT_PASS")
	forceReset = os.Getenv("FORCE_RESET") == "true"
	store      UserStore
	mu         sync.Mutex

	// 初始化验证码存储（默认使用内存存储，自带过期清理机制）
	captchaStore = base64Captcha.DefaultMemStore
)

// --- 数据结构 ---

type APIKey struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Key       string `json:"key"`
	CreatedAt int64  `json:"created_at"`
}

type UserData struct {
	Username       string            `json:"username"`
	Password       string            `json:"password"`
	MustChangePass bool              `json:"must_change_pass"`
	APIKeys        map[string]APIKey `json:"api_keys"`
}

type UserStore struct {
	User UserData `json:"user"`
}

type Credentials struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	NewPass     string `json:"new_password,omitempty"`
	// 新增验证码字段
	CaptchaID   string `json:"captcha_id"`
	CaptchaCode string `json:"captcha_code"`
}

type KeyRequest struct {
	Name string `json:"name"`
	ID   string `json:"id,omitempty"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// --- 初始化 ---
func init() {
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("default-secret-please-change")
	}
	if initUser == "" {
		initUser = "root"
	}
	if initPass == "" {
		initPass = "pass"
	}
}

func loadData() {
	mu.Lock()
	defer mu.Unlock()

	if forceReset {
		log.Println("Force reset detected.")
		resetStore()
		saveDataLocked()
		return
	}

	file, err := os.ReadFile(authFile)
	if err != nil {
		log.Println("Auth file not found, creating default.")
		resetStore()
		saveDataLocked()
	} else {
		json.Unmarshal(file, &store)
		if store.User.APIKeys == nil {
			store.User.APIKeys = make(map[string]APIKey)
		}
	}
}

func resetStore() {
	store.User = UserData{
		Username:       initUser,
		Password:       initPass,
		MustChangePass: true,
		APIKeys:        make(map[string]APIKey),
	}
}

func saveDataLocked() {
	data, _ := json.MarshalIndent(store, "", "  ")
	os.WriteFile(authFile, data, 0644)
}

// --- 辅助函数 ---

func generateRandomKey() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "sk-sap-error"
	}
	return "sk-sap-" + hex.EncodeToString(bytes)
}

func generateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func validateCookie(r *http.Request) bool {
	cookie, err := r.Cookie("sap_token")
	if err != nil {
		return false
	}
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !tkn.Valid {
		return false
	}
	return true
}

// --- Handlers ---

// 新增：生成验证码接口
func captchaHandler(w http.ResponseWriter, r *http.Request) {
	// 配置验证码参数：高, 宽, 长度, 干扰强度, 噪点数
	// 这里使用数字驱动，生成的图片比较清晰且适合内网
	driver := base64Captcha.NewDriverDigit(80, 240, 6, 0.7, 80)
	
	// 创建验证码实例
	c := base64Captcha.NewCaptcha(driver, captchaStore)
	
	// 生成 ID 和 Base64 图片字符串
	id, b64s, _, err := c.Generate()
	if err != nil {
		http.Error(w, "Captcha generation error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// 返回给前端：前端需要存下 captcha_id 并在登录时带回
	json.NewEncoder(w).Encode(map[string]string{
		"captcha_id":   id,
		"image_base64": b64s,
	})
}

func validateHandler(w *http.ResponseWriter, r *http.Request) {
	tokenString := ""

	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
	}

	if tokenString == "" {
		cookie, err := r.Cookie("sap_token")
		if err == nil {
			tokenString = cookie.Value
		}
	}

	if tokenString == "" {
		http.Error(*w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mu.Lock()
	user := store.User
	mu.Unlock()

	// 检查 API Key
	if strings.HasPrefix(tokenString, "sk-sap-") {
		validKey := false
		for _, k := range user.APIKeys {
			if k.Key == tokenString {
				validKey = true
				break
			}
		}
		if validKey {
			(*w).WriteHeader(http.StatusOK)
			return
		}
		http.Error(*w, "Invalid API Key", http.StatusUnauthorized)
		return
	}

	// 检查 JWT
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !tkn.Valid {
		http.Error(*w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if user.MustChangePass {
		originalURI := r.Header.Get("X-Original-URI")
		if !strings.HasPrefix(originalURI, "/api/auth/change-password") &&
			!strings.HasPrefix(originalURI, "/static/") &&
			!strings.Contains(originalURI, "login.html") {
			http.Error(*w, "Password Change Required", http.StatusForbidden)
			return
		}
	}

	(*w).WriteHeader(http.StatusOK)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	// 使用 JSON Decoder 解析 Body
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// ★ 修改点：验证码校验逻辑
	// Verify 参数：id, answer, clear
	// clear=true 表示验证后立即删除该ID，防止重放攻击
	if !captchaStore.Verify(creds.CaptchaID, creds.CaptchaCode, true) {
		w.WriteHeader(http.StatusBadRequest)
		// 返回特定 JSON 错误，以便前端识别刷新验证码
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_captcha"})
		return
	}

	mu.Lock()
	user := store.User
	mu.Unlock()

	if creds.Username != user.Username || creds.Password != user.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, _ := generateJWT(user.Username)

	http.SetCookie(w, &http.Cookie{
		Name:    "sap_token",
		Value:   token,
		Path:    "/",
		Expires: time.Now().Add(24 * time.Hour),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":            token,
		"must_change_pass": user.MustChangePass,
	})
}

func changePassHandler(w http.ResponseWriter, r *http.Request) {
	if !validateCookie(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var creds Credentials
	json.NewDecoder(r.Body).Decode(&creds)

	if creds.NewPass == "" {
		http.Error(w, "Empty password", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	store.User.Password = creds.NewPass
	store.User.MustChangePass = false
	saveDataLocked()

	w.Write([]byte(`{"status":"ok"}`))
}

func listKeysHandler(w http.ResponseWriter, r *http.Request) {
	if !validateCookie(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mu.Lock()
	keys := make([]APIKey, 0, len(store.User.APIKeys))
	for _, k := range store.User.APIKeys {
		keys = append(keys, k)
	}
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

func createKeyHandler(w http.ResponseWriter, r *http.Request) {
	if !validateCookie(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req KeyRequest
	json.NewDecoder(r.Body).Decode(&req)
	if req.Name == "" {
		req.Name = "Unnamed Key"
	}

	newKeyStr := generateRandomKey()
	id := fmt.Sprintf("%d", time.Now().UnixNano())

	newAPIKey := APIKey{
		ID:        id,
		Name:      req.Name,
		Key:       newKeyStr,
		CreatedAt: time.Now().Unix(),
	}

	mu.Lock()
	if store.User.APIKeys == nil {
		store.User.APIKeys = make(map[string]APIKey)
	}
	store.User.APIKeys[id] = newAPIKey
	saveDataLocked()
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newAPIKey)
}

func deleteKeyHandler(w http.ResponseWriter, r *http.Request) {
	if !validateCookie(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req KeyRequest
	json.NewDecoder(r.Body).Decode(&req)

	mu.Lock()
	delete(store.User.APIKeys, req.ID)
	saveDataLocked()
	mu.Unlock()

	w.Write([]byte(`{"status":"ok"}`))
}

func main() {
	loadData()

	http.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		validateHandler(&w, r)
	})

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/captcha", captchaHandler) // 注册验证码路由
	http.HandleFunc("/change-password", changePassHandler)

	http.HandleFunc("/keys/list", listKeysHandler)
	http.HandleFunc("/keys/create", createKeyHandler)
	http.HandleFunc("/keys/delete", deleteKeyHandler)

	log.Println("Auth server v2 running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}