package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type WebConfig struct {
	Port  uint16 `json:"port"`
	Addr  string `json:"addr"`
	Users []User `json:"users"`
}

var configs []WebConfig

type UserSession struct {
	SessionId string
	Name      string
	Expires   int64 // session过期时间
}

func Uuid() string {
	// 创建一个16字节的切片
	b := make([]byte, 16)

	// 从随机源中读取16字节
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error:", err)
		return ""
	}

	// 设置UUID版本和变体
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	// 将字节切片转换为UUID格式的字符串并打印
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

var login_html = `
<!DOCTYPE html>
<html>
<head>
	<title>login</title>
</head>
<body>
	<center>
		<form action="/login" method="POST">
			<input name="name" placeholder="username"><br>
			<input name="password" type="password" placeholder="password"><br>
			<button type="submit">Submit</button>
		</form>
	</center>
</body>
</html>
`

// 会话过期时间默认一个月
var SessionExpires = 30 * 24 * time.Hour
var sessions = make(map[string]*UserSession)

// 定时任务
func Job() {
	var dur = 1 * time.Hour
	t := time.NewTimer(dur)
	for {
		<-t.C
		t.Reset(dur)
		// 把超时的session踢出去
		for k, us := range sessions {
			if us.Expires < time.Now().Unix() {
				// session 超时
				delete(sessions, k)
			}
		}
	}
}

func RunProxy(cfg *WebConfig) {
	server_uuid := Uuid()
	user_pass_map := make(map[string]string)
	for _, user := range cfg.Users {
		user_pass_map[user.Name] = user.Password
	}
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// 修改请求目标URL
			target, _ := url.Parse(cfg.Addr)
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
		},
	}

	// 启动代理服务器
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			if r.Method == "GET" {
				// 获取登录页
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, login_html)
			} else if r.Method == "POST" {
				// 登录请求
				name := r.PostFormValue("name")
				password := r.PostFormValue("password")
				if hashedPassword, ok := user_pass_map[name]; ok {
					if Verify(hashedPassword, password) {
						// 登录成功
						var httpp_session_id = Uuid()
						// 会话过期时间
						var expires = time.Now().Add(SessionExpires)
						sessions[httpp_session_id] = &UserSession{
							SessionId: httpp_session_id,
							Name:      name,
							Expires:   expires.Unix(),
						}
						cookie_httpp_session_id := http.Cookie{Name: server_uuid, Value: httpp_session_id, Expires: expires}
						http.SetCookie(w, &cookie_httpp_session_id)
						http.Redirect(w, r, "/", http.StatusSeeOther)
					} else {
						http.Redirect(w, r, "/login", http.StatusSeeOther)
					}
				} else {
					// 用户名不存在
					http.Redirect(w, r, "/login", http.StatusSeeOther)
				}

			} else {
				// 不知道
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
		}
		// 检查cookie
		cookie, err := r.Cookie(server_uuid)
		if err != nil {
			// 没登录
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		httpp_session_id := cookie.Value
		if session, ok := sessions[httpp_session_id]; ok {
			// 校验session是否过期
			if session.Expires < time.Now().Unix() {
				// 会话过期
				delete(sessions, httpp_session_id)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			} else {
				proxy.ServeHTTP(w, r)
			}
		} else {
			// 会话不存在
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	})

	fmt.Printf("Listen in %d to %s\n", cfg.Port, cfg.Addr)
	http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), nil)
}

func Verify(hashedPassword string, enteredPassword string) bool {
	// 验证密码
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(enteredPassword))
	if err == nil {
		return true
	} else {
		return false
	}
}

func Genpass(passwd string) string {
	// 生成哈希密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(passwd), bcrypt.DefaultCost)
	if err != nil {
		return ""
	}
	return string(hashedPassword)
}

func main() {
	genpass := flag.Bool("genpass", false, "Whether to encrypt the password")
	passwd := flag.String("password", "password", "Password to be encrypted")
	config := flag.String("config", "config.json", "Profile Address")
	flag.Parse()
	if *genpass {
		// 生成密码加密
		p := Genpass(*passwd)
		fmt.Println(p)
		return
	}

	go Job()

	f, err := os.Open(*config)
	if err != nil {
		panic(err)
	}
	bf, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}
	f.Close()
	if err = json.Unmarshal(bf, &configs); err != nil {
		panic(err)
	}
	// 创建一个代理服务器
	for _, cfg := range configs {
		go RunProxy(&cfg)
	}
	// 创建一个通道来接收信号
	sigChan := make(chan os.Signal, 1)
	// 告诉通道捕获SIGINT信号（Ctrl+C）
	signal.Notify(sigChan, os.Interrupt, syscall.SIGINT)
	<-sigChan
}
