package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gomodule/redigo/redis"
)

var pool *redis.Pool

func init() {
	pool = &redis.Pool{
		MaxIdle:     10,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", "0.0.0.0:6379")
		},
	}
}

func main() {
	//Conn := pool.Get()
	//fmt.Println(Conn.Do("DEL", "user"))

	http.HandleFunc("/client/welcome", Welcome)
	http.HandleFunc("/client/register", Register)
	http.HandleFunc("/client/login", Login)
	if err := http.ListenAndServe("localhost:8081", nil); err != nil {
		log.Fatal("Shutting down the application")
		os.Exit(1)
	}
}

var jwtKey = []byte("my_secret_key")

// Location struct defines the location of a player
type Location struct {
	Name        string `json:"name"`
	Coordinates string `json:"coordinates"`
}

// Player struct defines the player details
type Player struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims struct will be encoded to a JWT.
// We add jwt.StandardClaims as an embedded type, to provide fields like expiry time
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

//Register function is used to register the player
func Register(w http.ResponseWriter, req *http.Request) {
	var p Player
	err := json.NewDecoder(req.Body).Decode(&p)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	// store the data in the database
	conn := pool.Get()
	_, err = conn.Do("SET", p.Username, p.Password)
	if err != nil {
		io.WriteString(w, "Registration Failed, Please try again")
		return
	}
	w.WriteHeader(http.StatusOK)
}

//Login function is used to login a player who is registered
func Login(w http.ResponseWriter, req *http.Request) {
	var p Player
	err := json.NewDecoder(req.Body).Decode(&p)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	// get the userdata from database if not register the user
	conn := pool.Get()
	reply, err := conn.Do("GET", p.Username)
	if err != nil {
		io.WriteString(w, "user doesn't exist")
	}
	var y []uint8
	x, ok := reply.([]uint8)
	if ok {
		y = x
	}
	if p.Password != string(y) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: p.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "login sucessful")

}

// Welcome function
func Welcome(w http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenString := cookie.Value
	claims := &Claims{}
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	}
	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}
