package helpers

import (
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func GenerateNewAccessToken(username string) (string, error) {
	secret := os.Getenv("JWT_SECRET_KEY")
	minutesCount, _ := strconv.Atoi(os.Getenv("JWT_SECRET_KEY_EXPIRE_MINUTES_COUNT"))

	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["name"] = username
	claims["exp"] = time.Now().Add(time.Minute * time.Duration(minutesCount)).Unix()
	// claims["exp"] = time.Now().Add(time.Hour * 24).Unix() //1 day

	t, err := token.SignedString([]byte(secret))

	if err != nil {
		panic(err)
	}
	return t, nil
}
