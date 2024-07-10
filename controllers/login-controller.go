package controllers

import (
	"log"
	"strconv"

	"bitbucket.org/isbtotogroup/devops_master_api/entities"
	"bitbucket.org/isbtotogroup/devops_master_api/helpers"
	"bitbucket.org/isbtotogroup/devops_master_api/models"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

func CheckLogin(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Login)
	validate := validator.New()
	if err := c.BodyParser(client); err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": err.Error(),
			"record":  nil,
		})
	}
	err := validate.Struct(client)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			var element helpers.ErrorResponse
			element.Field = err.StructField()
			element.Tag = err.Tag()
			errors = append(errors, &element)
		}
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": "validation",
			"record":  errors,
		})
	}

	result, ruleadmin, err := models.Login_Model(client.Username, client.Password, client.Ipaddress)

	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": err.Error(),
			"record":  nil,
		})
	}

	if !result {
		return c.Status(fiber.StatusUnauthorized).JSON(
			fiber.Map{
				"status":  fiber.StatusBadRequest,
				"message": "Username or Password Not Found",
			})

	} else {
		dataclient := client.Username + "==" + ruleadmin
		dataclient_encr, keymap := helpers.Encryption(dataclient)
		dataclient_encr_final := dataclient_encr + "|" + strconv.Itoa(keymap)
		t, err := helpers.GenerateNewAccessToken(dataclient_encr_final)
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		return c.JSON(fiber.Map{
			"status": fiber.StatusOK,
			"token":  t,
		})

	}
}
func Home(c *fiber.Ctx) error {
	client := new(entities.Home)
	if err := c.BodyParser(client); err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": err.Error(),
			"record":  nil,
		})
	}

	user := c.Locals("jwt").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	name := claims["name"].(string)
	temp_decp := helpers.Decryption(name)
	client_username, idruleadmin := helpers.Parsing_Decry(temp_decp, "==")
	log.Println(client_username)
	log.Println(idruleadmin)
	log.Println(client.Page)

	ruleadmin := models.Get_AdminRule("ruleadmingroup", idruleadmin)
	flag := models.Get_listitemsearch(ruleadmin, ",", client.Page)
	if !flag {
		c.Status(fiber.StatusForbidden)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusForbidden,
			"message": "Anda tidak bisa akses halaman ini",
			"record":  nil,
		})
	} else {
		c.Status(fiber.StatusOK)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusOK,
			"message": "ADMIN",
			"record":  nil,
		})
	}
}
func CheckPublic(c *fiber.Ctx) error {
	result, ruleadmin, _ := models.Login_Model("root", "asdQWE123!@#!@#", "192.168.1.5")

	return c.JSON(fiber.Map{
		"status":  fiber.StatusOK,
		"command": result,
		"rule":    ruleadmin,
	})
}
