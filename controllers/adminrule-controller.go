package controllers

import (
	"fmt"
	"time"

	"bitbucket.org/isbtotogroup/devops_master_api/entities"
	"bitbucket.org/isbtotogroup/devops_master_api/helpers"
	"bitbucket.org/isbtotogroup/devops_master_api/models"
	"github.com/buger/jsonparser"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

const Fieldadminrule_home_redis = "MASTER:BACKEND:LISTADMINRULE"

func Adminrulehome(c *fiber.Ctx) error {

	var obj entities.Responseredis_adminruleall
	var arraobj []entities.Responseredis_adminruleall
	render_page := time.Now()
	resultredis, flag := helpers.GetRedis(Fieldadminrule_home_redis)
	jsonredis := []byte(resultredis)
	record_RD, _, _, _ := jsonparser.Get(jsonredis, "record")
	jsonparser.ArrayEach(record_RD, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		Adminrule_idadmin, _ := jsonparser.GetString(value, "adminrule_idadmin")
		Adminrule_rule, _ := jsonparser.GetString(value, "adminrule_rule")

		obj.Adminrule_idadmin = Adminrule_idadmin
		obj.Adminrule_rule = Adminrule_rule
		arraobj = append(arraobj, obj)
	})

	if !flag {
		result, err := models.Fetch_adminruleHome()
		if err != nil {
			c.Status(fiber.StatusBadRequest)
			return c.JSON(fiber.Map{
				"status":  fiber.StatusBadRequest,
				"message": err.Error(),
				"record":  nil,
			})
		}
		helpers.SetRedis(Fieldadminrule_home_redis, result, 60*time.Minute)
		fmt.Println("ADMIN RULE MYSQL")
		return c.JSON(result)
	} else {
		fmt.Println("ADMIN RULE CACHE")
		return c.JSON(fiber.Map{
			"status":  fiber.StatusOK,
			"message": "Success",
			"record":  arraobj,
			"time":    time.Since(render_page).String(),
		})
	}
}

func AdminruleSave(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_adminrulesave)
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
	user := c.Locals("jwt").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	name := claims["name"].(string)
	temp_decp := helpers.Decryption(name)
	client_admin, _ := helpers.Parsing_Decry(temp_decp, "==")

	result, err := models.Save_adminrule(client_admin, client.Idadmin, client.Rule, client.Sdata)
	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": err.Error(),
			"record":  nil,
		})
	}

	_deleteredis_adminrule()
	return c.JSON(result)
}

func _deleteredis_adminrule() {
	val_master := helpers.DeleteRedis(Fieldadminrule_home_redis)
	fmt.Printf("Redis Delete BACKEND ADMIN RULE : %d", val_master)

}
