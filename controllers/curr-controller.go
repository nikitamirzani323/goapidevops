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

const Fieldcurr_home_redis = "MASTER:BACKEND:LISTCURR"
const Fieldcurr_home_client_redis = "CLIENT:LISTCURR"

func Currhome(c *fiber.Ctx) error {
	var obj entities.Model_curr
	var arraobj []entities.Model_curr
	render_page := time.Now()
	resultredis, flag := helpers.GetRedis(Fieldcurr_home_redis)
	jsonredis := []byte(resultredis)
	record_RD, _, _, _ := jsonparser.Get(jsonredis, "record")
	jsonparser.ArrayEach(record_RD, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		curr_id, _ := jsonparser.GetString(value, "curr_id")
		curr_name, _ := jsonparser.GetString(value, "curr_name")
		curr_create, _ := jsonparser.GetString(value, "curr_create")
		curr_update, _ := jsonparser.GetString(value, "curr_update")

		obj.Curr_id = curr_id
		obj.Curr_name = curr_name
		obj.Curr_create = curr_create
		obj.Curr_update = curr_update
		arraobj = append(arraobj, obj)
	})

	if !flag {
		result, err := models.Fetch_currHome()
		if err != nil {
			c.Status(fiber.StatusBadRequest)
			return c.JSON(fiber.Map{
				"status":  fiber.StatusBadRequest,
				"message": err.Error(),
				"record":  nil,
			})
		}
		helpers.SetRedis(Fieldcurr_home_redis, result, 60*time.Minute)
		fmt.Println("CURR MYSQL")
		return c.JSON(result)
	} else {
		fmt.Println("CURR CACHE")
		return c.JSON(fiber.Map{
			"status":  fiber.StatusOK,
			"message": "Success",
			"record":  arraobj,
			"time":    time.Since(render_page).String(),
		})
	}
}
func CurrSave(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_currsave)
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

	// admin, idrecord, name, sData string
	result, err := models.Save_curr(
		client_admin,
		client.Curr_id, client.Curr_name, client.Sdata)
	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": err.Error(),
			"record":  nil,
		})
	}

	_deleteredis_curr()
	return c.JSON(result)
}
func _deleteredis_curr() {
	val_master := helpers.DeleteRedis(Fieldcurr_home_redis)
	fmt.Printf("Redis Delete BACKEND CURR : %d", val_master)

	val_client := helpers.DeleteRedis(Fieldcurr_home_client_redis)
	fmt.Printf("Redis Delete CLIENT CURR : %d", val_client)

}
