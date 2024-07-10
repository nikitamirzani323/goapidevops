package controllers

import (
	"log"
	"time"

	"bitbucket.org/isbtotogroup/devops_master_api/entities"
	"bitbucket.org/isbtotogroup/devops_master_api/helpers"
	"bitbucket.org/isbtotogroup/devops_master_api/models"
	"github.com/buger/jsonparser"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

const Fieldadmin_home_redis = "MASTER:BACKEND:LISTADMIN"

func Adminhome(c *fiber.Ctx) error {
	var obj entities.Responseredis_adminhome
	var arraobj []entities.Responseredis_adminhome
	var obj_listruleadmin entities.Responseredis_adminrule
	var arraobj_listruleadmin []entities.Responseredis_adminrule
	render_page := time.Now()
	resultredis, flag := helpers.GetRedis(Fieldadmin_home_redis)
	jsonredis := []byte(resultredis)
	record_RD, _, _, _ := jsonparser.Get(jsonredis, "record")
	listruleadmin_RD, _, _, _ := jsonparser.Get(jsonredis, "listruleadmin")
	jsonparser.ArrayEach(record_RD, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		admin_username, _ := jsonparser.GetString(value, "admin_username")
		admin_nama, _ := jsonparser.GetString(value, "admin_nama")
		admin_rule, _ := jsonparser.GetString(value, "admin_rule")
		admin_joindate, _ := jsonparser.GetString(value, "admin_joindate")
		admin_lastlogin, _ := jsonparser.GetString(value, "admin_lastlogin")
		admin_lastipaddres, _ := jsonparser.GetString(value, "admin_lastipaddres")
		admin_status, _ := jsonparser.GetString(value, "admin_status")

		obj.Admin_username = admin_username
		obj.Admin_nama = admin_nama
		obj.Admin_rule = admin_rule
		obj.Admin_joindate = admin_joindate
		obj.Admin_lastlogin = admin_lastlogin
		obj.Admin_lastipaddres = admin_lastipaddres
		obj.Admin_status = admin_status
		arraobj = append(arraobj, obj)
	})
	jsonparser.ArrayEach(listruleadmin_RD, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		adminrule_name, _ := jsonparser.GetString(value, "adminrule_idruleadmin")

		obj_listruleadmin.Adminrule_idrule = adminrule_name
		arraobj_listruleadmin = append(arraobj_listruleadmin, obj_listruleadmin)
	})
	if !flag {
		result, err := models.Fetch_adminHome()
		if err != nil {
			c.Status(fiber.StatusBadRequest)
			return c.JSON(fiber.Map{
				"status":  fiber.StatusBadRequest,
				"message": err.Error(),
				"record":  nil,
			})
		}
		helpers.SetRedis(Fieldadmin_home_redis, result, 60*time.Minute)
		log.Println("ADMIN MYSQL")
		return c.JSON(result)
	} else {
		log.Println("ADMIN CACHE")
		return c.JSON(fiber.Map{
			"status":        fiber.StatusOK,
			"message":       "Success",
			"record":        arraobj,
			"listruleadmin": arraobj_listruleadmin,
			"time":          time.Since(render_page).String(),
		})
	}
}
func AdminDetail(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_admindetail)
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

	result, err := models.Fetch_adminDetail(client.Username)
	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": err.Error(),
			"record":  nil,
		})
	}
	return c.JSON(result)
}
func AdminSave(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_adminsave)
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

	result, err := models.Save_adminHome(
		client_admin,
		client.Username, client.Password, client.Nama,
		client.Rule, client.Status, client.Sdata)
	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": err.Error(),
			"record":  nil,
		})
	}

	_deleteredis_admin()
	return c.JSON(result)
}
func _deleteredis_admin() {
	val_master := helpers.DeleteRedis(Fieldadmin_home_redis)
	log.Printf("Redis Delete BACKEND ADMIN : %d", val_master)

}
