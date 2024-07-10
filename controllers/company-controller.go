package controllers

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"bitbucket.org/isbtotogroup/devops_master_api/entities"
	"bitbucket.org/isbtotogroup/devops_master_api/helpers"
	"bitbucket.org/isbtotogroup/devops_master_api/models"
	"github.com/buger/jsonparser"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

const Fieldcompany_home_redis = "MASTER:BACKEND:LISTCOMPANY"
const Fieldcompanyadmin_home_redis = "MASTER:BACKEND:LISTCOMPANYADMIN"
const Fieldcompanyadminrule_home_redis = "MASTER:BACKEND:LISTCOMPANYADMINRULE"
const Fieldcompanymoney_home_redis = "MASTER:BACKEND:LISTCOMPANYMONEY"
const Fieldcompanyconf_home_redis = "MASTER:BACKEND:LISTCOMPANYCONF"

func Companyhome(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_company)
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
	fmt.Println(client.Company_page)
	if client.Company_search != "" {
		val_pattern := helpers.DeleteRedis(Fieldcompany_home_redis + "_" + strconv.Itoa(client.Company_page) + "_" + client.Company_search)
		fmt.Printf("Redis Delete BACKEND COMPANY : %d", val_pattern)
	}

	var obj entities.Model_company
	var arraobj []entities.Model_company
	var objcurr entities.Model_currshare
	var arraobjcurr []entities.Model_currshare
	render_page := time.Now()
	resultredis, flag := helpers.GetRedis(Fieldcompany_home_redis)
	jsonredis := []byte(resultredis)
	record_RD, _, _, _ := jsonparser.Get(jsonredis, "record")
	listcurr_RD, _, _, _ := jsonparser.Get(jsonredis, "listcurr")
	jsonparser.ArrayEach(record_RD, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		company_id, _ := jsonparser.GetString(value, "company_id")
		company_startjoin, _ := jsonparser.GetString(value, "company_startjoin")
		company_endjoin, _ := jsonparser.GetString(value, "company_endjoin")
		company_idcurr, _ := jsonparser.GetString(value, "company_idcurr")
		company_name, _ := jsonparser.GetString(value, "company_name")
		company_owner, _ := jsonparser.GetString(value, "company_owner")
		company_phone1, _ := jsonparser.GetString(value, "company_phone1")
		company_phone2, _ := jsonparser.GetString(value, "company_phone2")
		company_email, _ := jsonparser.GetString(value, "company_email")
		company_minfee, _ := jsonparser.GetFloat(value, "company_minfee")
		company_url1, _ := jsonparser.GetString(value, "company_url1")
		company_url2, _ := jsonparser.GetString(value, "company_url2")
		company_status, _ := jsonparser.GetString(value, "company_status")
		company_status_css, _ := jsonparser.GetString(value, "company_status_css")
		company_create, _ := jsonparser.GetString(value, "company_create")
		company_update, _ := jsonparser.GetString(value, "company_update")

		obj.Company_id = company_id
		obj.Company_startjoin = company_startjoin
		obj.Company_endjoin = company_endjoin
		obj.Company_idcurr = company_idcurr
		obj.Company_name = company_name
		obj.Company_owner = company_owner
		obj.Company_email = company_email
		obj.Company_phone1 = company_phone1
		obj.Company_phone2 = company_phone2
		obj.Company_minfee = float64(company_minfee)
		obj.Company_url1 = company_url1
		obj.Company_url2 = company_url2
		obj.Company_status = company_status
		obj.Company_status_css = company_status_css
		obj.Company_create = company_create
		obj.Company_update = company_update
		arraobj = append(arraobj, obj)
	})
	jsonparser.ArrayEach(listcurr_RD, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		curr_id, _ := jsonparser.GetString(value, "curr_id")

		objcurr.Curr_id = curr_id
		arraobjcurr = append(arraobjcurr, objcurr)
	})
	if !flag {
		result, err := models.Fetch_companyHome(client.Company_search, client.Company_page)
		if err != nil {
			c.Status(fiber.StatusBadRequest)
			return c.JSON(fiber.Map{
				"status":  fiber.StatusBadRequest,
				"message": err.Error(),
				"record":  nil,
			})
		}
		helpers.SetRedis(Fieldcompany_home_redis+"_"+strconv.Itoa(client.Company_page)+"_"+client.Company_search, result, 60*time.Minute)
		fmt.Println("COMPANY DATABASE")
		return c.JSON(result)
	} else {
		fmt.Println("COMPANY CACHE")
		return c.JSON(fiber.Map{
			"status":   fiber.StatusOK,
			"message":  "Success",
			"record":   arraobj,
			"listcurr": arraobjcurr,
			"time":     time.Since(render_page).String(),
		})
	}
}
func Companyadminhome(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_companyadmin)
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

	var obj entities.Model_companyadmin
	var arraobj []entities.Model_companyadmin
	var objadminrule entities.Model_companyadminruleshare
	var arraobjadminrule []entities.Model_companyadminruleshare
	render_page := time.Now()
	resultredis, flag := helpers.GetRedis(Fieldcompanyadmin_home_redis + "_" + strings.ToLower(client.Companyadmin_idcompany))
	jsonredis := []byte(resultredis)
	record_RD, _, _, _ := jsonparser.Get(jsonredis, "record")
	listrule_RD, _, _, _ := jsonparser.Get(jsonredis, "listrule")
	jsonparser.ArrayEach(record_RD, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		companyadmin_id, _ := jsonparser.GetInt(value, "companyadmin_id")
		companyadmin_idrule, _ := jsonparser.GetInt(value, "companyadmin_idrule")
		companyadmin_idcompany, _ := jsonparser.GetString(value, "companyadmin_idcompany")
		companyadmin_nmrule, _ := jsonparser.GetString(value, "companyadmin_nmrule")
		companyadmin_username, _ := jsonparser.GetString(value, "companyadmin_username")
		companyadmin_name, _ := jsonparser.GetString(value, "companyadmin_name")
		companyadmin_status, _ := jsonparser.GetString(value, "companyadmin_status")
		companyadmin_status_css, _ := jsonparser.GetString(value, "companyadmin_status_css")
		companyadmin_create, _ := jsonparser.GetString(value, "companyadmin_create")
		companyadmin_update, _ := jsonparser.GetString(value, "companyadmin_update")

		obj.Companyadmin_id = int(companyadmin_id)
		obj.Companyadmin_idrule = int(companyadmin_idrule)
		obj.Companyadmin_idcompany = companyadmin_idcompany
		obj.Companyadmin_nmrule = companyadmin_nmrule
		obj.Companyadmin_username = companyadmin_username
		obj.Companyadmin_name = companyadmin_name
		obj.Companyadmin_status = companyadmin_status
		obj.Companyadmin_status_css = companyadmin_status_css
		obj.Companyadmin_create = companyadmin_create
		obj.Companyadmin_update = companyadmin_update
		arraobj = append(arraobj, obj)
	})
	jsonparser.ArrayEach(listrule_RD, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		companyadminrule_id, _ := jsonparser.GetInt(value, "companyadminrule_id")
		companyadminrule_name, _ := jsonparser.GetString(value, "companyadminrule_name")

		objadminrule.Companyadminrule_id = int(companyadminrule_id)
		objadminrule.Companyadminrule_name = companyadminrule_name
		arraobjadminrule = append(arraobjadminrule, objadminrule)
	})
	if !flag {
		result, err := models.Fetch_companyadminHome(client.Companyadmin_idcompany)
		if err != nil {
			c.Status(fiber.StatusBadRequest)
			return c.JSON(fiber.Map{
				"status":  fiber.StatusBadRequest,
				"message": err.Error(),
				"record":  nil,
			})
		}
		helpers.SetRedis(Fieldcompanyadmin_home_redis+"_"+strings.ToLower(client.Companyadmin_idcompany), result, 60*time.Minute)
		fmt.Println("COMPANY ADMIN DATABASE")
		return c.JSON(result)
	} else {
		fmt.Println("COMPANY ADMIN CACHE")
		return c.JSON(fiber.Map{
			"status":   fiber.StatusOK,
			"message":  "Success",
			"record":   arraobj,
			"listrule": arraobjadminrule,
			"time":     time.Since(render_page).String(),
		})
	}
}
func Companyadminrulehome(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_companyadmin)
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

	var obj entities.Model_companyadminrule
	var arraobj []entities.Model_companyadminrule
	render_page := time.Now()
	resultredis, flag := helpers.GetRedis(Fieldcompanyadminrule_home_redis + "_" + strings.ToLower(client.Companyadmin_idcompany))
	jsonredis := []byte(resultredis)
	record_RD, _, _, _ := jsonparser.Get(jsonredis, "record")
	jsonparser.ArrayEach(record_RD, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		companyadminrule_id, _ := jsonparser.GetInt(value, "companyadminrule_id")
		companyadminrule_nmruleadmin, _ := jsonparser.GetString(value, "companyadminrule_nmruleadmin")
		companyadminrule_ruleadmin, _ := jsonparser.GetString(value, "companyadminrule_ruleadmin")
		companyadminrule_create, _ := jsonparser.GetString(value, "companyadminrule_create")
		companyadminrule_update, _ := jsonparser.GetString(value, "companyadminrule_update")

		obj.Companyadminrule_id = int(companyadminrule_id)
		obj.Companyadminrule_nmruleadmin = companyadminrule_nmruleadmin
		obj.Companyadminrule_ruleadmin = companyadminrule_ruleadmin
		obj.Companyadminrule_create = companyadminrule_create
		obj.Companyadminrule_update = companyadminrule_update
		arraobj = append(arraobj, obj)
	})

	if !flag {
		result, err := models.Fetch_companyadminruleHome(client.Companyadmin_idcompany)
		if err != nil {
			c.Status(fiber.StatusBadRequest)
			return c.JSON(fiber.Map{
				"status":  fiber.StatusBadRequest,
				"message": err.Error(),
				"record":  nil,
			})
		}
		helpers.SetRedis(Fieldcompanyadminrule_home_redis+"_"+strings.ToLower(client.Companyadmin_idcompany), result, 60*time.Minute)
		fmt.Println("COMPANY ADMIN RULE DATABASE")
		return c.JSON(result)
	} else {
		fmt.Println("COMPANY ADMIN RULE CACHE")
		return c.JSON(fiber.Map{
			"status":  fiber.StatusOK,
			"message": "Success",
			"record":  arraobj,
			"time":    time.Since(render_page).String(),
		})
	}
}
func Companymoneyhome(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_companyadmin)
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

	var obj entities.Model_companymoney
	var arraobj []entities.Model_companymoney
	render_page := time.Now()
	resultredis, flag := helpers.GetRedis(Fieldcompanymoney_home_redis + "_" + strings.ToLower(client.Companyadmin_idcompany))
	jsonredis := []byte(resultredis)
	record_RD, _, _, _ := jsonparser.Get(jsonredis, "record")
	jsonparser.ArrayEach(record_RD, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		companymoney_id, _ := jsonparser.GetInt(value, "companymoney_id")
		companymoney_money, _ := jsonparser.GetInt(value, "companymoney_money")
		companymoney_create, _ := jsonparser.GetString(value, "companymoney_create")
		companymoney_update, _ := jsonparser.GetString(value, "companymoney_update")

		obj.Companymoney_id = int(companymoney_id)
		obj.Companymoney_money = int(companymoney_money)
		obj.Companymoney_create = companymoney_create
		obj.Companymoney_update = companymoney_update
		arraobj = append(arraobj, obj)
	})

	if !flag {
		result, err := models.Fetch_companymoneyHome(client.Companyadmin_idcompany)
		if err != nil {
			c.Status(fiber.StatusBadRequest)
			return c.JSON(fiber.Map{
				"status":  fiber.StatusBadRequest,
				"message": err.Error(),
				"record":  nil,
			})
		}
		helpers.SetRedis(Fieldcompanymoney_home_redis+"_"+strings.ToLower(client.Companyadmin_idcompany), result, 60*time.Minute)
		fmt.Println("COMPANY MONEY DATABASE")
		return c.JSON(result)
	} else {
		fmt.Println("COMPANY MONEY CACHE")
		return c.JSON(fiber.Map{
			"status":  fiber.StatusOK,
			"message": "Success",
			"record":  arraobj,
			"time":    time.Since(render_page).String(),
		})
	}
}
func Companyconfhome(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_companyadmin)
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

	var obj entities.Model_companyconf
	var arraobj []entities.Model_companyconf
	render_page := time.Now()
	resultredis, flag := helpers.GetRedis(Fieldcompanyconf_home_redis + "_" + strings.ToLower(client.Companyadmin_idcompany))
	jsonredis := []byte(resultredis)
	record_RD, _, _, _ := jsonparser.Get(jsonredis, "record")
	jsonparser.ArrayEach(record_RD, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		companyconf_id, _ := jsonparser.GetString(value, "companyconf_id")
		companyconf_2digit_30_time, _ := jsonparser.GetInt(value, "companyconf_2digit_30_time")
		companyconf_2digit_30_digit, _ := jsonparser.GetInt(value, "companyconf_2digit_30_digit")
		companyconf_2digit_30_minbet, _ := jsonparser.GetInt(value, "companyconf_2digit_30_minbet")
		companyconf_2digit_30_maxbet, _ := jsonparser.GetInt(value, "companyconf_2digit_30_maxbet")
		companyconf_2digit_30_win, _ := jsonparser.GetFloat(value, "companyconf_2digit_30_win")
		companyconf_2digit_30_win_redblack, _ := jsonparser.GetFloat(value, "companyconf_2digit_30_win_redblack")
		companyconf_2digit_30_win_line, _ := jsonparser.GetFloat(value, "companyconf_2digit_30_win_line")
		companyconf_2digit_30_win_zona, _ := jsonparser.GetFloat(value, "companyconf_2digit_30_win_zona")
		companyconf_2digit_30_win_jackpot, _ := jsonparser.GetFloat(value, "companyconf_2digit_30_win_jackpot")
		companyconf_2digit_30_status_redblack_line, _ := jsonparser.GetString(value, "companyconf_2digit_30_status_redblack_line")
		companyconf_2digit_30_status_redblack_line_css, _ := jsonparser.GetString(value, "companyconf_2digit_30_status_redblack_line_css")
		companyconf_2digit_30_operator, _ := jsonparser.GetString(value, "companyconf_2digit_30_operator")
		companyconf_2digit_30_operator_css, _ := jsonparser.GetString(value, "companyconf_2digit_30_operator_css")
		companyconf_2digit_30_maintenance, _ := jsonparser.GetString(value, "companyconf_2digit_30_maintenance")
		companyconf_2digit_30_maintenance_css, _ := jsonparser.GetString(value, "companyconf_2digit_30_maintenance_css")
		companyconf_2digit_30_status, _ := jsonparser.GetString(value, "companyconf_2digit_30_status")
		companyconf_2digit_30_status_css, _ := jsonparser.GetString(value, "companyconf_2digit_30_status_css")
		companyconf_create, _ := jsonparser.GetString(value, "companyconf_create")
		companyconf_update, _ := jsonparser.GetString(value, "companyconf_update")

		obj.Companyconf_id = companyconf_id
		obj.Companyconf_2digit_30_time = int(companyconf_2digit_30_time)
		obj.Companyconf_2digit_30_digit = int(companyconf_2digit_30_digit)
		obj.Companyconf_2digit_30_minbet = int(companyconf_2digit_30_minbet)
		obj.Companyconf_2digit_30_maxbet = int(companyconf_2digit_30_maxbet)
		obj.Companyconf_2digit_30_win = float64(companyconf_2digit_30_win)
		obj.Companyconf_2digit_30_win_redblack = float64(companyconf_2digit_30_win_redblack)
		obj.Companyconf_2digit_30_win_line = float64(companyconf_2digit_30_win_line)
		obj.Companyconf_2digit_30_win_zona = float64(companyconf_2digit_30_win_zona)
		obj.Companyconf_2digit_30_win_jackpot = float64(companyconf_2digit_30_win_jackpot)
		obj.Companyconf_2digit_30_status_redblack_line = companyconf_2digit_30_status_redblack_line
		obj.Companyconf_2digit_30_status_redblack_line_css = companyconf_2digit_30_status_redblack_line_css
		obj.Companyconf_2digit_30_operator = companyconf_2digit_30_operator
		obj.Companyconf_2digit_30_operator_css = companyconf_2digit_30_operator_css
		obj.Companyconf_2digit_30_maintenance = companyconf_2digit_30_maintenance
		obj.Companyconf_2digit_30_maintenance_css = companyconf_2digit_30_maintenance_css
		obj.Companyconf_2digit_30_status = companyconf_2digit_30_status
		obj.Companyconf_2digit_30_status_css = companyconf_2digit_30_status_css
		obj.Companyconf_create = companyconf_create
		obj.Companyconf_update = companyconf_update
		arraobj = append(arraobj, obj)
	})

	if !flag {
		result, err := models.Fetch_companyconfHome(client.Companyadmin_idcompany)
		if err != nil {
			c.Status(fiber.StatusBadRequest)
			return c.JSON(fiber.Map{
				"status":  fiber.StatusBadRequest,
				"message": err.Error(),
				"record":  nil,
			})
		}
		helpers.SetRedis(Fieldcompanyconf_home_redis+"_"+strings.ToLower(client.Companyadmin_idcompany), result, 60*time.Minute)
		fmt.Println("COMPANY CONF DATABASE")
		return c.JSON(result)
	} else {
		fmt.Println("COMPANY CONF CACHE")
		return c.JSON(fiber.Map{
			"status":  fiber.StatusOK,
			"message": "Success",
			"record":  arraobj,
			"time":    time.Since(render_page).String(),
		})
	}
}
func CompanySave(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_companysave)
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

	// admin, idrecord, idcurr, nmcompany, nmowner,
	// emailowner, phone1, phone2, url1, url2, status, sData string, minfee float64
	result, err := models.Save_company(
		client_admin,
		client.Company_id, client.Company_idcurr, client.Company_name, client.Company_owner,
		client.Company_email, client.Company_phone1, client.Company_phone2,
		client.Company_url1, client.Company_url2, client.Company_status,
		client.Sdata, client.Company_minfee)
	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": err.Error(),
			"record":  nil,
		})
	}

	_deleteredis_company("")
	return c.JSON(result)
}
func CompanyadminSave(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_companyadminsave)
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

	// admin, idcompany, username, password, name, status, sData string, idrecord, idrule int
	result, err := models.Save_companyadmin(
		client_admin,
		client.Companyadmin_idcompany, client.Companyadmin_username, client.Companyadmin_password,
		client.Companyadmin_name, client.Companyadmin_status, client.Sdata, client.Companyadmin_id, client.Companyadmin_idrule)
	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": err.Error(),
			"record":  nil,
		})
	}

	_deleteredis_company(client.Companyadmin_idcompany)
	return c.JSON(result)
}
func CompanyadminruleSave(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_companyadminrulesave)
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

	// admin, idcompany, name, rule, sData string, idrecord int
	result, err := models.Save_companyadminrule(
		client_admin,
		client.Companyadminrule_idcompany, client.Companyadminrule_nmruleadmin, client.Companyadminrule_ruleadmin,
		client.Sdata, client.Companyadminrule_id)
	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": err.Error(),
			"record":  nil,
		})
	}

	_deleteredis_company(client.Companyadminrule_idcompany)
	return c.JSON(result)
}
func CompanymoneySave(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_companymoneysave)
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

	// admin, idcompany, sData string, money int
	result, err := models.Save_companymoney(
		client_admin,
		client.Companymoney_idcompany,
		client.Sdata, client.Companymoney_money)
	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": err.Error(),
			"record":  nil,
		})
	}

	_deleteredis_company(client.Companymoney_idcompany)
	return c.JSON(result)
}
func CompanymoneyDelete(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_companymoneydelete)
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
	// user := c.Locals("jwt").(*jwt.Token)
	// claims := user.Claims.(jwt.MapClaims)
	// name := claims["name"].(string)
	// temp_decp := helpers.Decryption(name)
	// client_admin, _ := helpers.Parsing_Decry(temp_decp, "==")

	// idcompany string, idrecord int
	result, err := models.Delete_companymoney(
		client.Companymoney_idcompany,
		client.Companymoney_id)
	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": err.Error(),
			"record":  nil,
		})
	}

	_deleteredis_company(client.Companymoney_idcompany)
	return c.JSON(result)
}
func CompanyconfSave(c *fiber.Ctx) error {
	var errors []*helpers.ErrorResponse
	client := new(entities.Controller_companyconfsave)
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

	// admin, idcompany, status_2D30, maintenance_2D30 string, operator_2D30 string, status_redblack_line_2D30 string,
	// time_2D30, digit_2D30, minbet_2D30, maxbet_2D30 int,
	// win_2D30, win_redblack_2D30, win_line_2D30, win_zona_2D30, win_jackpot_2D30 float64
	result, err := models.Save_companyconf(
		client_admin,
		client.Companyconf_id, client.Companyconf_2digit_30_status,
		client.Companyconf_2digit_30_maintenance, client.Companyconf_2digit_30_operator, client.Companyconf_2digit_30_status_redblack_line,
		client.Companyconf_2digit_30_time, client.Companyconf_2digit_30_digit,
		client.Companyconf_2digit_30_minbet, client.Companyconf_2digit_30_maxbet,
		client.Companyconf_2digit_30_win, client.Companyconf_2digit_30_win_redblack, client.Companyconf_2digit_30_win_line,
		client.Companyconf_2digit_30_win_zona, client.Companyconf_2digit_30_win_jackpot)
	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"status":  fiber.StatusBadRequest,
			"message": err.Error(),
			"record":  nil,
		})
	}

	_deleteredis_company(client.Companyconf_id)
	return c.JSON(result)
}
func _deleteredis_company(idcompany string) {
	val_master := helpers.DeleteRedis(Fieldcompany_home_redis)
	fmt.Printf("Redis Delete BACKEND COMPANY : %d", val_master)

	val_compconf := helpers.DeleteRedis(Fieldcompanyconf_home_redis + "_" + strings.ToLower(idcompany))
	fmt.Printf("Redis Delete BACKEND COMPANY CONF : %d", val_compconf)
	val_compadmin := helpers.DeleteRedis(Fieldcompanyadmin_home_redis + "_" + strings.ToLower(idcompany))
	fmt.Printf("Redis Delete BACKEND COMPANY ADMIN : %d", val_compadmin)
	val_compadminrule := helpers.DeleteRedis(Fieldcompanyadminrule_home_redis + "_" + strings.ToLower(idcompany))
	fmt.Printf("Redis Delete BACKEND COMPANY ADMINRULE : %d", val_compadminrule)
	val_compmoney := helpers.DeleteRedis(Fieldcompanymoney_home_redis + "_" + strings.ToLower(idcompany))
	fmt.Printf("Redis Delete BACKEND COMPANY MONEY : %d", val_compmoney)

	//==DELETE REDIS TIMER
	val_timer := helpers.DeleteRedis("CONFIG" + "_" + strings.ToLower(idcompany))
	fmt.Printf("Redis Delete BACKEND TIMER CONFIG : %d", val_timer)
}
