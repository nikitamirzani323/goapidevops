package models

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"bitbucket.org/isbtotogroup/devops_master_api/configs"
	"bitbucket.org/isbtotogroup/devops_master_api/db"
	"bitbucket.org/isbtotogroup/devops_master_api/entities"
	"bitbucket.org/isbtotogroup/devops_master_api/helpers"
	"github.com/gofiber/fiber/v2"
	"github.com/nleeper/goment"
)

const database_company_local = configs.DB_tbl_mst_company
const database_companyadmin_local = configs.DB_tbl_mst_company_admin
const database_companyadminrule_local = configs.DB_tbl_mst_company_adminrule
const database_companyconfig_local = configs.DB_tbl_mst_company_config
const database_companymoney_local = configs.DB_tbl_mst_company_money

func Fetch_companyHome(search string, page int) (helpers.Responsercompany, error) {
	var obj entities.Model_company
	var arraobj []entities.Model_company
	var objcurr entities.Model_currshare
	var arraobjcurr []entities.Model_currshare
	var res helpers.Responsercompany
	msg := "Data Not Found"
	con := db.CreateCon()
	ctx := context.Background()
	start := time.Now()

	perpage := configs.PAGING_PAGE
	totalrecord := 0
	offset := page
	sql_selectcount := ""
	sql_selectcount += ""
	sql_selectcount += "SELECT "
	sql_selectcount += "COUNT(idcompany) as totalcompany  "
	sql_selectcount += "FROM " + database_company_local + "  "
	if search != "" {
		sql_selectcount += "WHERE LOWER(idcompany) LIKE '%" + strings.ToLower(search) + "%' "
		sql_selectcount += "OR LOWER(nmcompany) LIKE '%" + strings.ToLower(search) + "%' "
	}
	row_selectcount := con.QueryRowContext(ctx, sql_selectcount)
	switch e_selectcount := row_selectcount.Scan(&totalrecord); e_selectcount {
	case sql.ErrNoRows:
	case nil:
	default:
		helpers.ErrorCheck(e_selectcount)
	}

	sql_select := ""
	sql_select += "SELECT "
	sql_select += "idcompany, "
	sql_select += "to_char(COALESCE(startjoincompany,now()), 'YYYY-MM-DD HH24:MI:SS'), "
	sql_select += "to_char(COALESCE(endjoincompany,now()), 'YYYY-MM-DD HH24:MI:SS'), idcurr, "
	sql_select += "nmcompany, nmowner, emailowner, phone1owner,phone2owner, "
	sql_select += "companyurl_1, companyurl_2, minfee, "
	sql_select += "statuscompany, "
	sql_select += "createcompany, to_char(COALESCE(createdatecompany,now()), 'YYYY-MM-DD HH24:MI:SS'), "
	sql_select += "updatecompany, to_char(COALESCE(updatedatecompany,now()), 'YYYY-MM-DD HH24:MI:SS')  "
	sql_select += "FROM " + database_company_local + "   "
	if search == "" {
		sql_select += "ORDER BY createdatecompany DESC  OFFSET " + strconv.Itoa(offset) + " LIMIT " + strconv.Itoa(perpage)

	} else {
		sql_select += "WHERE LOWER(idcompany) LIKE '%" + strings.ToLower(search) + "%' "
		sql_select += "OR LOWER(nmcompany) LIKE '%" + strings.ToLower(search) + "%' "
		sql_select += "ORDER BY createdatecompany DESC   LIMIT " + strconv.Itoa(perpage)
	}

	row, err := con.QueryContext(ctx, sql_select)
	helpers.ErrorCheck(err)
	for row.Next() {
		var (
			idcompany_db, startjoincompany_db, endjoincompany_db, idcurr_db                string
			nmcompany_db, nmowner_db, emailowner_db, phone1owner_db, phone2owner_db        string
			companyurl_1_db, companyurl_2_db, statuscompany_db                             string
			minfee_db                                                                      float64
			createcompany_db, createdatecompany_db, updatecompany_db, updatedatecompany_db string
		)

		err = row.Scan(&idcompany_db,
			&startjoincompany_db, &endjoincompany_db, &idcurr_db,
			&nmcompany_db, &nmowner_db, &emailowner_db, &phone1owner_db, &phone2owner_db,
			&companyurl_1_db, &companyurl_2_db, &minfee_db, &statuscompany_db,
			&createcompany_db, &createdatecompany_db, &updatecompany_db, &updatedatecompany_db)

		helpers.ErrorCheck(err)
		create := ""
		update := ""
		status_css := configs.STATUS_CANCEL
		if createcompany_db != "" {
			create = createcompany_db + ", " + createdatecompany_db
		}
		if updatecompany_db != "" {
			update = updatecompany_db + ", " + updatedatecompany_db
		}
		if statuscompany_db == "Y" {
			status_css = configs.STATUS_COMPLETE
		}

		obj.Company_id = idcompany_db
		obj.Company_startjoin = startjoincompany_db
		obj.Company_endjoin = endjoincompany_db
		obj.Company_idcurr = idcurr_db
		obj.Company_name = nmcompany_db
		obj.Company_owner = nmowner_db
		obj.Company_email = emailowner_db
		obj.Company_phone1 = phone1owner_db
		obj.Company_phone2 = phone2owner_db
		obj.Company_url1 = companyurl_1_db
		obj.Company_url2 = companyurl_2_db
		obj.Company_minfee = minfee_db
		obj.Company_status = statuscompany_db
		obj.Company_status_css = status_css
		obj.Company_create = create
		obj.Company_update = update
		arraobj = append(arraobj, obj)
		msg = "Success"
	}
	defer row.Close()

	sql_selectcurr := `SELECT 
			idcurr 
			FROM ` + configs.DB_tbl_mst_curr + ` 
			ORDER BY idcurr ASC    
	`
	rowcurr, errcurr := con.QueryContext(ctx, sql_selectcurr)
	helpers.ErrorCheck(errcurr)
	for rowcurr.Next() {
		var (
			idcurr_db string
		)

		errcurr = rowcurr.Scan(&idcurr_db)

		helpers.ErrorCheck(errcurr)

		objcurr.Curr_id = idcurr_db
		arraobjcurr = append(arraobjcurr, objcurr)
		msg = "Success"
	}
	defer rowcurr.Close()

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = arraobj
	res.Perpage = perpage
	res.Totalrecord = totalrecord
	res.Listcurr = arraobjcurr
	res.Time = time.Since(start).String()

	return res, nil
}
func Fetch_companyadminHome(idcompany string) (helpers.Responsercompanyadmin, error) {
	var obj entities.Model_companyadmin
	var arraobj []entities.Model_companyadmin
	var objadminrule entities.Model_companyadminruleshare
	var arraobjadminrule []entities.Model_companyadminruleshare
	var res helpers.Responsercompanyadmin
	msg := "Data Not Found"
	con := db.CreateCon()
	ctx := context.Background()
	start := time.Now()

	sql_select := ""
	sql_select += "SELECT "
	sql_select += "idcompadmin, idcompadminrule, "
	sql_select += "adminusername, nameadmin, statuscompadmin, "
	sql_select += "createcompadmin, to_char(COALESCE(createdatecompadmin,now()), 'YYYY-MM-DD HH24:MI:SS'), "
	sql_select += "updatecompadmin, to_char(COALESCE(updatedatecompadmin,now()), 'YYYY-MM-DD HH24:MI:SS')  "
	sql_select += "FROM " + database_companyadmin_local + " "
	sql_select += "WHERE idcompany ='" + idcompany + "' "
	sql_select += "ORDER BY createdatecompadmin DESC   "
	fmt.Println(sql_select)
	row, err := con.QueryContext(ctx, sql_select)
	helpers.ErrorCheck(err)
	for row.Next() {
		var (
			idcompadmin_db, idcompadminrule_db                                                     int
			adminusername_db, nameadmin_db, statuscompadmin_db                                     string
			createcompadmin_db, createdatecompadmin_db, updatecompadmin_db, updatedatecompadmin_db string
		)

		err = row.Scan(&idcompadmin_db, &idcompadminrule_db,
			&adminusername_db, &nameadmin_db, &statuscompadmin_db,
			&createcompadmin_db, &createdatecompadmin_db, &updatecompadmin_db, &updatedatecompadmin_db)

		helpers.ErrorCheck(err)
		create := ""
		update := ""
		status_css := configs.STATUS_CANCEL
		if createcompadmin_db != "" {
			create = createcompadmin_db + ", " + createdatecompadmin_db
		}
		if updatecompadmin_db != "" {
			update = updatecompadmin_db + ", " + updatedatecompadmin_db
		}
		if statuscompadmin_db == "Y" {
			status_css = configs.STATUS_COMPLETE
		}

		obj.Companyadmin_id = idcompadmin_db
		obj.Companyadmin_idrule = idcompadminrule_db
		obj.Companyadmin_idcompany = idcompany
		obj.Companyadmin_nmrule = _Get_adminrule(idcompadminrule_db)
		obj.Companyadmin_username = adminusername_db
		obj.Companyadmin_name = nameadmin_db
		obj.Companyadmin_status = statuscompadmin_db
		obj.Companyadmin_status_css = status_css
		obj.Companyadmin_create = create
		obj.Companyadmin_update = update
		arraobj = append(arraobj, obj)
		msg = "Success"
	}
	defer row.Close()

	sql_selectadminrule := `SELECT 
			idcompadminrule, nmruleadmin 
			FROM ` + configs.DB_tbl_mst_company_adminrule + ` 
			WHERE idcompany='` + idcompany + `'  
			ORDER BY nmruleadmin ASC    
	`
	rowadminrule, erradminrule := con.QueryContext(ctx, sql_selectadminrule)
	helpers.ErrorCheck(erradminrule)
	for rowadminrule.Next() {
		var (
			idcompadminrule_db int
			nmruleadmin_db     string
		)

		erradminrule = rowadminrule.Scan(&idcompadminrule_db, &nmruleadmin_db)

		helpers.ErrorCheck(erradminrule)

		objadminrule.Companyadminrule_id = idcompadminrule_db
		objadminrule.Companyadminrule_name = nmruleadmin_db
		arraobjadminrule = append(arraobjadminrule, objadminrule)
		msg = "Success"
	}
	defer rowadminrule.Close()

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = arraobj
	res.Listrule = arraobjadminrule
	res.Time = time.Since(start).String()

	return res, nil
}
func Fetch_companyadminruleHome(idcompany string) (helpers.Response, error) {
	var obj entities.Model_companyadminrule
	var arraobj []entities.Model_companyadminrule
	var res helpers.Response
	msg := "Data Not Found"
	con := db.CreateCon()
	ctx := context.Background()
	start := time.Now()

	sql_select := ""
	sql_select += "SELECT "
	sql_select += "idcompadminrule,nmruleadmin, ruleadmin, "
	sql_select += "createcompadminrule, to_char(COALESCE(createdatecompadminrule,now()), 'YYYY-MM-DD HH24:MI:SS'), "
	sql_select += "updatecompadminrule, to_char(COALESCE(updatedatecompadminrule,now()), 'YYYY-MM-DD HH24:MI:SS')  "
	sql_select += "FROM " + database_companyadminrule_local + " "
	sql_select += "WHERE idcompany ='" + idcompany + "' "
	sql_select += "ORDER BY createdatecompadminrule DESC   "
	fmt.Println(sql_select)
	row, err := con.QueryContext(ctx, sql_select)
	helpers.ErrorCheck(err)
	for row.Next() {
		var (
			idcompadminrule_db                                                                                     int
			nmruleadmin_db, ruleadmin_db                                                                           string
			createcompadminrule_db, createdatecompadminrule_db, updatecompadminrule_db, updatedatecompadminrule_db string
		)

		err = row.Scan(&idcompadminrule_db, &nmruleadmin_db, &ruleadmin_db,
			&createcompadminrule_db, &createdatecompadminrule_db, &updatecompadminrule_db, &updatedatecompadminrule_db)

		helpers.ErrorCheck(err)
		create := ""
		update := ""
		if createcompadminrule_db != "" {
			create = createcompadminrule_db + ", " + createdatecompadminrule_db
		}
		if updatecompadminrule_db != "" {
			update = updatecompadminrule_db + ", " + updatedatecompadminrule_db
		}

		obj.Companyadminrule_id = idcompadminrule_db
		obj.Companyadminrule_nmruleadmin = nmruleadmin_db
		obj.Companyadminrule_ruleadmin = ruleadmin_db
		obj.Companyadminrule_create = create
		obj.Companyadminrule_update = update
		arraobj = append(arraobj, obj)
		msg = "Success"
	}
	defer row.Close()

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = arraobj
	res.Time = time.Since(start).String()

	return res, nil
}
func Fetch_companymoneyHome(idcompany string) (helpers.Response, error) {
	var obj entities.Model_companymoney
	var arraobj []entities.Model_companymoney
	var res helpers.Response
	msg := "Data Not Found"
	con := db.CreateCon()
	ctx := context.Background()
	start := time.Now()

	sql_select := ""
	sql_select += "SELECT "
	sql_select += "idcompmoney, compmoney, "
	sql_select += "createcompmoney, to_char(COALESCE(createdatecompmoney,now()), 'YYYY-MM-DD HH24:MI:SS'), "
	sql_select += "updatecompmoney, to_char(COALESCE(updatedatecompmoney,now()), 'YYYY-MM-DD HH24:MI:SS')  "
	sql_select += "FROM " + database_companymoney_local + " "
	sql_select += "WHERE idcompany ='" + idcompany + "' "
	fmt.Println(sql_select)
	row, err := con.QueryContext(ctx, sql_select)
	helpers.ErrorCheck(err)
	for row.Next() {
		var (
			idcompmoney_db, compmoney_db                                               int
			createcompmoney, createdatecompmoney, updatecompmoney, updatedatecompmoney string
		)

		err = row.Scan(&idcompmoney_db, &compmoney_db,
			&createcompmoney, &createdatecompmoney, &updatecompmoney, &updatedatecompmoney)

		helpers.ErrorCheck(err)
		create := ""
		update := ""
		if createcompmoney != "" {
			create = createcompmoney + ", " + createdatecompmoney
		}
		if updatecompmoney != "" {
			update = updatecompmoney + ", " + updatedatecompmoney
		}

		obj.Companymoney_id = idcompmoney_db
		obj.Companymoney_money = compmoney_db
		obj.Companymoney_create = create
		obj.Companymoney_update = update
		arraobj = append(arraobj, obj)
		msg = "Success"
	}
	defer row.Close()

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = arraobj
	res.Time = time.Since(start).String()
	return res, nil
}
func Fetch_companyconfHome(idcompany string) (helpers.Response, error) {
	var obj entities.Model_companyconf
	var arraobj []entities.Model_companyconf
	var res helpers.Response
	msg := "Data Not Found"
	con := db.CreateCon()
	ctx := context.Background()
	start := time.Now()

	sql_select := ""
	sql_select += "SELECT "
	sql_select += "conf_2digit_30_time, conf_2digit_30_digit, "
	sql_select += "conf_2digit_30_minbet, conf_2digit_30_maxbet,   "
	sql_select += "conf_2digit_30_win, conf_2digit_30_win_redblack, conf_2digit_30_win_line,conf_2digit_30_win_zona,conf_2digit_30_win_jackpot,   "
	sql_select += "conf_2digit_30_status_redblack_line, conf_2digit_30_operator, conf_2digit_30_maintenance, conf_2digit_30_status,  "
	sql_select += "createconf, to_char(COALESCE(createdateconf,now()), 'YYYY-MM-DD HH24:MI:SS'), "
	sql_select += "updateconf, to_char(COALESCE(updatedateconf,now()), 'YYYY-MM-DD HH24:MI:SS')  "
	sql_select += "FROM " + database_companyconfig_local + " "
	sql_select += "WHERE idcompany ='" + idcompany + "' "
	fmt.Println(sql_select)
	row, err := con.QueryContext(ctx, sql_select)
	helpers.ErrorCheck(err)
	for row.Next() {
		var (
			conf_2digit_30_time_db, conf_2digit_30_digit_db, conf_2digit_30_minbet_db, conf_2digit_30_maxbet_db                                       int
			conf_2digit_30_win_db, conf_2digit_30_win_redblack_db, conf_2digit_30_win_line, conf_2digit_30_win_zona_db, conf_2digit_30_win_jackpot_db float64
			conf_2digit_30_status_redblack_line_db, conf_2digit_30_operator_db, conf_2digit_30_maintenance_db, conf_2digit_30_status_db               string
			createconf_db, createdateconf_db, updateconf_db, updatedateconf_db                                                                        string
		)

		err = row.Scan(&conf_2digit_30_time_db, &conf_2digit_30_digit_db, &conf_2digit_30_minbet_db,
			&conf_2digit_30_maxbet_db, &conf_2digit_30_win_db, &conf_2digit_30_win_redblack_db, &conf_2digit_30_win_line, &conf_2digit_30_win_zona_db, &conf_2digit_30_win_jackpot_db,
			&conf_2digit_30_status_redblack_line_db, &conf_2digit_30_operator_db, &conf_2digit_30_maintenance_db, &conf_2digit_30_status_db,
			&createconf_db, &createdateconf_db, &updateconf_db, &updatedateconf_db)

		helpers.ErrorCheck(err)
		create := ""
		update := ""
		redblackline_css := configs.STATUS_CANCEL
		operator_css := configs.STATUS_CANCEL
		maintenance_css := configs.STATUS_CANCEL
		status_css := configs.STATUS_CANCEL
		if createconf_db != "" {
			create = createconf_db + ", " + createdateconf_db
		}
		if updateconf_db != "" {
			update = updateconf_db + ", " + updatedateconf_db
		}
		if conf_2digit_30_status_redblack_line_db == "Y" {
			redblackline_css = configs.STATUS_COMPLETE
		}
		if conf_2digit_30_operator_db == "Y" {
			operator_css = configs.STATUS_COMPLETE
		}
		if conf_2digit_30_maintenance_db == "Y" {
			maintenance_css = configs.STATUS_COMPLETE
		}
		if conf_2digit_30_status_db == "Y" {
			status_css = configs.STATUS_COMPLETE
		}

		obj.Companyconf_id = idcompany
		obj.Companyconf_2digit_30_time = conf_2digit_30_time_db
		obj.Companyconf_2digit_30_digit = conf_2digit_30_digit_db
		obj.Companyconf_2digit_30_minbet = conf_2digit_30_minbet_db
		obj.Companyconf_2digit_30_maxbet = conf_2digit_30_maxbet_db
		obj.Companyconf_2digit_30_win = conf_2digit_30_win_db
		obj.Companyconf_2digit_30_win_redblack = conf_2digit_30_win_redblack_db
		obj.Companyconf_2digit_30_win_line = conf_2digit_30_win_line
		obj.Companyconf_2digit_30_win_zona = conf_2digit_30_win_zona_db
		obj.Companyconf_2digit_30_win_jackpot = conf_2digit_30_win_jackpot_db
		obj.Companyconf_2digit_30_status_redblack_line = conf_2digit_30_status_redblack_line_db
		obj.Companyconf_2digit_30_status_redblack_line_css = redblackline_css
		obj.Companyconf_2digit_30_operator = conf_2digit_30_operator_db
		obj.Companyconf_2digit_30_operator_css = operator_css
		obj.Companyconf_2digit_30_maintenance = conf_2digit_30_maintenance_db
		obj.Companyconf_2digit_30_maintenance_css = maintenance_css
		obj.Companyconf_2digit_30_status = conf_2digit_30_status_db
		obj.Companyconf_2digit_30_status_css = status_css
		obj.Companyconf_create = create
		obj.Companyconf_update = update
		arraobj = append(arraobj, obj)
		msg = "Success"
	}
	defer row.Close()

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = arraobj
	res.Time = time.Since(start).String()

	return res, nil
}
func Save_company(admin, idrecord, idcurr, nmcompany, nmowner,
	emailowner, phone1, phone2, url1, url2, status, sData string, minfee float64) (helpers.Response, error) {
	var res helpers.Response
	msg := "Failed"
	tglnow, _ := goment.New()
	render_page := time.Now()
	flag := false

	if sData == "New" {
		flag = CheckDB(database_company_local, "idcompany", idrecord)
		if !flag {
			sql_insert := `
				insert into
				` + database_company_local + ` (
					idcompany,  startjoincompany, endjoincompany, idcurr,
					nmcompany , nmowner, emailowner, phone1owner, phone2owner,
					companyurl_1 , companyurl_2, minfee, statuscompany,
					createcompany, createdatecompany 
				) values (
					$1, $2, $3, $4, 
					$5, $6, $7, $8, $9, 
					$10, $11, $12, $13, 
					$14, $15  
				)
			`
			start_join := tglnow.Format("YYYY-MM-DD HH:mm:ss")
			flag_insert, msg_insert := Exec_SQL(sql_insert, database_company_local, "INSERT",
				idrecord, start_join, start_join, idcurr,
				nmcompany, nmowner, emailowner, phone1, phone2,
				url1, url2, minfee, status,
				admin, start_join)

			if flag_insert {
				msg = "Succes"
			} else {
				fmt.Println(msg_insert)
			}
		} else {
			msg = "Duplicate Entry"
		}
	} else {
		sql_update := `
				UPDATE 
				` + database_company_local + `  
				SET idcurr=$1, 
				nmcompany=$2, nmowner=$3, emailowner=$4, phone1owner=$5, phone2owner=$6,   
				companyurl_1=$7, companyurl_2=$8,  minfee=$9, statuscompany=$10,   
				updatecompany=$11, updatedatecompany=$12    
				WHERE idcompany=$13    
			`

		flag_update, msg_update := Exec_SQL(sql_update, database_company_local, "UPDATE",
			idcurr, nmcompany, nmowner,
			emailowner, phone1, phone2, url1, url2, minfee, status,
			admin, tglnow.Format("YYYY-MM-DD HH:mm:ss"), idrecord)

		if flag_update {
			flag = true
			msg = "Succes"
		} else {
			fmt.Println(msg_update)
		}
	}

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = nil
	res.Time = time.Since(render_page).String()

	return res, nil
}
func Save_companyadmin(admin, idcompany, username, password, name, status, sData string, idrecord, idrule int) (helpers.Response, error) {
	var res helpers.Response
	msg := "Failed"
	tglnow, _ := goment.New()
	render_page := time.Now()
	flag := false

	if sData == "New" {
		flag = CheckDB(database_company_local, "adminusername", strings.ToLower(username))
		if !flag {
			sql_insert := `
				insert into
				` + database_companyadmin_local + ` (
					idcompadmin, idcompadminrule, idcompany,  adminusername, adminpassword, nameadmin, statuscompadmin, lastlogincompadmin, 
					createcompadmin, createdatecompadmin 
				) values (
					$1, $2, $3, $4, $5, $6, $7, $8,
					$9, $10  
				)
			`
			start := tglnow.Format("YYYY-MM-DD HH:mm:ss")
			hashpass := helpers.HashPasswordMD5(password)
			field_column := database_companyadmin_local + strings.ToLower(idcompany) + tglnow.Format("YYYY")
			idrecord_counter := Get_counter(field_column)
			idrecord := tglnow.Format("YY") + strconv.Itoa(idrecord_counter)
			flag_insert, msg_insert := Exec_SQL(sql_insert, database_companyadmin_local, "INSERT",
				idrecord, idrule, idcompany, username, hashpass,
				name, status, start,
				admin, start)

			if flag_insert {
				msg = "Succes"
			} else {
				fmt.Println(msg_insert)
			}
		} else {
			msg = "Duplicate Entry"
		}
	} else {
		sql_update := `
				UPDATE 
				` + database_companyadmin_local + `  
				SET idcompadminrule=$1, nameadmin=$2, statuscompadmin=$3, 
				updatecompadmin=$4, updatedatecompadmin=$5     
				WHERE idcompadmin=$6  
			`

		flag_update, msg_update := Exec_SQL(sql_update, database_companyadmin_local, "UPDATE",
			idrule, name, status,
			admin, tglnow.Format("YYYY-MM-DD HH:mm:ss"), idrecord)

		if flag_update {
			flag = true
			msg = "Succes"
		} else {
			fmt.Println(msg_update)
		}
	}

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = nil
	res.Time = time.Since(render_page).String()

	return res, nil
}
func Save_companyadminrule(admin, idcompany, name, rule, sData string, idrecord int) (helpers.Response, error) {
	var res helpers.Response
	msg := "Failed"
	tglnow, _ := goment.New()
	render_page := time.Now()

	if sData == "New" {
		sql_insert := `
				insert into
				` + database_companyadminrule_local + ` (
					idcompadminrule, idcompany,  nmruleadmin, ruleadmin, 
					createcompadminrule, createdatecompadminrule 
				) values (
					$1, $2, $3, $4,
					$5, $6 
				)
			`

		field_column := database_companyadminrule_local + strings.ToLower(idcompany) + tglnow.Format("YYYY")
		idrecord_counter := Get_counter(field_column)
		idrecord := tglnow.Format("YY") + strconv.Itoa(idrecord_counter)
		flag_insert, msg_insert := Exec_SQL(sql_insert, database_companyadminrule_local, "INSERT",
			idrecord, idcompany, name, rule,
			admin, tglnow.Format("YYYY-MM-DD HH:mm:ss"))

		if flag_insert {
			msg = "Succes"
		} else {
			fmt.Println(msg_insert)
		}
	} else {
		sql_update := `
				UPDATE 
				` + database_companyadminrule_local + `  
				SET nmruleadmin=$1, ruleadmin=$2, 
				updatecompadminrule=$3, updatedatecompadminrule=$4     
				WHERE idcompadminrule=$5   
			`

		flag_update, msg_update := Exec_SQL(sql_update, database_companyadminrule_local, "UPDATE",
			name, rule,
			admin, tglnow.Format("YYYY-MM-DD HH:mm:ss"), idrecord)

		if flag_update {
			msg = "Succes"
		} else {
			fmt.Println(msg_update)
		}
	}

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = nil
	res.Time = time.Since(render_page).String()

	return res, nil
}
func Save_companymoney(admin, idcompany, sData string, money int) (helpers.Response, error) {
	var res helpers.Response
	msg := "Failed"
	tglnow, _ := goment.New()
	render_page := time.Now()

	if sData == "New" {
		sql_insert := `
				insert into
				` + database_companymoney_local + ` (
					idcompmoney, idcompany,  compmoney, 
					createcompmoney, createdatecompmoney 
				) values (
					$1, $2, $3, 
					$4, $5 
				)
			`

		field_column := database_companymoney_local + strings.ToLower(idcompany) + tglnow.Format("YYYY")
		idrecord_counter := Get_counter(field_column)
		idrecord := tglnow.Format("YY") + strconv.Itoa(idrecord_counter)
		flag_insert, msg_insert := Exec_SQL(sql_insert, database_companymoney_local, "INSERT",
			idrecord, idcompany, money,
			admin, tglnow.Format("YYYY-MM-DD HH:mm:ss"))

		if flag_insert {
			msg = "Succes"
		} else {
			fmt.Println(msg_insert)
		}
	}

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = nil
	res.Time = time.Since(render_page).String()

	return res, nil
}
func Delete_companymoney(idcompany string, idrecord int) (helpers.Response, error) {
	var res helpers.Response
	msg := "Failed"
	render_page := time.Now()

	sql_delete := `
		DELETE FROM  
		` + database_companymoney_local + `   
		WHERE idcompmoney=$1  
		AND idcompany=$2  
	`

	flag_delete, msg_delete := Exec_SQL(sql_delete, database_companymoney_local, "DELETE", idrecord, idcompany)

	if flag_delete {
		msg = "Succes"
	} else {
		fmt.Println(msg_delete)
	}

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = nil
	res.Time = time.Since(render_page).String()

	return res, nil
}
func Save_companyconf(admin, idcompany, status_2D30, maintenance_2D30 string, operator_2D30 string, status_redblack_line_2D30 string,
	time_2D30, digit_2D30, minbet_2D30, maxbet_2D30 int,
	win_2D30, win_redblack_2D30, win_line_2D30, win_zona_2D30, win_jackpot_2D30 float64) (helpers.Response, error) {
	var res helpers.Response
	msg := "Failed"
	tglnow, _ := goment.New()
	render_page := time.Now()
	flag := false

	flag = CheckDB(database_companyconfig_local, "idcompany", idcompany)
	if !flag {
		sql_insert := `
				insert into
				` + database_companyconfig_local + ` (
					idcompany, conf_2digit_30_time,  conf_2digit_30_digit, 
					conf_2digit_30_minbet, conf_2digit_30_maxbet, 
					conf_2digit_30_win, conf_2digit_30_win_redblack, conf_2digit_30_win_line, conf_2digit_30_win_zona, conf_2digit_30_win_jackpot
					conf_2digit_30_status_redblack_line, conf_2digit_30_operator, conf_2digit_30_maintenance, conf_2digit_30_status, 
					createconf, createdateconf 
				) values (
					$1, $2, $3, 
					$4, $5, 
					$6, $7, $8, $9, $10,
					$11, $12, $13, $14,
					$15, $16     
				)
			`

		flag_insert, msg_insert := Exec_SQL(sql_insert, database_companyconfig_local, "INSERT",
			idcompany, time_2D30, digit_2D30,
			minbet_2D30, maxbet_2D30,
			win_2D30, win_redblack_2D30, win_line_2D30, win_zona_2D30, win_jackpot_2D30,
			status_redblack_line_2D30, operator_2D30, maintenance_2D30, status_2D30,
			admin, tglnow.Format("YYYY-MM-DD HH:mm:ss"))

		if flag_insert {
			msg = "Succes"
		} else {
			fmt.Println(msg_insert)
		}
	} else {
		sql_update := `
				UPDATE 
				` + database_companyconfig_local + `  
				SET conf_2digit_30_time=$1, conf_2digit_30_digit=$2, 
				conf_2digit_30_minbet=$3, conf_2digit_30_maxbet=$4, 
				conf_2digit_30_win=$5, conf_2digit_30_win_redblack=$6, conf_2digit_30_win_line=$7, conf_2digit_30_win_zona=$8, conf_2digit_30_win_jackpot=$9, 
				conf_2digit_30_status_redblack_line=$10 ,conf_2digit_30_operator=$11, conf_2digit_30_maintenance=$12, conf_2digit_30_status=$13,   
				updateconf=$14, updatedateconf=$15       
				WHERE idcompany=$16      
			`

		flag_update, msg_update := Exec_SQL(sql_update, database_companyconfig_local, "UPDATE",
			time_2D30, digit_2D30,
			minbet_2D30, maxbet_2D30,
			win_2D30, win_redblack_2D30, win_line_2D30, win_zona_2D30, win_jackpot_2D30,
			status_redblack_line_2D30, operator_2D30, maintenance_2D30, status_2D30,
			admin, tglnow.Format("YYYY-MM-DD HH:mm:ss"), idcompany)

		if flag_update {
			msg = "Succes"
		} else {
			fmt.Println(msg_update)
		}
	}

	fieldconfig_redis := strings.ToLower(idcompany) + ":12D30S:" + "CONFIG"

	val_conf_all := helpers.DeleteRedis(fieldconfig_redis)
	fmt.Println("")
	fmt.Printf("Redis Delete CONFIG ALL : %d\r", val_conf_all)

	type Configure struct {
		Curr                string  `json:"curr"`
		Minbet              int     `json:"minbet"`
		Maxbet              int     `json:"maxbet"`
		Win_angka           float64 `json:"win_angka"`
		Win_redblack        float64 `json:"win_redblack"`
		Win_line            float64 `json:"win_line"`
		Win_zona            float64 `json:"win_zona"`
		Win_jackpot         float64 `json:"win_jackpot"`
		Status_redblackline string  `json:"status_redblackline"`
		Status_maintenance  string  `json:"status_maintenance"`
	}
	var obj Configure
	obj.Curr = _Get_infocompany(idcompany)
	obj.Minbet = minbet_2D30
	obj.Minbet = minbet_2D30
	obj.Maxbet = maxbet_2D30
	obj.Win_angka = win_2D30
	obj.Win_redblack = win_redblack_2D30
	obj.Win_line = win_line_2D30
	obj.Win_zona = win_zona_2D30
	obj.Win_jackpot = win_jackpot_2D30
	obj.Status_redblackline = status_redblack_line_2D30
	obj.Status_maintenance = maintenance_2D30
	helpers.SetRedis(fieldconfig_redis, obj, 10080*time.Minute)

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = nil
	res.Time = time.Since(render_page).String()

	return res, nil
}
func _Get_adminrule(idrule int) string {
	con := db.CreateCon()
	ctx := context.Background()
	rule := ""
	sql_select := `SELECT
			nmruleadmin    
			FROM ` + database_companyadminrule_local + `  
			WHERE idcompadminrule='` + strconv.Itoa(idrule) + `'       
		`

	row := con.QueryRowContext(ctx, sql_select)
	switch e := row.Scan(&rule); e {
	case sql.ErrNoRows:
	case nil:
	default:
		helpers.ErrorCheck(e)
	}

	return rule
}
func _Get_infocompany(idcompany string) string {
	con := db.CreateCon()
	ctx := context.Background()
	idcurr := ""
	sql_select := `SELECT
			idcurr    
			FROM ` + database_company_local + `  
			WHERE idcompany='` + idcompany + `'       
		`

	row := con.QueryRowContext(ctx, sql_select)
	switch e := row.Scan(&idcurr); e {
	case sql.ErrNoRows:
	case nil:
	default:
		helpers.ErrorCheck(e)
	}

	return idcurr
}
