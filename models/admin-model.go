package models

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"bitbucket.org/isbtotogroup/devops_master_api/configs"
	"bitbucket.org/isbtotogroup/devops_master_api/db"
	"bitbucket.org/isbtotogroup/devops_master_api/entities"
	"bitbucket.org/isbtotogroup/devops_master_api/helpers"
	"github.com/gofiber/fiber/v2"
	"github.com/nleeper/goment"
)

const database_admin_local = configs.DB_tbl_admin

func Fetch_adminHome() (helpers.ResponseAdmin, error) {
	var obj entities.Model_admin
	var arraobj []entities.Model_admin
	var res helpers.ResponseAdmin
	msg := "Data Not Found"
	con := db.CreateCon()
	ctx := context.Background()
	start := time.Now()

	sql_select := `SELECT 
			username , name, idadmin,
			statuslogin, to_char(COALESCE(lastlogin,now()), 'YYYY-MM-DD HH24:MI:SS'), joindate, 
			ipaddress   
			FROM ` + database_admin_local + ` 
			ORDER BY lastlogin DESC 
		`

	row, err := con.QueryContext(ctx, sql_select)

	var no int = 0
	helpers.ErrorCheck(err)
	for row.Next() {
		no += 1
		var (
			username_db, name_db, idadminlevel_db                   string
			statuslogin_db, lastlogin_db, joindate_db, ipaddress_db string
		)

		err = row.Scan(
			&username_db, &name_db, &idadminlevel_db,
			&statuslogin_db, &lastlogin_db, &joindate_db,
			&ipaddress_db)

		helpers.ErrorCheck(err)
		if statuslogin_db == "Y" {
			statuslogin_db = "ACTIVE"
		}
		if lastlogin_db == "0000-00-00 00:00:00" {
			lastlogin_db = ""
		}
		obj.Username = username_db
		obj.Nama = name_db
		obj.Rule = idadminlevel_db
		obj.Joindate = joindate_db
		obj.Lastlogin = lastlogin_db
		obj.LastIpaddress = ipaddress_db
		obj.Status = statuslogin_db
		arraobj = append(arraobj, obj)
		msg = "Success"
	}
	defer row.Close()

	var objRule entities.Model_adminrule
	var arraobjRule []entities.Model_adminrule
	sql_listrule := `SELECT 
		idadmin 	
		FROM ` + configs.DB_tbl_admingroup + ` 
	`
	row_listrule, err_listrule := con.QueryContext(ctx, sql_listrule)

	helpers.ErrorCheck(err_listrule)
	for row_listrule.Next() {
		var (
			idruleadmin_db string
		)

		err = row_listrule.Scan(&idruleadmin_db)

		helpers.ErrorCheck(err)

		objRule.Idrule = idruleadmin_db
		arraobjRule = append(arraobjRule, objRule)
		msg = "Success"
	}

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = arraobj
	res.Listrule = arraobjRule
	res.Time = time.Since(start).String()

	return res, nil
}
func Fetch_adminDetail(username string) (helpers.ResponseAdmin, error) {
	var obj entities.Model_adminsave
	var arraobj []entities.Model_adminsave
	var res helpers.ResponseAdmin
	msg := "Data Not Found"
	con := db.CreateCon()
	ctx := context.Background()
	start := time.Now()

	sql_detail := `SELECT 
		idadmin, name, statuslogin  
		createadmin, to_char(COALESCE(createdateadmin,now()), 'YYYY-MM-DD HH24:MI:SS'), 
		updateadmin, to_char(COALESCE(updatedateadmin,now()), 'YYYY-MM-DD HH24:MI:SS')  
		FROM ` + database_admin_local + `
		WHERE username = $1 
	`
	var (
		idadmin_db, name_db, statuslogin_db                                    string
		createadmin_db, createdateadmin_db, updateadmin_db, updatedateadmin_db string
	)
	rows := con.QueryRowContext(ctx, sql_detail, username)

	switch err := rows.Scan(
		&idadmin_db, &name_db, &statuslogin_db,
		&createadmin_db, &createdateadmin_db, &updateadmin_db, &updatedateadmin_db); err {
	case sql.ErrNoRows:

	case nil:
		if createdateadmin_db == "0000-00-00 00:00:00" {
			createdateadmin_db = ""
		}
		if updatedateadmin_db == "0000-00-00 00:00:00" {
			updatedateadmin_db = ""
		}
		create := ""
		update := ""
		if createdateadmin_db != "" {
			create = createadmin_db + ", " + createdateadmin_db
		}
		if updateadmin_db != "" {
			create = updateadmin_db + ", " + updatedateadmin_db
		}

		obj.Username = username
		obj.Nama = name_db
		obj.Rule = idadmin_db
		obj.Status = statuslogin_db
		obj.Create = create
		obj.Update = update
		arraobj = append(arraobj, obj)
		msg = "Success"
	default:
		helpers.ErrorCheck(err)
	}

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = arraobj
	res.Time = time.Since(start).String()

	return res, nil
}
func Save_adminHome(admin, username, password, nama, rule, status, sData string) (helpers.Response, error) {
	var res helpers.Response
	msg := "Failed"
	tglnow, _ := goment.New()
	render_page := time.Now()
	flag := false

	if sData == "New" {
		flag = CheckDB(database_admin_local, "username", username)
		if !flag {
			sql_insert := `
				insert into
				` + database_admin_local + ` (
					username , password, idadmin, name, statuslogin, joindate, 
					createadmin, createdateadmin
				) values (
					$1, $2, $3, $4, $5, $6, 
					$7, $8
				)
			`
			hashpass := helpers.HashPasswordMD5(password)
			flag_insert, msg_insert := Exec_SQL(sql_insert, database_admin_local, "INSERT",
				username, hashpass,
				rule, nama, status,
				tglnow.Format("YYYY-MM-DD"),
				admin,
				tglnow.Format("YYYY-MM-DD HH:mm:ss"))

			if flag_insert {
				msg = "Succes"
			} else {
				fmt.Println(msg_insert)
			}
		} else {
			msg = "Duplicate Entry"
		}
	} else {
		if password == "" {
			sql_update := `
				UPDATE 
				` + database_admin_local + `  
				SET name =$1, idadmin=$2, statuslogin=$3,  
				updateadmin=$4, updatedateadmin=$5 
				WHERE username =$6 
			`

			flag_update, msg_update := Exec_SQL(sql_update, database_admin_local, "UPDATE",
				nama,
				rule,
				status,
				admin,
				tglnow.Format("YYYY-MM-DD HH:mm:ss"),
				username)

			if flag_update {
				msg = "Succes"
			} else {
				fmt.Println(msg_update)
			}
		} else {
			hashpass := helpers.HashPasswordMD5(password)
			sql_update2 := `
				UPDATE 
				` + configs.DB_tbl_admin + `   
				SET name =$1, password=$2, idadmin=$3, statuslogin=$4,  
				updateadmin=$5, updatedateadmin=$6 
				WHERE username =$7 
			`
			flag_update, msg_update := Exec_SQL(sql_update2, database_admin_local, "UPDATE",
				nama,
				hashpass,
				rule,
				status,
				admin,
				tglnow.Format("YYYY-MM-DD HH:mm:ss"),
				username)

			if flag_update {
				msg = "Succes"
			} else {
				fmt.Println(msg_update)
			}
		}
	}

	res.Status = fiber.StatusOK
	res.Message = msg
	res.Record = nil
	res.Time = time.Since(render_page).String()

	return res, nil
}
