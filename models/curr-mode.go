package models

import (
	"context"
	"fmt"
	"time"

	"bitbucket.org/isbtotogroup/devops_master_api/configs"
	"bitbucket.org/isbtotogroup/devops_master_api/db"
	"bitbucket.org/isbtotogroup/devops_master_api/entities"
	"bitbucket.org/isbtotogroup/devops_master_api/helpers"
	"github.com/gofiber/fiber/v2"
	"github.com/nleeper/goment"
)

const database_curr_local = configs.DB_tbl_mst_curr

func Fetch_currHome() (helpers.Response, error) {
	var obj entities.Model_curr
	var arraobj []entities.Model_curr
	var res helpers.Response
	msg := "Data Not Found"
	con := db.CreateCon()
	ctx := context.Background()
	start := time.Now()

	sql_select := `SELECT 
			idcurr , nmcurr,  
			createcurr, to_char(COALESCE(createdatecurr,now()), 'YYYY-MM-DD HH24:MI:SS'), 
			updatecurr, to_char(COALESCE(updatedatecurr,now()), 'YYYY-MM-DD HH24:MI:SS') 
			FROM ` + database_curr_local + `  
			ORDER BY createdatecurr DESC   `

	row, err := con.QueryContext(ctx, sql_select)
	helpers.ErrorCheck(err)
	for row.Next() {
		var (
			idcurr_db, nmcurr_db                                               string
			createcurr_db, createdatecurr_db, updatecurr_db, updatedatecurr_db string
		)

		err = row.Scan(&idcurr_db, &nmcurr_db,
			&createcurr_db, &createdatecurr_db, &updatecurr_db, &updatedatecurr_db)

		helpers.ErrorCheck(err)
		create := ""
		update := ""
		if createcurr_db != "" {
			create = createcurr_db + ", " + createdatecurr_db
		}
		if updatecurr_db != "" {
			update = updatecurr_db + ", " + updatedatecurr_db
		}

		obj.Curr_id = idcurr_db
		obj.Curr_name = nmcurr_db
		obj.Curr_create = create
		obj.Curr_update = update
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
func Save_curr(admin, idrecord, name, sData string) (helpers.Response, error) {
	var res helpers.Response
	msg := "Failed"
	tglnow, _ := goment.New()
	render_page := time.Now()
	flag := false

	if sData == "New" {
		flag = CheckDB(database_curr_local, "idcurr", idrecord)
		if !flag {
			sql_insert := `
				insert into
				` + database_curr_local + ` (
					idcurr , nmcurr, 
					createcurr, createdatecurr 
				) values (
					$1, $2,    
					$3, $4 
				)
			`
			flag_insert, msg_insert := Exec_SQL(sql_insert, database_curr_local, "INSERT",
				idrecord, name,
				admin, tglnow.Format("YYYY-MM-DD HH:mm:ss"))

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
				` + database_curr_local + `  
				SET nmcurr=$1, 
				updatecurr=$2, updatedatecurr=$3    
				WHERE idcurr=$4   
			`

		flag_update, msg_update := Exec_SQL(sql_update, database_curr_local, "UPDATE",
			name,
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
