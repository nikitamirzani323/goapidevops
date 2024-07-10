package entities

type Model_company struct {
	Company_id         string  `json:"company_id"`
	Company_startjoin  string  `json:"company_startjoin"`
	Company_endjoin    string  `json:"company_endjoin"`
	Company_idcurr     string  `json:"company_idcurr"`
	Company_name       string  `json:"company_name"`
	Company_owner      string  `json:"company_owner"`
	Company_phone1     string  `json:"company_phone1"`
	Company_phone2     string  `json:"company_phone2"`
	Company_email      string  `json:"company_email"`
	Company_minfee     float64 `json:"company_minfee"`
	Company_url1       string  `json:"company_url1"`
	Company_url2       string  `json:"company_url2"`
	Company_status     string  `json:"company_status"`
	Company_status_css string  `json:"company_status_css"`
	Company_create     string  `json:"company_create"`
	Company_update     string  `json:"company_update"`
}
type Model_companyadmin struct {
	Companyadmin_id         int    `json:"companyadmin_id"`
	Companyadmin_idrule     int    `json:"companyadmin_idrule"`
	Companyadmin_idcompany  string `json:"companyadmin_idcompany"`
	Companyadmin_nmrule     string `json:"companyadmin_nmrule"`
	Companyadmin_username   string `json:"companyadmin_username"`
	Companyadmin_name       string `json:"companyadmin_name"`
	Companyadmin_status     string `json:"companyadmin_status"`
	Companyadmin_status_css string `json:"companyadmin_status_css"`
	Companyadmin_create     string `json:"companyadmin_create"`
	Companyadmin_update     string `json:"companyadmin_update"`
}
type Model_companyadminrule struct {
	Companyadminrule_id          int    `json:"companyadminrule_id"`
	Companyadminrule_nmruleadmin string `json:"companyadminrule_nmruleadmin"`
	Companyadminrule_ruleadmin   string `json:"companyadminrule_ruleadmin"`
	Companyadminrule_create      string `json:"companyadminrule_create"`
	Companyadminrule_update      string `json:"companyadminrule_update"`
}
type Model_companyconf struct {
	Companyconf_id                                 string  `json:"companyconf_id"`
	Companyconf_2digit_30_time                     int     `json:"companyconf_2digit_30_time"`
	Companyconf_2digit_30_digit                    int     `json:"companyconf_2digit_30_digit"`
	Companyconf_2digit_30_minbet                   int     `json:"companyconf_2digit_30_minbet"`
	Companyconf_2digit_30_maxbet                   int     `json:"companyconf_2digit_30_maxbet"`
	Companyconf_2digit_30_win                      float64 `json:"companyconf_2digit_30_win"`
	Companyconf_2digit_30_win_redblack             float64 `json:"companyconf_2digit_30_win_redblack"`
	Companyconf_2digit_30_win_line                 float64 `json:"companyconf_2digit_30_win_line"`
	Companyconf_2digit_30_win_zona                 float64 `json:"companyconf_2digit_30_win_zona"`
	Companyconf_2digit_30_win_jackpot              float64 `json:"companyconf_2digit_30_win_jackpot"`
	Companyconf_2digit_30_status_redblack_line     string  `json:"companyconf_2digit_30_status_redblack_line"`
	Companyconf_2digit_30_status_redblack_line_css string  `json:"companyconf_2digit_30_status_redblack_line_css"`
	Companyconf_2digit_30_operator                 string  `json:"companyconf_2digit_30_operator"`
	Companyconf_2digit_30_operator_css             string  `json:"companyconf_2digit_30_operator_css"`
	Companyconf_2digit_30_maintenance              string  `json:"companyconf_2digit_30_maintenance"`
	Companyconf_2digit_30_maintenance_css          string  `json:"companyconf_2digit_30_maintenance_css"`
	Companyconf_2digit_30_status                   string  `json:"companyconf_2digit_30_status"`
	Companyconf_2digit_30_status_css               string  `json:"companyconf_2digit_30_status_css"`
	Companyconf_create                             string  `json:"companyconf_create"`
	Companyconf_update                             string  `json:"companyconf_update"`
}
type Model_companymoney struct {
	Companymoney_id     int    `json:"companymoney_id"`
	Companymoney_money  int    `json:"companymoney_money"`
	Companymoney_create string `json:"companymoney_create"`
	Companymoney_update string `json:"companymoney_update"`
}
type Model_companyshare struct {
	Company_id   string `json:"company_id"`
	Company_name string `json:"company_name"`
}
type Model_companyadminruleshare struct {
	Companyadminrule_id   int    `json:"companyadminrule_id"`
	Companyadminrule_name string `json:"companyadminrule_name"`
}

type Controller_companysave struct {
	Page           string  `json:"page" validate:"required"`
	Sdata          string  `json:"sdata" validate:"required"`
	Company_search string  `json:"company_search"`
	Company_page   int     `json:"company_page"`
	Company_id     string  `json:"company_id"`
	Company_idcurr string  `json:"company_idcurr" validate:"required"`
	Company_name   string  `json:"company_name" validate:"required"`
	Company_owner  string  `json:"company_owner" validate:"required"`
	Company_phone1 string  `json:"company_phone1"`
	Company_phone2 string  `json:"company_phone2"`
	Company_email  string  `json:"company_email"`
	Company_minfee float64 `json:"company_minfee"`
	Company_url1   string  `json:"company_url1" validate:"required"`
	Company_url2   string  `json:"company_url2" validate:"required"`
	Company_status string  `json:"company_status" validate:"required"`
}
type Controller_companyadminsave struct {
	Page                   string `json:"page" validate:"required"`
	Sdata                  string `json:"sdata" validate:"required"`
	Companyadmin_id        int    `json:"companyadmin_id"`
	Companyadmin_idcompany string `json:"companyadmin_idcompany" validate:"required"`
	Companyadmin_idrule    int    `json:"companyadmin_idrule" validate:"required"`
	Companyadmin_username  string `json:"companyadmin_username" validate:"required"`
	Companyadmin_password  string `json:"companyadmin_password`
	Companyadmin_name      string `json:"companyadmin_name" validate:"required"`
	Companyadmin_status    string `json:"companyadmin_status" validate:"required"`
}
type Controller_companyadminrulesave struct {
	Page                         string `json:"page" validate:"required"`
	Sdata                        string `json:"sdata" validate:"required"`
	Companyadminrule_id          int    `json:"companyadminrule_id"`
	Companyadminrule_idcompany   string `json:"companyadminrule_idcompany" validate:"required"`
	Companyadminrule_nmruleadmin string `json:"companyadminrule_nmruleadmin" validate:"required"`
	Companyadminrule_ruleadmin   string `json:"companyadminrule_ruleadmin" validate:"required"`
}
type Controller_companymoneysave struct {
	Page                   string `json:"page" validate:"required"`
	Sdata                  string `json:"sdata" validate:"required"`
	Companymoney_idcompany string `json:"companymoney_idcompany" validate:"required"`
	Companymoney_money     int    `json:"companymoney_money" validate:"required"`
}
type Controller_companyconfsave struct {
	Page                                       string  `json:"page" validate:"required"`
	Companyconf_id                             string  `json:"companyconf_id" validate:"required"`
	Companyconf_2digit_30_time                 int     `json:"companyconf_2digit_30_time" validate:"required"`
	Companyconf_2digit_30_digit                int     `json:"companyconf_2digit_30_digit" validate:"required"`
	Companyconf_2digit_30_minbet               int     `json:"companyconf_2digit_30_minbet" validate:"required"`
	Companyconf_2digit_30_maxbet               int     `json:"companyconf_2digit_30_maxbet" validate:"required"`
	Companyconf_2digit_30_win                  float64 `json:"companyconf_2digit_30_win" validate:"required"`
	Companyconf_2digit_30_win_redblack         float64 `json:"companyconf_2digit_30_win_redblack" validate:"required"`
	Companyconf_2digit_30_win_line             float64 `json:"companyconf_2digit_30_win_line" validate:"required"`
	Companyconf_2digit_30_win_zona             float64 `json:"companyconf_2digit_30_win_zona" validate:"required"`
	Companyconf_2digit_30_win_jackpot          float64 `json:"companyconf_2digit_30_win_jackpot" validate:"required"`
	Companyconf_2digit_30_status_redblack_line string  `json:"companyconf_2digit_30_status_redblack_line" validate:"required"`
	Companyconf_2digit_30_operator             string  `json:"companyconf_2digit_30_operator" validate:"required"`
	Companyconf_2digit_30_maintenance          string  `json:"companyconf_2digit_30_maintenance" validate:"required"`
	Companyconf_2digit_30_status               string  `json:"companyconf_2digit_30_status" validate:"required"`
}
type Controller_company struct {
	Company_search string `json:"company_search"`
	Company_page   int    `json:"company_page"`
}
type Controller_companyadmin struct {
	Companyadmin_idcompany string `json:"companyadmin_idcompany" `
}
type Controller_companymoneydelete struct {
	Companymoney_id        int    `json:"companymoney_id" `
	Companymoney_idcompany string `json:"companymoney_idcompany" `
}
