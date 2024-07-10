package entities

type Model_admin struct {
	Username      string `json:"admin_username"`
	Nama          string `json:"admin_nama"`
	Rule          string `json:"admin_rule"`
	Joindate      string `json:"admin_joindate"`
	Lastlogin     string `json:"admin_lastlogin"`
	LastIpaddress string `json:"admin_lastipaddres"`
	Status        string `json:"admin_status"`
}
type Model_adminrule struct {
	Idrule string `json:"adminrule_idruleadmin"`
}
type Model_adminsave struct {
	Username string `json:"admin_username"`
	Nama     string `json:"admin_nama"`
	Rule     string `json:"admin_rule"`
	Status   string `json:"admin_status"`
	Create   string `json:"admin_create"`
	Update   string `json:"admin_update"`
}
type Controller_admindetail struct {
	Username string `json:"admin_username" validate:"required"`
}
type Controller_adminsave struct {
	Sdata    string `json:"sdata" validate:"required"`
	Page     string `json:"page" validate:"required"`
	Username string `json:"admin_username" validate:"required"`
	Password string `json:"admin_password"`
	Nama     string `json:"admin_nama" validate:"required"`
	Rule     string `json:"admin_rule" validate:"required"`
	Status   string `json:"admin_status" validate:"required"`
}

type Responseredis_adminhome struct {
	Admin_username     string `json:"admin_username"`
	Admin_nama         string `json:"admin_nama"`
	Admin_rule         string `json:"admin_rule"`
	Admin_joindate     string `json:"admin_joindate"`
	Admin_timezone     string `json:"admin_timezone"`
	Admin_lastlogin    string `json:"admin_lastlogin"`
	Admin_lastipaddres string `json:"admin_lastipaddres"`
	Admin_status       string `json:"admin_status"`
}
type Responseredis_adminrule struct {
	Adminrule_idrule string `json:"adminrule_idruleadmin"`
}
