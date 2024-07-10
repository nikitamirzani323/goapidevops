package entities

type Model_adminruleall struct {
	Idadmin        string `json:"adminrule_idadmin"`
	Ruleadmingroup string `json:"adminrule_rule"`
}
type Model_agenadminrule struct {
	Agenadminrule_id     int    `json:"agenadminrule_id"`
	Agenadminrule_idagen string `json:"agenadminrule_idagen"`
	Agenadminrule_nmagen string `json:"agenadminrule_nmagen"`
	Agenadminrule_name   string `json:"agenadminrule_name"`
	Agenadminrule_rule   string `json:"agenadminrule_rule"`
	Agenadminrule_create string `json:"agenadminrule_create"`
	Agenadminrule_update string `json:"agenadminrule_update"`
}

type Controller_adminrulesave struct {
	Sdata   string `json:"sdata" validate:"required"`
	Page    string `json:"page" validate:"required"`
	Idadmin string `json:"adminrule_idadmin" validate:"required"`
	Rule    string `json:"adminrule_rule" `
}
type Controller_agenadminrulesave struct {
	Sdata                string `json:"sdata" validate:"required"`
	Page                 string `json:"page" validate:"required"`
	Agenadminrule_id     int    `json:"agenadminrule_id" `
	Agenadminrule_idagen string `json:"agenadminrule_idagen" validate:"required"`
	Agenadminrule_name   string `json:"agenadminrule_name"`
	Agenadminrule_rule   string `json:"agenadminrule_rule"`
}

type Responseredis_adminruleall struct {
	Adminrule_idadmin string `json:"adminrule_idadmin"`
	Adminrule_rule    string `json:"adminrule_rule"`
}
