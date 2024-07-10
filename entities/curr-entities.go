package entities

type Model_curr struct {
	Curr_id     string `json:"curr_id"`
	Curr_name   string `json:"curr_name"`
	Curr_create string `json:"curr_create"`
	Curr_update string `json:"curr_update"`
}
type Model_currshare struct {
	Curr_id string `json:"curr_id"`
}

type Controller_currsave struct {
	Page      string `json:"page" validate:"required"`
	Sdata     string `json:"sdata" validate:"required"`
	Curr_id   string `json:"curr_id" validate:"required"`
	Curr_name string `json:"curr_name" validate:"required"`
}
