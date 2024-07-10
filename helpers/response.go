package helpers

type Response struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Record  interface{} `json:"record"`
	Time    string      `json:"time"`
}
type Responsepaging struct {
	Status      int         `json:"status"`
	Message     string      `json:"message"`
	Record      interface{} `json:"record"`
	Perpage     int         `json:"perpage"`
	Totalrecord int         `json:"totalrecord"`
	Time        string      `json:"time"`
}
type Responsercompany struct {
	Status      int         `json:"status"`
	Message     string      `json:"message"`
	Record      interface{} `json:"record"`
	Listcurr    interface{} `json:"listcurr"`
	Perpage     int         `json:"perpage"`
	Totalrecord int         `json:"totalrecord"`
	Time        string      `json:"time"`
}
type Responsercompanyadmin struct {
	Status   int         `json:"status"`
	Message  string      `json:"message"`
	Record   interface{} `json:"record"`
	Listrule interface{} `json:"listrule"`
	Time     string      `json:"time"`
}
type Responsercompanymoney struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Record  interface{} `json:"record"`
	Minbet  int         `json:"minbet"`
	Maxbet  int         `json:"maxbet"`
	Time    string      `json:"time"`
}
type Responserfq struct {
	Status      int         `json:"status"`
	Message     string      `json:"message"`
	Record      interface{} `json:"record"`
	Listbranch  interface{} `json:"listbranch"`
	Listcurr    interface{} `json:"listcurr"`
	Perpage     int         `json:"perpage"`
	Totalrecord int         `json:"totalrecord"`
	Time        string      `json:"time"`
}
type Responsepurchaserequest struct {
	Status          int         `json:"status"`
	Message         string      `json:"message"`
	Record          interface{} `json:"record"`
	Listbranch      interface{} `json:"listbranch"`
	Listdepartement interface{} `json:"listdepartement"`
	Listcurr        interface{} `json:"listcurr"`
	Perpage         int         `json:"perpage"`
	Totalrecord     int         `json:"totalrecord"`
	Time            string      `json:"time"`
}
type Responsevendor struct {
	Status         int         `json:"status"`
	Message        string      `json:"message"`
	Record         interface{} `json:"record"`
	Listcatevendor interface{} `json:"listcatevendor"`
	Perpage        int         `json:"perpage"`
	Totalrecord    int         `json:"totalrecord"`
	Time           string      `json:"time"`
}
type Responseemployee struct {
	Status          int         `json:"status"`
	Message         string      `json:"message"`
	Record          interface{} `json:"record"`
	Listdepartement interface{} `json:"listdepartement"`
	Perpage         int         `json:"perpage"`
	Totalrecord     int         `json:"totalrecord"`
	Time            string      `json:"time"`
}
type Responseitem struct {
	Status       int         `json:"status"`
	Message      string      `json:"message"`
	Record       interface{} `json:"record"`
	Listcateitem interface{} `json:"listcateitem"`
	Perpage      int         `json:"perpage"`
	Totalrecord  int         `json:"totalrecord"`
	Time         string      `json:"time"`
}
type Responsewarehouse struct {
	Status     int         `json:"status"`
	Message    string      `json:"message"`
	Record     interface{} `json:"record"`
	Listbranch interface{} `json:"listbranch"`
	Time       string      `json:"time"`
}
type Responsestoragebin struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Record  interface{} `json:"record"`
	Listuom interface{} `json:"listuom"`
	Time    string      `json:"time"`
}

type Responselistpatterndetail struct {
	Status    int         `json:"status"`
	Message   string      `json:"message"`
	Record    interface{} `json:"record"`
	Totalwin  int         `json:"totalwin"`
	Totallose int         `json:"totallose"`
	Time      string      `json:"time"`
}
type Responsepattern struct {
	Status      int         `json:"status"`
	Message     string      `json:"message"`
	Record      interface{} `json:"record"`
	Perpage     int         `json:"perpage"`
	Totalrecord int         `json:"totalrecord"`
	Totalwin    int         `json:"totalwin"`
	Totallose   int         `json:"totallose"`
	Listpoint   interface{} `json:"listpoint"`
	Time        string      `json:"time"`
}
type Responsecompany struct {
	Status   int         `json:"status"`
	Message  string      `json:"message"`
	Record   interface{} `json:"record"`
	Listcurr interface{} `json:"listcurr"`
	Time     string      `json:"time"`
}
type Responsecompanyadmin struct {
	Status      int         `json:"status"`
	Message     string      `json:"message"`
	Record      interface{} `json:"record"`
	Listcompany interface{} `json:"listcompany"`
	Listrule    interface{} `json:"listrule"`
	Time        string      `json:"time"`
}
type Responsecompanyadminrule struct {
	Status      int         `json:"status"`
	Message     string      `json:"message"`
	Record      interface{} `json:"record"`
	Listcompany interface{} `json:"listcompany"`
	Time        string      `json:"time"`
}
type Responseagenrule struct {
	Status   int         `json:"status"`
	Message  string      `json:"message"`
	Record   interface{} `json:"record"`
	Listagen interface{} `json:"listagen"`
	Time     string      `json:"time"`
}
type ResponseAdmin struct {
	Status   int         `json:"status"`
	Message  string      `json:"message"`
	Record   interface{} `json:"record"`
	Listrule interface{} `json:"listruleadmin"`
	Time     string      `json:"time"`
}
type ResponseEmployee struct {
	Status          int         `json:"status"`
	Message         string      `json:"message"`
	Record          interface{} `json:"record"`
	Listdepartement interface{} `json:"listdepartement"`
	Time            string      `json:"time"`
}
type ErrorResponse struct {
	Field string
	Tag   string
}

func ErrorCheck(err error) {
	if err != nil {
		panic(err.Error())
	}
}
