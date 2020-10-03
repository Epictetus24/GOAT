package reporting

//Vuln stores details about the vuln
type Vuln struct {
	vulnid           int
	Name             string
	Riskrating       int
	Finding          string
	Summary          string
	Technicaldetails string
	Recommendation   string
	Owaspid          string
	CVE              string
	Cvssvector       string
	References       string
}

/* risk ratings are as follows
0 = info
1 = low
2 = medium
3 = high
4 = critical
*/

//Vulncollect stores a slice of the vulns captured.
type Vulncollect struct {
	Vulnlist      []Vuln
	Affectedhosts []string
}
