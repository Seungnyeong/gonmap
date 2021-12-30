package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/t94j0/nmap"
)


type target struct {
	hostname 	string
	types	 	string
	publicIp 	string
	privateIp 	string
	zone		string
	category 	string
	position	string
	status		string
	kind		string
	osType		string
	result		string
}

func main() {
	
	file, _ := os.Open("./target.csv")
	rdr := csv.NewReader(bufio.NewReader(file))
	rows, error := rdr.ReadAll()
	checkErr(error)

	var targets []target
	var results []target

	c := make(chan target)
	for _, row := range rows {
		go extractTarget(row, c)
		target := <-c
		targets = append(targets, target)
	}

	mainC := make(chan target)
	

	for _, target := range targets {
		go scanTarget(target, mainC)
	}
	
	for i:=0; i < len(targets); i++{
		targets := <-mainC
		results = append(results, targets)
		
	}
	
	writeCSV(results)
	fmt.Println("Finished Scan")
}

func writeCSV(sResult []target) {
	fmt.Println("File Write")
	file, err := os.Create("result2.csv")
	checkErr(err)

	w := csv.NewWriter(file)

	headers := []string{
		"hostName", 
		"purpose", 
		"publicIP", 
		"privateIP", 
		"zonePosition", 
		"category", 
		"assetPosition", 
		"status", 
		"subCategory", 
		"osType",
		"result",
	}

	wErr := w.Write(headers)
	defer w.Flush()
	checkErr(wErr)
	for _, result := range sResult {
		resultSlice := []string{
				result.hostname, 
				result.types, 
				result.publicIp, 
				result.privateIp, 
				result.zone, 
				result.kind, 
				result.position, 
				result.status, 
				result.kind, 
				result.osType, 
				result.result,
		}
		resultErr := w.Write(resultSlice)
		checkErr(resultErr)
	}
}

func scanTarget(item target, c chan<- target) {
	scan, _ := nmap.Init().
				AddHosts(item.publicIp).
				AddPortRange(0, 1000).
				AddFlags("-sS").Run()
	
	c <-  target {
			hostname : item.hostname ,
			types	 : item.types	 ,
			publicIp : item.publicIp ,
			privateIp : item.privateIp,
			zone	 : item.zone		,	
			category : item.category ,
			position : item.position	,	
			status	 : item.status		,	
			kind	 : item.kind		,	
			osType	 : item.osType		,	
			result	 : CleanString(scan.ToString())	,	
	}
}

func extractTarget(row []string, c chan<- target) {

	c <- target {
		hostname : row[0],
		types : row[1],
		publicIp : row[2],
		privateIp : row[3],
		zone : row[4],
		category : row[5],
		position : row[6],
		status : row[7],
		kind : row[8],
		osType : row[9],
	}
}

func checkErr(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func CleanString(str string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(str)), " ")
}