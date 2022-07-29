package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"github.com/t94j0/nmap"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

type target struct {
	hostname string
	domain   string
	result   string
	telnet   string
}

type caller struct{}

func main() {

	file, _ := os.Open("./target.csv")
	rdr := csv.NewReader(bufio.NewReader(file))
	rows, error := rdr.ReadAll()
	checkErr(error)
	r := regexp.MustCompile("Port [0-9]+")

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

	for i := 0; i < len(targets); i++ {
		targets := <-mainC
		a := r.FindAllString(targets.result, -1)
		b := telnetCheck(a, targets.domain)
		targets.telnet = b

		results = append(results, targets)

	}

	writeCSV(results)
	fmt.Println("Finished Scan")
}

func telnetCheck(ports []string, domain string) string {
	re := regexp.MustCompile("[0-9]+")
	result := ""
	timeout := time.Second

	for i := 0; i < len(ports); i++ {
		t := re.FindAllString(ports[i], -1)
		s := fmt.Sprintf("%s:%s", domain, t[0])

		conn, err := net.DialTimeout("tcp", s, timeout)

		fmt.Println(s)
		if err != nil {
			fmt.Println("Connecting error:", err)
		}
		if conn != nil {
			defer conn.Close()
			result += "\n" + fmt.Sprintf("Opend %s ", s)
		}

	}
	return result
}

func writeCSV(sResult []target) {

	fmt.Println("File Write")
	file, err := os.Create("result2.csv")
	checkErr(err)

	w := csv.NewWriter(file)

	headers := []string{
		"hostname",
		"domain",
		"result",
		"telnet",
	}

	wErr := w.Write(headers)

	defer w.Flush()
	checkErr(wErr)
	for _, result := range sResult {
		resultSlice := []string{
			result.hostname,
			result.domain,
			result.result,
			result.telnet,
		}
		resultErr := w.Write(resultSlice)

		checkErr(resultErr)
	}
}

func scanTarget(item target, c chan<- target) {
	scan, _ := nmap.Init().
		AddHosts(item.domain).
		AddPorts(21, 22, 23, 25, 53, 80, 389, 443, 445, 3306, 5432, 1521, 2638, 1433, 3389, 8080, 9000, 9200, 8443, 5601, 5000, 3000, 27017).
		AddFlags("--open").
		AddFlags("-sT").Run()
	c <- target{
		hostname: item.hostname,
		domain:   item.domain,
		result:   scan.ToString(),
	}
}

func extractTarget(row []string, c chan<- target) {

	c <- target{
		hostname: row[0],
		domain:   row[1],
	}
}

func checkErr(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func CleanString(str string) string {
	if strings.ContainsAny(str, "open") {
		fmt.Println(str)
		return strings.Join(strings.Fields(strings.TrimSpace(str)), " ")
	}
	return ""
}
