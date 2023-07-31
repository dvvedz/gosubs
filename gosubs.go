package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
)

func main() {
	fastScan := flag.Bool("skip", false, "when this flag is provided we will not use bbot")
	flag.Parse()

	var wg sync.WaitGroup
	for _, apex := range getDataFromStdin() {
		if !*fastScan {
			wg.Add(1)
			go func() {
				defer wg.Done()
				parseBbotData(apex)
			}()

		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			execCommand(true, "amass", "enum", "-passive", "-d", apex)
			execCommand(false, "amass", "db", "-names", "-d", apex, "-nocolor")
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			execCommand(false, "github-subdomains", "-d", apex, "-raw", "-o", "/tmp/githubsubdomains.txt")
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			execCommand(false, "subfinder", "-d", apex, "-all")
		}()

		wg.Wait()
	}
}

func getDataFromStdin() []string {
	scanner := bufio.NewScanner(os.Stdin)

	var apexes []string

	for scanner.Scan() {
		apexes = append(apexes, scanner.Text())
	}

	if len(apexes) == 0 {
		log.Fatal("Stdin is empty")
	}
	return apexes
}

func lookPath(p string) string {
	path, err := exec.LookPath(p)
	if err != nil {
		log.Fatal(err)
	}
	return path
}

func execCommand(silent bool, c ...string) []string {

	var subs []string
	var out bytes.Buffer

	p := lookPath(c[0])
	cmd := exec.Command(p, c[1:]...)

	if !silent {
		//cmd.Stderr = os.Stderr
		cmd.Stdout = io.MultiWriter(os.Stdout, &out)
	} else {
		cmd.Stdout = &out
	}

	if err := cmd.Run(); err != nil {
		log.Fatalf("failed running %s %v", c, err)
	}

	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		subs = append(subs, scanner.Text())
	}
	return subs
}

func parseBbotData(domain string) {
	bs := execCommand(true, "bbot", "-t", domain, "-f", "subdomain-enum", "-rf", "passive", "-c", "modules.massdns.max_resolvers=1000", "--output-module", "json", "--yes", "-s")
	var br BbotResponse

	for _, item := range bs {
		json.Unmarshal([]byte(item), &br)
		if br.Type == "DNS_NAME" {
			fmt.Println(br.Data)
		}
	}
}

type BbotResponse struct {
	Type          string   `json:"type"`
	ID            string   `json:"id"`
	Data          string   `json:"data"`
	ScopeDistance int      `json:"scope_distance"`
	Scan          string   `json:"scan"`
	Timestamp     float64  `json:"timestamp"`
	ResolvedHosts []string `json:"resolved_hosts"`
	Source        string   `json:"source"`
	Tags          []string `json:"tags"`
	Module        string   `json:"module"`
}
