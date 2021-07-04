package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-github/v35/github"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

// FalcoPayload is a struct to map falco event json
type FalcoPayload struct {
	Output   string    `json:"output"`
	Priority string    `json:"priority"`
	Rule     string    `json:"rule"`
	Time     time.Time `json:"time"`
	Fields   struct {
		ContainerId        string `json:"container.id"`
		ContainerImageRepo string `json:"container.image.repository"`
		Namespace          string `json:"k8s.ns.name"`
		Pod                string `json:"k8s.pod.name"`
		ProcCmd            string `json:"proc.cmdline"`
		ProcName           string `json:"proc.name"`
		ProcPName          string `json:"proc.pname"`
		ProcTTY            int64  `json:"proc.tty"`
		UserLoginUID       int64  `json:"user.loginuid"`
		UserName           string `json:"user.name"`
	} `json:"output_fields"`
}

var file = flag.String("file", "", "will update file")
var ref = flag.String("ref", "master", "reference commit or branch for repository")
var githubToken = flag.String("github-token", "", "GitHub PAT token")
var owner = flag.String("owner", "", "owner of the repository")
var repository = flag.String("repository", "", "the location of the source code")
var notifyURL = flag.String("notify-url", "", "the URL to notify Flux v2 for changes")

func main() {
	flag.Parse()

	if *githubToken == "" && *file == "" && *repository == "" && *owner == "" {
		flag.PrintDefaults()
		log.Fatalf("\"--github-token\", \"--file\", \"owner\", and \"repository\" flags are required ones.")
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: *githubToken},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	p, err := cloudevents.NewHTTP()
	if err != nil {
		log.Fatalf("failed to create protocol, detail: %s\n", err.Error())
	}

	c, err := cloudevents.NewClient(p)
	if err != nil {
		log.Fatalf("failed to create client, detail: %s\n", err.Error())
	}

	log.Println("will listen on :8080")
	if err := c.StartReceiver(ctx, func(ctx context.Context, event cloudevents.Event) {
		// https://github.com/falcosecurity/falcosidekick/blob/master/outputs/cloudevents.go#L30-L31
		if event.Source() == "falco.org" && event.Type() == "falco.rule.output.v1" {
			payload := &FalcoPayload{}
			if err := event.DataAs(payload); err != nil {
				log.Printf("failed to parse event payload, detail: %s\n", err.Error())
				return
			}

			if payload.Rule == "Terminal shell in container" {
				opts := &github.RepositoryContentGetOptions{
					Ref: *ref,
				}

				fc, _, _, err := client.Repositories.GetContents(ctx, *owner, *repository, *file, opts)

				if err != nil {
					log.Fatalf("could not get contents of the repository %s, detail: %s", *repository, err.Error())
				}

				content, err := fc.GetContent()

				if err != nil {
					log.Fatalf("could not get content, detail: %s", err.Error())
				}

				m := make(map[interface{}]interface{})

				err = yaml.Unmarshal([]byte(content), &m)
				if err != nil {
					log.Fatalf("could not unmarshall, detail: %s", err.Error())
				}

				spec := m["spec"].(map[interface{}]interface{})
				spec["replicas"] = 0

				d, err := yaml.Marshal(&m)
				if err != nil {
					log.Fatalf("error: %v", err)
				}
				fmt.Printf("--- m dump:\n%s\n\n", string(d))

				committer := &github.CommitAuthor{
					Name:  github.String("falco"),
					Email: github.String("falco@falco.com"),
				}
				commitOption := &github.RepositoryContentFileOptions{
					Branch:    ref,
					Message:   github.String("scaling down to zero replicas"),
					Committer: committer,
					Author:    committer,
					Content:   d,
					SHA:       fc.SHA,
				}

				c, resp, err := client.Repositories.UpdateFile(ctx, *owner, *repository, *file, commitOption)
				if err != nil {
					log.Fatalf("could not update file %s, detail: %s", *file, err.Error())
				}

				if resp.StatusCode == http.StatusOK {
					log.Printf("[%s] scaled down to zero %s from %s because %s\n", payload.Rule, payload.Fields.Pod, payload.Fields.Namespace, payload.Output)

					if *notifyURL != "" {
						reqBody, _ := json.Marshal(map[string]string{})
						resp, err := http.Post(*notifyURL, "application/json", bytes.NewBuffer(reqBody))
						if err != nil {
							log.Fatalf("could not send post request to %s, detail: %s", *notifyURL, err.Error())
						}
						defer resp.Body.Close()
						if resp.StatusCode == http.StatusOK {
							log.Printf("Notification send to %s successfully\n", *notifyURL)
						} else {
							log.Printf("Notification could not send to %s successfully, response code: %d\n", *notifyURL, resp.StatusCode)
						}
					}
				} else {
					log.Printf("[%s] could not scaled down to zero %s from %s because %s, response code: %d\n", payload.Rule, payload.Fields.Pod, payload.Fields.Namespace, payload.Output, resp.StatusCode)
					log.Println("Printing Response details start")
					spew.Dump(c)
					log.Println("Printing Response details end")
				}
			}
		} else {
			log.Println("ignoring event:\n", event)
		}
	}); err != nil {
		log.Fatal("failed to start receiver:", err)
	}

}
