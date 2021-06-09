package main

import (
	"context"
	"flag"
	"fmt"
	"log"
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

func main() {
	flag.Parse()

	if *githubToken == "" && *file == "" && *repository == "" && *owner == "" {
		log.Fatalf("\"--github-token\", \"--file\", \"owner\", and \"repository\" flags are required ones.")
		flag.PrintDefaults()
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: *githubToken},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	p, err := cloudevents.NewHTTP()
	if err != nil {
		log.Fatalln("failed to create protocol:", err.Error())
	}

	c, err := cloudevents.NewClient(p)
	if err != nil {
		log.Fatalln("failed to create client,", err)
	}

	log.Println("will listen on :8080")
	if err := c.StartReceiver(ctx, func(ctx context.Context, event cloudevents.Event) {
		if event.Source() == "falco.org" && event.Type() == "falco.rule.output.v1" {
			payload := &FalcoPayload{}
			if err := event.DataAs(payload); err != nil {
				log.Println("failed to parse falco payload from event:", err)
				return
			}

			if payload.Rule == "Terminal shell in container" {
				// TODO: do whatever you want to do
				fc, _, _, err := client.Repositories.GetContents(ctx, *owner, *repository, *file, &github.RepositoryContentGetOptions{
					Ref: *ref,
				})

				if err != nil {
					log.Fatalf("error: %s", err.Error())
				}

				content, err := fc.GetContent()

				if err != nil {
					log.Fatalf("error: %s", err.Error())
				}

				m := make(map[interface{}]interface{})

				err = yaml.Unmarshal([]byte(content), &m)
				if err != nil {
					log.Fatalf("error: %v", err)
				}

				spec := m["spec"].(map[interface{}]interface{})
				spec["replicas"] = 0

				d, err := yaml.Marshal(&m)
				if err != nil {
					log.Fatalf("error: %v", err)
				}
				fmt.Printf("--- m dump:\n%s\n\n", string(d))

				commitOption := &github.RepositoryContentFileOptions{
					Branch:  github.String("master"),
					Message: github.String("scaling down to zero replica"),
					Committer: &github.CommitAuthor{
						Name:  github.String("falco"),
						Email: github.String("falco@falco.com"),
					},
					Author: &github.CommitAuthor{
						Name:  github.String("falco"),
						Email: github.String("falco@falco"),
					},
					Content: d,
					SHA:     fc.SHA,
				}

				c, resp, err := client.Repositories.UpdateFile(ctx, *owner, *repository, *file, commitOption)
				if err != nil {
					log.Fatalf("UpdateFile: %v", err)
				}
				log.Printf("resp.Status=%v", resp.Status)
				log.Printf("resp.StatusCode=%v", resp.StatusCode)
				spew.Dump(c)

				log.Printf("[%s] scaled down to zero %s from %s because %s\n", payload.Rule, payload.Fields.Pod, payload.Fields.Namespace, payload.Output)
			}
		} else {
			log.Println("ignoring event:\n", event)
		}
	}); err != nil {
		log.Fatal("failed to start receiver:", err)
	}

}
