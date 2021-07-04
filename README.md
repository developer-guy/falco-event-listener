# Test Flux v2 KRE (Kubernetes Response Engine) with Falco and Falcosidekick
This project aims to provide a listener for CloudEvents thrown by Falcosidekick against malicious behaviors that Falco detects. In a nutshell, this project is a CLI application and listens to events then takes action for those events, such as updating the Git repository. 
