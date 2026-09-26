package phase0

import (
	"net/http"
	"os"
	"os/exec"
)

func alternateSource() {
	command := os.Getenv("COMMAND")
	exec.Command("sh", "-c", command) // phase0-expect vuln
}

func directSource(request *http.Request) {
	command := request.FormValue("command")
	exec.Command("sh", "-c", command) // phase0-expect vuln
}

func constantSink(request *http.Request) {
	request.FormValue("ignored")
	exec.Command("echo", "safe") // phase0-expect safe
}
