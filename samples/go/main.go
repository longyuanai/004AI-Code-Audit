package demo

func run(request *http.Request) {
	command := request.FormValue("command")
	exec.Command("sh", "-c", command)
}
