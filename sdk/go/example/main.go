// Example naitron-c controller in Go.
package main

import (
	"encoding/json"
	"os"

	"naitron"
)

func main() {
	naitron.Run(func(req naitron.Request) (int, string, []byte) {
		b, _ := json.Marshal(map[string]any{
			"controller": "go-hello",
			"lang":       "go",
			"pid":        os.Getpid(),
			"method":     req.Method,
			"path":       req.Path,
			"name":       req.Params["name"],
			"sub":        req.Sub,
		})
		return 200, "application/json", b
	}, "go-hello")
}
