package main

import (
	"fmt"
	"github.com/SamNet-dev/wg-orchestrator/services/api/internal/auth"
)

func main() {
	hash, _ := auth.HashPassword("admin123")
	fmt.Println(hash)
}
